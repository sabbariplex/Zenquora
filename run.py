#!/usr/bin/env python
"""Wrapper script to run the Flask-SocketIO app on Railway/Render"""
import os
import logging
import sys
import traceback

# Configure logging to suppress eventlet/gevent false error messages
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout,
    force=True  # Force reconfiguration
)

# Suppress eventlet/werkzeug/socketio false error logs
logging.getLogger('eventlet.wsgi.server').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.INFO)
logging.getLogger('socketio').setLevel(logging.WARNING)
logging.getLogger('engineio').setLevel(logging.WARNING)

# Ensure we flush output immediately
sys.stdout.flush()
sys.stderr.flush()

print("[STARTUP] Initializing application...")
sys.stdout.flush()

try:
    from app import socketio, app
    print("[STARTUP] Application imported successfully")
    sys.stdout.flush()
except Exception as e:
    print(f"[STARTUP ERROR] Failed to import application: {e}")
    print(f"[STARTUP ERROR] Traceback: {traceback.format_exc()}")
    sys.stdout.flush()
    sys.stderr.flush()
    raise

if __name__ == '__main__':
    try:
        # Get PORT from environment variable (Railway sets this)
        port_str = os.environ.get('PORT', '5000')
        try:
            port = int(port_str)
        except ValueError:
            print(f"[STARTUP ERROR] Invalid PORT value: {port_str}, using default 5000")
            port = 5000
        
        # Always use False for production (Railway/Render)
        # Only enable debug if explicitly set to 'development'
        is_dev = os.environ.get('FLASK_ENV') == 'development'
        debug = False  # Always False for production safety

        # Print startup information
        print(f"[STARTUP] =========================================")
        print(f"[STARTUP] Starting Flask-SocketIO Server")
        print(f"[STARTUP] Host: 0.0.0.0")
        print(f"[STARTUP] Port: {port}")
        print(f"[STARTUP] Debug mode: {debug}")
        print(f"[STARTUP] Environment: {'development' if is_dev else 'production'}")
        print(f"[STARTUP] PORT environment variable: {os.environ.get('PORT', 'NOT SET')}")
        print(f"[STARTUP] Railway detected: {any(key.startswith('RAILWAY_') for key in os.environ.keys())}")
        print(f"[STARTUP] Application ready to accept connections")
        print(f"[STARTUP] Health check: http://0.0.0.0:{port}/health")
        print(f"[STARTUP] =========================================")
        sys.stdout.flush()

        # Use SocketIO's built-in server (works with eventlet mode)
        # This is production-ready for Railway
        print(f"[STARTUP] Starting server...")
        sys.stdout.flush()
        
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=debug,
            log_output=True,  # Enable logging to help debug Railway issues
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Server stopped by user")
        sys.stdout.flush()
    except Exception as e:
        print(f"[STARTUP ERROR] Failed to start server: {e}")
        print(f"[STARTUP ERROR] Traceback: {traceback.format_exc()}")
        sys.stdout.flush()
        sys.stderr.flush()
        raise

