#!/usr/bin/env python
"""Wrapper script to run the Flask-SocketIO app on Railway/Render"""
import os
import logging
import sys

# Configure logging to suppress eventlet/gevent false error messages
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

# Suppress eventlet/werkzeug/socketio false error logs
logging.getLogger('eventlet.wsgi.server').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.INFO)

from app import socketio, app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'

    print(f"[STARTUP] Starting server on 0.0.0.0:{port}")
    print(f"[STARTUP] Debug mode: {debug}")
    print(f"[STARTUP] Application ready to accept connections")

    # Use SocketIO's built-in server (works with eventlet mode)
    # This is production-ready for Railway
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        log_output=False,  # Disable to prevent false error logs
        use_reloader=False
    )

