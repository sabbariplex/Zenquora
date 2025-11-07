#!/usr/bin/env python
"""Wrapper script to run the Flask-SocketIO app on Railway/Render"""
import os
from app import socketio, app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'

    print(f"[STARTUP] Starting server on 0.0.0.0:{port}")
    print(f"[STARTUP] Debug mode: {debug}")

    # Use SocketIO's built-in server (works with gevent mode)
    # This is production-ready for Railway
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        log_output=True,
        use_reloader=False
    )

