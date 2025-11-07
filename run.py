#!/usr/bin/env python
"""Wrapper script to run the Flask-SocketIO app on Railway/Render"""
import os
from app import socketio, app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)

