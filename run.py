#!/usr/bin/env python
"""
PermaLog - Immutable Logging Service
Run script to start the Flask application
"""

from app import create_app, socketio

if __name__ == '__main__':
    app = create_app(debug=True)
    socketio.run(app, host='0.0.0.0', port=5000) 