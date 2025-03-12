from flask import Flask
from flask_socketio import SocketIO
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask-SocketIO for real-time updates
socketio = SocketIO()

def create_app(debug=False):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Get configuration from environment variables
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'permalog-secret-key')
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', debug)
    
    # Register custom Jinja2 filters
    @app.template_filter('escapejs')
    def escapejs_filter(s):
        """Escape string for JavaScript."""
        if s is None:
            return ''
        s = str(s)
        s = s.replace('\\', '\\\\')
        s = s.replace('\r', '\\r')
        s = s.replace('\n', '\\n')
        s = s.replace('"', '\\"')
        s = s.replace("'", "\\'")
        return s
    
    # Register blueprints
    from app.routes import register_blueprints
    register_blueprints(app)
    
    # Initialize SocketIO with the app
    cors_allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '*')
    socketio.init_app(app, cors_allowed_origins=cors_allowed_origins)
    
    # Run setup script to create initial admin user if needed
    with app.app_context():
        from app.setup import setup_initial_admin
        setup_initial_admin()
    
    return app 