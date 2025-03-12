"""Routes package for the PermaLog application.

This package contains all the route blueprints for the application:
- main_routes: Main web UI routes
- auth_routes: Authentication routes
- api_routes: API endpoints
- admin_routes: Admin panel routes
"""

from app.routes.main_routes import main_bp
from app.routes.auth_routes import auth_bp
from app.routes.api_routes import api_bp
from app.routes.admin_routes import admin_bp

def register_blueprints(app):
    """Register all blueprints with the Flask application."""
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/admin') 