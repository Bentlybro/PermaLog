"""
Setup script for PermaLog.
Creates initial admin user if none exists.
"""

from app.database import get_user_count, create_user
import os
import secrets
import string

def setup_initial_admin():
    """Create an initial admin user if no users exist."""
    # Check if any users exist
    user_count = get_user_count()
    
    if user_count == 0:
        # No users exist, create an admin user
        admin_username = os.environ.get('PERMALOG_ADMIN_USERNAME', 'admin')
        admin_email = os.environ.get('PERMALOG_ADMIN_EMAIL', 'admin@example.com')
        
        # Use provided password or generate a random one
        admin_password = os.environ.get('PERMALOG_ADMIN_PASSWORD')
        if not admin_password:
            # Generate a random password
            admin_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            print("\n" + "=" * 50)
            print("INITIAL ADMIN USER CREATED")
            print("=" * 50)
            print(f"Username: {admin_username}")
            print(f"Email: {admin_email}")
            print(f"Password: {admin_password}")
            print("=" * 50)
            print("Please change this password after logging in.")
            print("=" * 50 + "\n")
        
        # Create the admin user
        user_id = create_user(admin_username, admin_email, admin_password, role='admin')
        
        if user_id:
            print(f"Initial admin user created with ID: {user_id}")
        else:
            print("Failed to create initial admin user")
    
    return user_count == 0 