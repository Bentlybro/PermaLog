"""Admin routes for the PermaLog application."""

from flask import Blueprint, request, render_template, redirect, url_for, flash
from app.database import get_recent_activity, get_user_count, get_total_logs_count
from app.database import get_active_sessions_count, list_api_keys, list_users
from app.database import get_user_by_id, update_user, log_activity
from app.middleware import require_auth

# Create blueprint for admin routes
admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
@require_auth('admin')
def admin_dashboard(current_user):
    """Render the admin dashboard."""
    # Get recent activity for the dashboard
    recent_activity = get_recent_activity(limit=10)
    
    # Get system stats
    user_count = get_user_count()
    logs_count = get_total_logs_count()
    active_sessions = get_active_sessions_count()
    api_keys_count = len(list_api_keys())
    
    return render_template(
        'admin/dashboard.html',
        user=current_user,
        recent_activity=recent_activity,
        stats={
            'users': user_count,
            'logs': logs_count,
            'sessions': active_sessions,
            'api_keys': api_keys_count
        }
    )

@admin_bp.route('/users')
@require_auth('admin')
def admin_users(current_user):
    """Render the user management page."""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Calculate offset for pagination
    offset = (page - 1) * per_page
    
    # Get users with pagination
    users = list_users(limit=per_page, offset=offset)
    
    return render_template(
        'admin/users.html',
        users=users,
        page=page,
        per_page=per_page,
        user=current_user
    )

@admin_bp.route('/api-keys')
@require_auth('admin')
def admin_api_keys(current_user):
    """Render the admin API keys management page."""
    # Get all API keys
    all_keys = list_api_keys()
    
    # Get all users to map user IDs to usernames
    users = list_users(limit=1000)  # Assuming there won't be more than 1000 users
    user_map = {user['id']: user for user in users}
    
    # Add username to each key
    for key in all_keys:
        if key['user_id'] is not None:
            # First try to get from the user map
            if key['user_id'] in user_map:
                key['username'] = user_map[key['user_id']]['username']
            else:
                # If not in the map, try to get directly from the database
                user = get_user_by_id(key['user_id'])
                if user and 'username' in user:
                    key['username'] = user['username']
                else:
                    # If still not found, show Unknown with ID
                    key['username'] = f"Unknown (ID: {key['user_id']})"
        else:
            key['username'] = 'System'
    
    return render_template(
        'admin/api_keys.html',
        keys=all_keys,
        user=current_user
    )

@admin_bp.route('/users/<int:user_id>', methods=['GET', 'POST'])
@require_auth('admin')
def admin_edit_user(user_id, current_user):
    """Edit a user."""
    user = get_user_by_id(user_id)
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin.admin_users'))
    
    if request.method == 'POST':
        # Update user information
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        active = request.form.get('active') == 'on'
        
        # Only update password if provided
        password = request.form.get('password')
        
        update_data = {
            'username': username,
            'email': email,
            'role': role,
            'active': active
        }
        
        if password:
            update_data['password'] = password
        
        success = update_user(user_id, **update_data)
        
        if success:
            # Log the user update
            log_activity(
                user_id=current_user['id'],
                action='update_user',
                message=f"Admin {current_user['username']} updated user: {user['username']}",
                ip_address=request.remote_addr,
                icon='bi-person-gear'
            )
            
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin.admin_users'))
        else:
            flash('Failed to update user.', 'danger')
    
    return render_template('admin/edit_user.html', user=user, current_user=current_user) 