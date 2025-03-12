from flask import Blueprint, request, jsonify, render_template, redirect, url_for, send_file, session, flash
from app.database import store_log, get_logs, verify_log, verify_chain, get_total_logs_count, get_recent_activity
from app.database import create_api_key, list_api_keys, revoke_api_key, delete_api_key
from app.database import create_user, authenticate_user, get_user_by_id, create_session
from app.database import invalidate_session, list_users, update_user, validate_api_key
from app.database import invalidate_all_user_sessions, get_user_count, get_active_sessions_count
from app.database import log_activity
from app.middleware import require_api_key, require_auth
from app import socketio
import json
import csv
import io
import datetime
import secrets
import string

# Create blueprints for main routes, API, and auth
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)
auth_bp = Blueprint('auth', __name__)
admin_bp = Blueprint('admin', __name__)

# Authentication Routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    # If user is already logged in, redirect to dashboard
    if session.get('session_token'):
        return redirect(url_for('main.index'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = 'Username and password are required.'
        else:
            user = authenticate_user(username, password)
            
            if user:
                # Create a new session
                session_token = create_session(
                    user['id'],
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                
                if session_token:
                    # Store session token in cookie
                    session['session_token'] = session_token
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    
                    # Log the login activity
                    log_activity(
                        user_id=user['id'],
                        action='login',
                        message=f"User {user['username']} logged in",
                        ip_address=request.remote_addr
                    )
                    
                    flash('Login successful!', 'success')
                    
                    # Redirect to the next page or dashboard
                    next_page = request.args.get('next')
                    if next_page and next_page.startswith('/'):
                        return redirect(next_page)
                    return redirect(url_for('main.index'))
                else:
                    error = 'Failed to create session. Please try again.'
            else:
                error = 'Invalid username or password.'
    
    return render_template('login.html', error=error)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    # If user is already logged in, redirect to dashboard
    if session.get('session_token'):
        return redirect(url_for('main.index'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            error = 'All fields are required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        else:
            # Create a new user (default role is 'user')
            user_id = create_user(username, email, password)
            
            if user_id:
                # Log the registration activity
                log_activity(
                    user_id=user_id,
                    action='register',
                    message=f"User {username} registered",
                    ip_address=request.remote_addr
                )
                
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                error = 'Username or email already exists.'
    
    return render_template('register.html', error=error)

@auth_bp.route('/logout')
def logout():
    """Handle user logout."""
    # Get user info before invalidating session
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Invalidate the session
    session_token = session.get('session_token')
    if session_token:
        invalidate_session(session_token)
    
    # Log the logout activity if we have user info
    if user_id and username:
        log_activity(
            user_id=user_id,
            action='logout',
            message=f"User {username} logged out",
            ip_address=request.remote_addr
        )
    
    # Clear session data
    session.clear()
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# Web UI Routes
@main_bp.route('/')
@require_auth()
def index(current_user):
    """Render the main dashboard page."""
    # Get the total number of logs in the database
    total_logs = get_total_logs_count()
    return render_template('index.html', total_logs=total_logs, user=current_user)

@main_bp.route('/logs')
@require_auth('logs')
def logs_page(current_user):
    """Render the logs page with filters."""
    # Get filter parameters from query string
    level = request.args.get('level')
    source = request.args.get('source')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    is_ajax = request.args.get('ajax') == 'true'
    
    # Calculate offset for pagination
    offset = (page - 1) * per_page
    
    # Get logs with filters
    logs = get_logs(
        limit=per_page,
        offset=offset,
        level=level,
        source=source,
        start_time=start_time,
        end_time=end_time
    )
    
    # Get total logs count with the same filters
    total_logs = get_total_logs_count(
        level=level,
        source=source,
        start_time=start_time,
        end_time=end_time
    )
    
    # Preprocess logs to format timestamps and metadata for display
    for log in logs:
        # Format metadata as JSON string for display
        if log.get('metadata'):
            try:
                log['metadata_json'] = json.dumps(log['metadata'], indent=2)
            except Exception as e:
                log['metadata_json'] = f"Error formatting metadata: {str(e)}"
        else:
            log['metadata_json'] = 'None'
        
        # Ensure all necessary fields are present
        if 'hash' not in log:
            log['hash'] = 'Not available'
        if 'prev_hash' not in log:
            log['prev_hash'] = 'Not available'
    
    return render_template(
        'logs.html',
        logs=logs,
        page=page,
        per_page=per_page,
        level=level,
        source=source,
        start_time=start_time,
        end_time=end_time,
        total_logs=total_logs,
        is_ajax=is_ajax,
        user=current_user
    )

@main_bp.route('/verify')
@require_auth('verify')
def verify_page(current_user):
    """Render the verification page."""
    return render_template('verify.html', user=current_user)

@main_bp.route('/api-docs')
@require_auth('api_docs')
def api_docs_page(current_user):
    """Render the API documentation page."""
    return render_template('api_docs.html', user=current_user)

@main_bp.route('/api-keys')
@require_auth('api_keys')
def api_keys_page(current_user):
    """Render the API keys management page."""
    return render_template('api_keys.html', user=current_user)

# Admin Routes
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
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin.admin_users'))
        else:
            flash('Failed to update user.', 'danger')
    
    return render_template('admin/edit_user.html', user=user, current_user=current_user)

# API Routes
@api_bp.route('/log', methods=['POST'])
@require_api_key('write')
def add_log():
    """API endpoint to add a new log entry."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Validate required fields
    if 'level' not in data or 'message' not in data:
        return jsonify({'error': 'Missing required fields: level, message'}), 400
    
    # Store the log
    log = store_log(
        level=data['level'],
        message=data['message'],
        source=data.get('source'),
        metadata=data.get('metadata')
    )
    
    # Emit the new log to connected clients
    socketio.emit('new_log', log)
    
    return jsonify(log), 201

@api_bp.route('/logs', methods=['GET'])
@require_api_key('read')
def get_all_logs():
    """API endpoint to retrieve logs with optional filtering."""
    # Get filter parameters from query string
    level = request.args.get('level')
    source = request.args.get('source')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    # Get logs with filters
    logs = get_logs(
        limit=limit,
        offset=offset,
        level=level,
        source=source,
        start_time=start_time,
        end_time=end_time
    )
    
    return jsonify(logs)

@api_bp.route('/total-logs', methods=['GET'])
@require_api_key('read')
def get_total_logs():
    """API endpoint to get the total number of logs."""
    # Get filter parameters from query string
    level = request.args.get('level')
    source = request.args.get('source')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    
    # Get total logs count with filters
    total = get_total_logs_count(
        level=level,
        source=source,
        start_time=start_time,
        end_time=end_time
    )
    
    return jsonify({'total': total})

@api_bp.route('/verify/<int:log_id>', methods=['GET'])
@require_api_key('verify')
def verify_log_api(log_id):
    """API endpoint to verify the integrity of a specific log entry."""
    result = verify_log(log_id)
    return jsonify(result)

@api_bp.route('/verify', methods=['GET'])
@require_api_key('verify')
def verify_chain_api():
    """API endpoint to verify the integrity of the log chain."""
    start_id = request.args.get('start_id')
    end_id = request.args.get('end_id')
    
    # Convert to integers if provided
    if start_id:
        start_id = int(start_id)
    if end_id:
        end_id = int(end_id)
    
    result = verify_chain(start_id, end_id)
    return jsonify(result)

# API Key Management Routes
@api_bp.route('/keys', methods=['POST'])
@require_auth('api_keys')
def create_key(current_user):
    """Create a new API key."""
    data = request.json
    
    if not data or 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400
    
    permissions = data.get('permissions', ['read', 'write', 'verify'])
    
    # Validate permissions
    valid_permissions = ['read', 'write', 'verify']
    for perm in permissions:
        if perm not in valid_permissions:
            return jsonify({'error': f'Invalid permission: {perm}'}), 400
    
    # Associate the API key with the current user
    user_id = current_user.get('id')
    if user_id is None:
        return jsonify({'error': 'User ID not found in session'}), 500
        
    api_key = create_api_key(data['name'], permissions, user_id)
    
    # Log the API key creation
    log_activity(
        user_id=user_id,
        action='create_api_key',
        message=f"User {current_user['username']} created API key: {data['name']}",
        ip_address=request.remote_addr
    )
    
    return jsonify(api_key), 201

@api_bp.route('/keys', methods=['GET'])
@require_auth('api_keys')
def list_keys(current_user):
    """List API keys for the current user."""
    # Only admins can see all keys, others only see their own
    if current_user['role'] == 'admin':
        keys = list_api_keys()
    else:
        keys = list_api_keys(current_user['id'])
    
    return jsonify(keys)

@api_bp.route('/keys/<int:key_id>/revoke', methods=['POST'])
@require_auth('api_keys')
def revoke_key(key_id, current_user):
    """Revoke an API key."""
    # Check if the key belongs to the current user (unless admin)
    if current_user['role'] != 'admin':
        keys = list_api_keys(current_user['id'])
        if not any(key['id'] == key_id for key in keys):
            return jsonify({'error': 'API key not found or not authorized'}), 404
    
    # Get key info before revoking
    keys = list_api_keys(current_user['id'] if current_user['role'] != 'admin' else None)
    key_info = next((k for k in keys if k['id'] == key_id), None)
    
    success = revoke_api_key(key_id)
    
    if not success:
        return jsonify({'error': 'API key not found'}), 404
    
    # Log the API key revocation
    if key_info:
        # If admin is revoking someone else's key, log it differently
        if current_user['role'] == 'admin' and key_info['user_id'] and key_info['user_id'] != current_user['id']:
            # Get the username of the key owner
            user = get_user_by_id(key_info['user_id'])
            username = user['username'] if user else 'Unknown User'
            
            log_activity(
                user_id=current_user['id'],
                action='admin_revoke_api_key',
                message=f"Admin {current_user['username']} revoked API key '{key_info['name']}' belonging to {username}",
                ip_address=request.remote_addr,
                icon='bi-shield-lock'
            )
        else:
            log_activity(
                user_id=current_user['id'],
                action='revoke_api_key',
                message=f"User {current_user['username']} revoked API key: {key_info['name']}",
                ip_address=request.remote_addr
            )
    
    return jsonify({'message': 'API key revoked successfully'})

@api_bp.route('/keys/<int:key_id>', methods=['DELETE'])
@require_auth('api_keys')
def delete_key(key_id, current_user):
    """Delete an API key."""
    # Check if the key belongs to the current user (unless admin)
    if current_user['role'] != 'admin':
        keys = list_api_keys(current_user['id'])
        if not any(key['id'] == key_id for key in keys):
            return jsonify({'error': 'API key not found or not authorized'}), 404
    
    # Get key info before deleting
    keys = list_api_keys(current_user['id'] if current_user['role'] != 'admin' else None)
    key_info = next((k for k in keys if k['id'] == key_id), None)
    
    success = delete_api_key(key_id)
    
    if not success:
        return jsonify({'error': 'API key not found'}), 404
    
    # Log the API key deletion
    if key_info:
        # If admin is deleting someone else's key, log it differently
        if current_user['role'] == 'admin' and key_info['user_id'] and key_info['user_id'] != current_user['id']:
            # Get the username of the key owner
            user = get_user_by_id(key_info['user_id'])
            username = user['username'] if user else 'Unknown User'
            
            log_activity(
                user_id=current_user['id'],
                action='admin_delete_api_key',
                message=f"Admin {current_user['username']} deleted API key '{key_info['name']}' belonging to {username}",
                ip_address=request.remote_addr,
                icon='bi-shield-lock'
            )
        else:
            log_activity(
                user_id=current_user['id'],
                action='delete_api_key',
                message=f"User {current_user['username']} deleted API key: {key_info['name']}",
                ip_address=request.remote_addr
            )
    
    return jsonify({'message': 'API key deleted successfully'})

# Export Routes
@api_bp.route('/export', methods=['GET'])
def export_logs():
    """Export logs in various formats. API key required only for direct API access."""
    # Check if request is coming from the web UI
    referer = request.headers.get('Referer', '')
    is_web_ui = referer and (
        '/logs' in referer or 
        request.host_url.rstrip('/') in referer or
        request.host in referer
    )
    
    # If not from web UI, require API key
    if not is_web_ui:
        # Get API key from headers or query parameters
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'API key is required',
                'message': 'Please provide an API key using the X-API-Key header or api_key query parameter'
            }), 401
        
        # Validate the API key
        if not validate_api_key(api_key, 'read'):
            return jsonify({
                'error': 'Invalid API key',
                'message': 'The provided API key is invalid or does not have the required permissions'
            }), 403
    
    # Get filter parameters from query string
    level = request.args.get('level')
    source = request.args.get('source')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    format_type = request.args.get('format', 'json')  # Default to JSON
    
    # Get logs with filters (no limit for exports)
    logs = get_logs(
        limit=10000,  # Set a reasonable limit
        offset=0,
        level=level,
        source=source,
        start_time=start_time,
        end_time=end_time
    )
    
    # Generate filename with timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"permalog_export_{timestamp}"
    
    if format_type.lower() == 'csv':
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Timestamp', 'Level', 'Message', 'Source', 'Metadata', 'Hash', 'Previous Hash'])
        
        # Write data
        for log in logs:
            metadata = json.dumps(log.get('metadata', {}))
            writer.writerow([
                log.get('id', ''),
                log.get('timestamp', ''),
                log.get('level', ''),
                log.get('message', ''),
                log.get('source', ''),
                metadata,
                log.get('hash', ''),
                log.get('prev_hash', '')
            ])
        
        # Prepare response
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"{filename}.csv"
        )
    
    # Default to JSON
    return jsonify({
        'exported_at': datetime.datetime.now().isoformat(),
        'count': len(logs),
        'filters': {
            'level': level,
            'source': source,
            'start_time': start_time,
            'end_time': end_time
        },
        'logs': logs
    })

# User Management API (Admin only)
@api_bp.route('/admin/users', methods=['GET'])
@require_auth('admin')
def api_list_users(current_user):
    """API endpoint to list all users."""
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    users = list_users(limit=limit, offset=offset)
    return jsonify(users)

@api_bp.route('/admin/users', methods=['POST'])
@require_auth('admin')
def api_create_user(current_user):
    """API endpoint to create a new user."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Extract required fields
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    
    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400
    
    # Create the user
    user_id = create_user(username, email, password, role)
    
    if user_id:
        # Log the user creation
        log_activity(
            user_id=current_user['id'],
            action='create_user',
            message=f"Admin {current_user['username']} created user: {username}",
            ip_address=request.remote_addr,
            icon='bi-person-plus'
        )
        
        return jsonify({
            'id': user_id,
            'username': username,
            'email': email,
            'role': role,
            'message': 'User created successfully'
        })
    else:
        return jsonify({'error': 'Failed to create user. Username or email may already exist.'}), 400

@api_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@require_auth('admin')
def api_update_user(user_id, current_user):
    """API endpoint to update a user."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Get the user to check if it exists
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Extract fields to update
    update_data = {}
    if 'username' in data:
        update_data['username'] = data['username']
    if 'email' in data:
        update_data['email'] = data['email']
    if 'password' in data:
        update_data['password'] = data['password']
    if 'role' in data:
        update_data['role'] = data['role']
    if 'active' in data:
        update_data['active'] = data['active']
    
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
        
        return jsonify({'message': 'User updated successfully'})
    else:
        return jsonify({'error': 'Failed to update user'}), 400

@api_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@require_auth('admin')
def api_delete_user(user_id, current_user):
    """API endpoint to delete a user."""
    # Prevent deleting self
    if user_id == current_user['id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    # Get the user to check if it exists
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Deactivate the user instead of deleting
    success = update_user(user_id, active=False)
    
    if success:
        # Invalidate all sessions for this user
        invalidate_all_user_sessions(user_id)
        
        # Log the user deletion
        log_activity(
            user_id=current_user['id'],
            action='delete_user',
            message=f"Admin {current_user['username']} deleted user: {user['username']}",
            ip_address=request.remote_addr,
            icon='bi-person-x'
        )
        
        return jsonify({'message': 'User deleted successfully'})
    else:
        return jsonify({'error': 'Failed to delete user'}), 400

@api_bp.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@require_auth('admin')
def api_reset_user_password(user_id, current_user):
    """API endpoint to reset a user's password."""
    # Get the user to check if it exists
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate a random password
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
    # Update the user's password
    success = update_user(user_id, password=password)
    
    if success:
        # Invalidate all sessions for this user
        invalidate_all_user_sessions(user_id)
        
        # Log the password reset
        log_activity(
            user_id=current_user['id'],
            action='reset_password',
            message=f"Admin {current_user['username']} reset password for user: {user['username']}",
            ip_address=request.remote_addr,
            icon='bi-key'
        )
        
        return jsonify({
            'message': 'Password reset successfully',
            'password': password
        })
    else:
        return jsonify({'error': 'Failed to reset password'}), 400

@api_bp.route('/admin/users/<int:user_id>/invalidate-sessions', methods=['POST'])
@require_auth('admin')
def api_invalidate_user_sessions(user_id, current_user):
    """API endpoint to invalidate all sessions for a user."""
    # Get the user to check if it exists
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Invalidate all sessions for this user
    success = invalidate_all_user_sessions(user_id)
    
    if success:
        return jsonify({'message': 'Sessions invalidated successfully'})
    else:
        return jsonify({'error': 'Failed to invalidate sessions'}), 400

@api_bp.route('/admin/stats', methods=['GET'])
@require_auth('admin')
def api_admin_stats(current_user):
    """API endpoint to get system statistics."""
    # Get counts from database
    user_count = get_user_count()
    
    return jsonify({
        'users': user_count,
        'api_keys': len(list_api_keys()),
        'logs': get_total_logs_count(),
        'active_sessions': get_active_sessions_count()
    })

@api_bp.route('/admin/activity', methods=['GET'])
@require_auth('admin')
def api_admin_activity(current_user):
    """API endpoint to get recent system activity."""
    # Get recent activity from the database
    limit = int(request.args.get('limit', 10))
    activities = get_recent_activity(limit=limit)
    return jsonify(activities)

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection to WebSocket."""
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection from WebSocket."""
    print('Client disconnected') 