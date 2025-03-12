"""API routes for the PermaLog application."""

from flask import Blueprint, request, jsonify, send_file
from app.database import store_log, get_logs, verify_log, verify_chain, get_total_logs_count
from app.database import create_api_key, list_api_keys, revoke_api_key, delete_api_key
from app.database import get_user_by_id, update_user, validate_api_key
from app.database import invalidate_all_user_sessions, get_user_count, get_active_sessions_count
from app.database import create_user, log_activity, get_recent_activity
from app.middleware import require_api_key, require_auth
from app import socketio
import json
import csv
import io
import datetime
import secrets
import string

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

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

# Admin API Routes
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