"""Main web UI routes for the PermaLog application."""

from flask import Blueprint, render_template, redirect, url_for
from app.database import get_total_logs_count
from app.middleware import require_auth

# Create blueprint for main routes
main_bp = Blueprint('main', __name__)

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
    from flask import request
    from app.database import get_logs
    import json
    
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