from functools import wraps
from flask import request, jsonify, redirect, url_for, session, flash
from app.database import validate_api_key, validate_session, get_user_by_id
import time
import threading
import collections

# Simple in-memory rate limiter
class RateLimiter:
    def __init__(self, limit=100, window=60):
        """
        Initialize a rate limiter.
        
        Args:
            limit: Maximum number of requests allowed in the time window
            window: Time window in seconds
        """
        self.limit = limit
        self.window = window
        self.requests = collections.defaultdict(list)
        self.lock = threading.Lock()
        
        # Start a cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_requests, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_old_requests(self):
        """Periodically clean up old requests to prevent memory leaks."""
        while True:
            time.sleep(self.window)
            with self.lock:
                current_time = time.time()
                for key in list(self.requests.keys()):
                    # Remove requests older than the window
                    self.requests[key] = [t for t in self.requests[key] if current_time - t < self.window]
                    # Remove empty lists
                    if not self.requests[key]:
                        del self.requests[key]
    
    def is_rate_limited(self, key):
        """
        Check if a key is rate limited.
        
        Args:
            key: The key to check (e.g., API key or IP address)
            
        Returns:
            tuple: (is_limited, remaining, reset_time)
        """
        with self.lock:
            current_time = time.time()
            
            # Remove requests older than the window
            self.requests[key] = [t for t in self.requests[key] if current_time - t < self.window]
            
            # Check if the key has exceeded the limit
            is_limited = len(self.requests[key]) >= self.limit
            
            # Add the current request if not limited
            if not is_limited:
                self.requests[key].append(current_time)
            
            # Calculate remaining requests and reset time
            remaining = max(0, self.limit - len(self.requests[key]))
            
            # Calculate when the oldest request will expire
            if self.requests[key]:
                oldest_request = min(self.requests[key])
                reset_time = int(oldest_request + self.window - current_time)
            else:
                reset_time = 0
            
            return is_limited, remaining, reset_time

# Create a global rate limiter instance
# 100 requests per minute by default
rate_limiter = RateLimiter(limit=100, window=60)

# Role-based access control
ROLE_PERMISSIONS = {
    'user': ['dashboard', 'logs', 'verify', 'api_docs'],
    'moderator': ['dashboard', 'logs', 'verify', 'api_docs', 'api_keys'],
    'admin': ['dashboard', 'logs', 'verify', 'api_docs', 'api_keys', 'admin']
}

def require_auth(permission=None):
    """
    Decorator to require authentication for a route.
    Optionally checks for specific permission based on user role.
    
    Args:
        permission: The permission required (e.g., 'dashboard', 'logs', 'api_keys', 'admin')
                   If None, just checks if the user is authenticated
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is authenticated
            user = None
            
            # Check for session cookie
            session_token = session.get('session_token')
            if session_token:
                user = validate_session(session_token)
            
            if not user:
                # Redirect to login page
                return redirect(url_for('auth.login', next=request.path))
            
            # Check permission if specified
            if permission and permission not in ROLE_PERMISSIONS.get(user['role'], []):
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('main.index'))
            
            # Add user to kwargs
            kwargs['current_user'] = user
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_api_key(permission=None):
    """
    Decorator to require a valid API key for a route.
    
    Args:
        permission: The permission required (read, write, verify)
                   If None, just checks if the key is valid
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if this is a web UI request with a valid session
            is_verify_endpoint = request.path == '/api/verify' or request.path.startswith('/api/verify/')
            is_export_endpoint = request.path == '/api/export'
            
            if is_verify_endpoint or is_export_endpoint:
                # For verification and export endpoints, check if request is from web UI
                referer = request.headers.get('Referer', '')
                is_web_ui = referer and (
                    '/verify' in referer or 
                    '/logs' in referer or
                    request.host_url.rstrip('/') in referer or
                    request.host in referer
                )
                
                if is_web_ui:
                    # Check for session cookie
                    session_token = session.get('session_token')
                    if session_token and validate_session(session_token):
                        # User is authenticated via web UI, allow access
                        return f(*args, **kwargs)
            
            # Check for API key in headers
            api_key = request.headers.get('X-API-Key')
            
            # If no API key in headers, check query parameters
            if not api_key:
                api_key = request.args.get('api_key')
            
            # If still no API key, return error
            if not api_key:
                return jsonify({
                    'error': 'API key is required',
                    'message': 'Please provide an API key using the X-API-Key header or api_key query parameter'
                }), 401
            
            # Validate the API key
            if not validate_api_key(api_key, permission):
                return jsonify({
                    'error': 'Invalid API key',
                    'message': 'The provided API key is invalid or does not have the required permissions'
                }), 403
            
            # Check rate limit
            is_limited, remaining, reset_time = rate_limiter.is_rate_limited(api_key)
            
            # Add rate limit headers to the response
            def add_rate_limit_headers(response):
                response.headers['X-RateLimit-Limit'] = str(rate_limiter.limit)
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                response.headers['X-RateLimit-Reset'] = str(reset_time)
                return response
            
            # If rate limited, return error
            if is_limited:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'You have exceeded the rate limit of {rate_limiter.limit} requests per {rate_limiter.window} seconds',
                    'reset_in': reset_time
                }), 429
                return add_rate_limit_headers(response)
            
            # Call the original function
            response = f(*args, **kwargs)
            
            # Add rate limit headers to the response
            if isinstance(response, tuple) and len(response) == 2:
                # Response is (json, status_code)
                json_response, status_code = response
                response = jsonify(json_response), status_code
            
            return add_rate_limit_headers(response)
        return decorated_function
    return decorator 