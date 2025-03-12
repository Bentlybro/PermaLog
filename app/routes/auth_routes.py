"""Authentication routes for the PermaLog application."""

from flask import Blueprint, request, render_template, redirect, url_for, session, flash
from app.database import create_user, authenticate_user, create_session, invalidate_session, log_activity

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

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