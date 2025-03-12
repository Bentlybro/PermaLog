import sqlite3
import hashlib
import json
import time
import os
from datetime import datetime, timedelta
import secrets
import uuid
import bcrypt
from cryptography.fernet import Fernet
import base64

# Ensure the data directory exists
if not os.path.exists('data'):
    os.makedirs('data')

DB_PATH = 'data/logs.db'

# Encryption key management
def get_encryption_key():
    """Get or create the encryption key for sensitive data."""
    key_path = 'data/encryption.key'
    
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
    else:
        # Generate a new key
        key = Fernet.generate_key()
        # Save the key to a file
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        
        # Set secure permissions on the key file
        try:
            os.chmod(key_path, 0o600)  # Only owner can read/write
        except:
            # Windows doesn't support the same permissions model
            pass
    
    return key

# Initialize encryption
ENCRYPTION_KEY = get_encryption_key()
FERNET = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt sensitive data."""
    if data is None:
        return None
    return FERNET.encrypt(data.encode('utf-8')).decode('utf-8')

def decrypt_data(encrypted_data):
    """Decrypt sensitive data."""
    if encrypted_data is None:
        return None
    return FERNET.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

def init_db():
    """Initialize the database with the logs table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create logs table with immutable design
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        source TEXT,
        metadata TEXT,
        prev_hash TEXT,
        hash TEXT NOT NULL
    )
    ''')
    
    # Create an index on timestamp for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
    
    # Create API keys table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used TEXT,
        permissions TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL,
        last_login TEXT,
        active INTEGER NOT NULL DEFAULT 1
    )
    ''')
    
    # Create sessions table for managing user sessions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create activity table for tracking user actions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        message TEXT NOT NULL,
        time TEXT NOT NULL,
        ip_address TEXT,
        icon TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Check if the activity table exists but doesn't have the icon column
    cursor.execute("PRAGMA table_info(activity)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'activity' in [table[0] for table in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()] and 'icon' not in columns:
        # Add the icon column to the activity table
        cursor.execute('ALTER TABLE activity ADD COLUMN icon TEXT')
    
    conn.commit()
    conn.close()

def get_last_log():
    """Get the last log entry to calculate the next hash."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, hash FROM logs ORDER BY id DESC LIMIT 1')
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return {'id': result[0], 'hash': result[1]}
    return None

def calculate_hash(log_data, prev_hash=None):
    """Calculate SHA-256 hash for a log entry."""
    # Create a string representation of the log data
    data_string = json.dumps(log_data, sort_keys=True)
    
    # Include the previous hash in the calculation if available
    if prev_hash:
        data_string = prev_hash + data_string
    
    # Calculate the SHA-256 hash
    return hashlib.sha256(data_string.encode()).hexdigest()

def store_log(level, message, source=None, metadata=None):
    """Store a new log entry with hash chaining."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get current timestamp
    timestamp = datetime.now().isoformat()
    
    # Convert metadata to JSON string if provided
    metadata_json = json.dumps(metadata) if metadata else None
    
    # Get the previous log entry
    last_log = get_last_log()
    prev_hash = last_log['hash'] if last_log else None
    
    # Prepare log data for hash calculation
    log_data = {
        'timestamp': timestamp,
        'level': level,
        'message': message,
        'source': source,
        'metadata': metadata_json
    }
    
    # Calculate the hash for this log entry
    current_hash = calculate_hash(log_data, prev_hash)
    
    # Insert the log entry
    cursor.execute('''
    INSERT INTO logs (timestamp, level, message, source, metadata, prev_hash, hash)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, level, message, source, metadata_json, prev_hash, current_hash))
    
    log_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return {
        'id': log_id,
        'timestamp': timestamp,
        'level': level,
        'message': message,
        'source': source,
        'metadata': metadata,
        'hash': current_hash
    }

def get_logs(limit=100, offset=0, level=None, source=None, start_time=None, end_time=None):
    """Retrieve logs with optional filtering."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    cursor = conn.cursor()
    
    query = 'SELECT * FROM logs'
    params = []
    
    # Build WHERE clause based on filters
    where_clauses = []
    
    if level:
        where_clauses.append('level = ?')
        params.append(level)
    
    if source:
        where_clauses.append('source = ?')
        params.append(source)
    
    if start_time:
        where_clauses.append('timestamp >= ?')
        params.append(start_time)
    
    if end_time:
        where_clauses.append('timestamp <= ?')
        params.append(end_time)
    
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Add ordering and pagination
    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Parse metadata JSON
    for log in logs:
        if log['metadata']:
            log['metadata'] = json.loads(log['metadata'])
    
    conn.close()
    return logs

def get_total_logs_count(level=None, source=None, start_time=None, end_time=None):
    """Get the total count of logs with optional filtering."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    query = 'SELECT COUNT(*) FROM logs'
    params = []
    
    # Build WHERE clause based on filters
    where_clauses = []
    
    if level:
        where_clauses.append('level = ?')
        params.append(level)
    
    if source:
        where_clauses.append('source = ?')
        params.append(source)
    
    if start_time:
        where_clauses.append('timestamp >= ?')
        params.append(start_time)
    
    if end_time:
        where_clauses.append('timestamp <= ?')
        params.append(end_time)
    
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    cursor.execute(query, params)
    count = cursor.fetchone()[0]
    
    conn.close()
    return count

def verify_log(log_id):
    """Verify the integrity of a log entry by checking its hash chain."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the log entry to verify
    cursor.execute('SELECT * FROM logs WHERE id = ?', (log_id,))
    log = cursor.fetchone()
    
    if not log:
        conn.close()
        return {'verified': False, 'error': 'Log entry not found'}
    
    log = dict(log)
    
    # Prepare log data for hash verification
    log_data = {
        'timestamp': log['timestamp'],
        'level': log['level'],
        'message': log['message'],
        'source': log['source'],
        'metadata': log['metadata']
    }
    
    # Calculate the hash
    calculated_hash = calculate_hash(log_data, log['prev_hash'])
    
    # Verify the hash
    if calculated_hash != log['hash']:
        conn.close()
        return {
            'verified': False, 
            'error': 'Hash mismatch', 
            'stored_hash': log['hash'], 
            'calculated_hash': calculated_hash
        }
    
    # If this is not the first log, verify the chain
    if log['prev_hash']:
        # Get the previous log
        cursor.execute('SELECT * FROM logs WHERE id < ? ORDER BY id DESC LIMIT 1', (log_id,))
        prev_log = cursor.fetchone()
        
        if prev_log and prev_log['hash'] != log['prev_hash']:
            conn.close()
            return {
                'verified': False, 
                'error': 'Previous hash mismatch', 
                'stored_prev_hash': log['prev_hash'], 
                'actual_prev_hash': prev_log['hash']
            }
    
    conn.close()
    return {'verified': True, 'log_id': log_id}

def verify_chain(start_id=None, end_id=None):
    """Verify the integrity of the entire log chain or a segment of it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Determine the range of logs to verify
    if end_id is None:
        cursor.execute('SELECT MAX(id) FROM logs')
        end_id = cursor.fetchone()[0]
    
    if start_id is None:
        start_id = 1
    
    # Get all logs in the range
    cursor.execute('SELECT * FROM logs WHERE id >= ? AND id <= ? ORDER BY id', (start_id, end_id))
    logs = [dict(row) for row in cursor.fetchall()]
    
    if not logs:
        conn.close()
        return {'verified': False, 'error': 'No logs found in the specified range'}
    
    # Verify each log and its connection to the previous one
    prev_hash = None
    for log in logs:
        # Prepare log data for hash verification
        log_data = {
            'timestamp': log['timestamp'],
            'level': log['level'],
            'message': log['message'],
            'source': log['source'],
            'metadata': log['metadata']
        }
        
        # Verify the hash
        calculated_hash = calculate_hash(log_data, log['prev_hash'])
        if calculated_hash != log['hash']:
            conn.close()
            return {
                'verified': False, 
                'error': f'Hash mismatch at log ID {log["id"]}', 
                'log_id': log['id'],
                'stored_hash': log['hash'], 
                'calculated_hash': calculated_hash
            }
        
        # Verify the chain
        if prev_hash is not None and log['prev_hash'] != prev_hash:
            conn.close()
            return {
                'verified': False, 
                'error': f'Chain broken at log ID {log["id"]}', 
                'log_id': log['id'],
                'stored_prev_hash': log['prev_hash'], 
                'expected_prev_hash': prev_hash
            }
        
        prev_hash = log['hash']
    
    conn.close()
    return {
        'verified': True, 
        'start_id': start_id, 
        'end_id': end_id, 
        'count': len(logs)
    }

# API Key Management Functions
def generate_api_key():
    """Generate a secure API key."""
    return f"plg_{secrets.token_hex(16)}"

def create_api_key(name, permissions=None, user_id=None):
    """Create a new API key.
    
    Args:
        name: A descriptive name for the API key
        permissions: A list of permissions (read, write, verify)
                    Default is ["read", "write", "verify"]
        user_id: The ID of the user who owns this key
    
    Returns:
        A dictionary containing the API key details
    """
    if permissions is None:
        permissions = ["read", "write", "verify"]
    
    # Ensure user_id is an integer or None
    if user_id is not None:
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            user_id = None
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Generate a plain text API key
    plain_key = generate_api_key()
    
    # Hash the key for storage (we'll use bcrypt for consistency)
    hashed_key = hash_password(plain_key)
    
    created_at = datetime.now().isoformat()
    permissions_json = json.dumps(permissions)
    
    cursor.execute('''
    INSERT INTO api_keys (key, name, created_at, permissions, active, user_id)
    VALUES (?, ?, ?, ?, 1, ?)
    ''', (hashed_key, name, created_at, permissions_json, user_id))
    
    api_key_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return {
        'id': api_key_id,
        'key': plain_key,  # Return the plain key only when first created
        'name': name,
        'created_at': created_at,
        'permissions': permissions,
        'active': True,
        'user_id': user_id
    }

def get_api_key(key):
    """Get API key details from the database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all API keys to check against the hashed values
    cursor.execute('SELECT * FROM api_keys WHERE active = 1')
    api_keys = cursor.fetchall()
    
    conn.close()
    
    # Check each key by comparing with bcrypt
    for api_key in api_keys:
        # Convert to dict for easier handling
        api_key_dict = dict(api_key)
        
        # Check if the provided key matches the stored hash
        if verify_password(api_key_dict['key'], key):
            api_key_dict['permissions'] = json.loads(api_key_dict['permissions'])
            api_key_dict['active'] = bool(api_key_dict['active'])
            return api_key_dict
    
    return None

def validate_api_key(key, required_permission=None):
    """Validate an API key and check if it has the required permission.
    
    Args:
        key: The API key to validate
        required_permission: The permission to check for (read, write, verify)
                            If None, just checks if the key is valid and active
    
    Returns:
        True if the key is valid and has the required permission, False otherwise
    """
    api_key = get_api_key(key)
    
    if not api_key or not api_key['active']:
        return False
    
    # Update last used timestamp
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE api_keys SET last_used = ? WHERE key = ?', 
                  (datetime.now().isoformat(), key))
    conn.commit()
    conn.close()
    
    if required_permission is None:
        return True
    
    return required_permission in api_key['permissions']

def list_api_keys(user_id=None):
    """List all API keys, optionally filtered by user_id."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if user_id is not None:
        cursor.execute('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    else:
        cursor.execute('SELECT * FROM api_keys ORDER BY created_at DESC')
    
    keys = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    # Parse permissions JSON
    for key in keys:
        key['permissions'] = json.loads(key['permissions'])
        key['active'] = bool(key['active'])
    
    return keys

def revoke_api_key(key_id):
    """Revoke an API key by setting it as inactive."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE api_keys SET active = 0 WHERE id = ?', (key_id,))
    affected_rows = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return affected_rows > 0

def delete_api_key(key_id):
    """Delete an API key from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    affected_rows = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return affected_rows > 0

# User Authentication Functions
def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(stored_hash, provided_password):
    """Verify a password against a stored hash."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash.encode('utf-8'))

def create_user(username, email, password, role='user'):
    """Create a new user account.
    
    Args:
        username: Unique username
        email: User's email address
        password: Plain text password (will be hashed)
        role: User role (user, moderator, admin)
    
    Returns:
        User ID if successful, None if username or email already exists
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return None
    
    # Check if email already exists (need to check all emails and decrypt)
    cursor.execute('SELECT email FROM users')
    existing_emails = cursor.fetchall()
    
    # Check if the email is already in use
    for row in existing_emails:
        stored_email = row[0]
        # If email is encrypted, decrypt it
        if stored_email.startswith('gAAAAA'):  # Fernet encrypted data starts with this prefix
            try:
                decrypted_email = decrypt_data(stored_email)
                if decrypted_email.lower() == email.lower():
                    conn.close()
                    return None
            except:
                # If decryption fails, it's not a match
                pass
        # For non-encrypted emails (legacy data)
        elif stored_email.lower() == email.lower():
            conn.close()
            return None
    
    # Hash the password
    password_hash = hash_password(password)
    created_at = datetime.now().isoformat()
    
    # Encrypt the email
    encrypted_email = encrypt_data(email)
    
    try:
        cursor.execute('''
        INSERT INTO users (username, email, password_hash, role, created_at, active)
        VALUES (?, ?, ?, ?, ?, 1)
        ''', (username, encrypted_email, password_hash, role, created_at))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return user_id
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        return None

def authenticate_user(username_or_email, password):
    """Authenticate a user with username/email and password.
    
    Args:
        username_or_email: Username or email address
        password: Plain text password
    
    Returns:
        User dict if authentication successful, None otherwise
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Try to find user by username
    cursor.execute('''
    SELECT * FROM users 
    WHERE username = ? AND active = 1
    ''', (username_or_email,))
    
    user = cursor.fetchone()
    
    # If not found by username, try to find by email
    if not user:
        # Get all users and check emails manually (since they're encrypted)
        cursor.execute('SELECT * FROM users WHERE active = 1')
        all_users = cursor.fetchall()
        
        for potential_user in all_users:
            stored_email = potential_user['email']
            # Check if email is encrypted
            if stored_email.startswith('gAAAAA'):  # Fernet encrypted data starts with this prefix
                try:
                    decrypted_email = decrypt_data(stored_email)
                    if decrypted_email.lower() == username_or_email.lower():
                        user = potential_user
                        break
                except:
                    # If decryption fails, continue to next user
                    continue
            # For non-encrypted emails (legacy data)
            elif stored_email.lower() == username_or_email.lower():
                user = potential_user
                break
    
    if not user:
        conn.close()
        return None
    
    # Verify password
    if not verify_password(user['password_hash'], password):
        conn.close()
        return None
    
    # Update last login time
    cursor.execute('''
    UPDATE users SET last_login = ? WHERE id = ?
    ''', (datetime.now().isoformat(), user['id']))
    
    conn.commit()
    
    # Convert row to dict
    user_dict = dict(user)
    
    # Decrypt email if it's encrypted
    if user_dict['email'] and user_dict['email'].startswith('gAAAAA'):
        try:
            user_dict['email'] = decrypt_data(user_dict['email'])
        except:
            # If decryption fails, leave as is
            pass
    
    conn.close()
    return user_dict

def get_user_by_id(user_id):
    """Get user by ID."""
    if user_id is None:
        return None
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        user_dict = dict(user)
        
        # Decrypt email if it's encrypted
        if user_dict['email'] and user_dict['email'].startswith('gAAAAA'):
            try:
                user_dict['email'] = decrypt_data(user_dict['email'])
            except:
                # If decryption fails, leave as is
                pass
                
        return user_dict
    return None

def create_session(user_id, ip_address=None, user_agent=None, expires_days=30):
    """Create a new session for a user.
    
    Args:
        user_id: User ID
        ip_address: Client IP address
        user_agent: Client user agent
        expires_days: Number of days until session expires
    
    Returns:
        Session token if successful, None otherwise
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Generate a secure session token
    session_token = secrets.token_hex(32)
    created_at = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
    
    try:
        cursor.execute('''
        INSERT INTO sessions (user_id, session_token, created_at, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, session_token, created_at, expires_at, ip_address, user_agent))
        
        conn.commit()
        conn.close()
        return session_token
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        return None

def validate_session(session_token):
    """Validate a session token and return the associated user.
    
    Args:
        session_token: Session token to validate
    
    Returns:
        User dict if session is valid, None otherwise
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the session
    cursor.execute('''
    SELECT s.*, u.* FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.session_token = ? AND s.expires_at > ? AND u.active = 1
    ''', (session_token, datetime.now().isoformat()))
    
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return None
    
    # Convert row to dict
    user = {k: result[k] for k in result.keys() if k not in ('session_token', 'expires_at', 'created_at', 'ip_address', 'user_agent')}
    
    conn.close()
    return user

def invalidate_session(session_token):
    """Invalidate a session (logout)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
    
    conn.commit()
    conn.close()
    
    return cursor.rowcount > 0

def invalidate_all_user_sessions(user_id):
    """Invalidate all sessions for a user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    return cursor.rowcount > 0

def update_user(user_id, **kwargs):
    """Update user information.
    
    Args:
        user_id: User ID
        **kwargs: Fields to update (username, email, password, role, active)
    
    Returns:
        True if successful, False otherwise
    """
    allowed_fields = {'username', 'email', 'password', 'role', 'active'}
    update_fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
    
    if not update_fields:
        return False
    
    # Special handling for password
    if 'password' in update_fields:
        update_fields['password_hash'] = hash_password(update_fields.pop('password'))
    
    # Special handling for email
    if 'email' in update_fields:
        update_fields['email'] = encrypt_data(update_fields['email'])
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Build the update query
        set_clause = ', '.join(f"{field} = ?" for field in update_fields)
        values = list(update_fields.values())
        values.append(user_id)
        
        cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        
        conn.commit()
        conn.close()
        return cursor.rowcount > 0
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        return False

def list_users(limit=100, offset=0):
    """List all users with pagination."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT id, username, email, role, created_at, last_login, active
    FROM users
    ORDER BY id
    LIMIT ? OFFSET ?
    ''', (limit, offset))
    
    users = [dict(row) for row in cursor.fetchall()]
    
    # Decrypt emails
    for user in users:
        if user['email'] and user['email'].startswith('gAAAAA'):
            try:
                user['email'] = decrypt_data(user['email'])
            except:
                # If decryption fails, leave as is
                pass
    
    conn.close()
    return users

def get_user_count():
    """Get the total number of users."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM users')
    count = cursor.fetchone()[0]
    
    conn.close()
    return count

def get_active_sessions_count():
    """Get the count of active sessions.
    
    Returns:
        int: Number of active sessions
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Count sessions that haven't expired
    cursor.execute('''
    SELECT COUNT(*) FROM sessions 
    WHERE expires_at > ?
    ''', (datetime.now().isoformat(),))
    
    count = cursor.fetchone()[0]
    
    conn.close()
    return count

def log_activity(user_id, action, message, ip_address=None, icon=None):
    """Log user activity.
    
    Args:
        user_id: User ID (can be None for system actions)
        action: Action type (e.g., 'login', 'create_api_key')
        message: Description of the activity
        ip_address: IP address of the user
        icon: Bootstrap icon class for UI display
        
    Returns:
        int: ID of the new activity record
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Set default icon based on action if not provided
    if not icon:
        icon_map = {
            'login': 'bi-box-arrow-in-right',
            'logout': 'bi-box-arrow-left',
            'create_api_key': 'bi-key-fill',
            'revoke_api_key': 'bi-key',
            'delete_api_key': 'bi-trash',
            'register': 'bi-person-plus',
            'update_user': 'bi-person-gear',
            'delete_user': 'bi-person-x',
            'admin_revoke_api_key': 'bi-shield-lock',
            'admin_delete_api_key': 'bi-shield-exclamation',
            'create_user': 'bi-person-plus-fill',
            'reset_password': 'bi-key-fill'
        }
        icon = icon_map.get(action, 'bi-activity')
    
    cursor.execute('''
    INSERT INTO activity (user_id, action, message, time, ip_address, icon)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        action,
        message,
        datetime.now().isoformat(),
        ip_address,
        icon
    ))
    
    activity_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return activity_id

def get_recent_activity(limit=10):
    """Get recent activity.
    
    Args:
        limit: Maximum number of activities to return
        
    Returns:
        list: Recent activity records
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if the icon column exists
    cursor.execute("PRAGMA table_info(activity)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'icon' in columns:
        cursor.execute('''
        SELECT a.id, a.user_id, a.action, a.message, a.time, a.ip_address, a.icon, u.username
        FROM activity a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.time DESC
        LIMIT ?
        ''', (limit,))
    else:
        cursor.execute('''
        SELECT a.id, a.user_id, a.action, a.message, a.time, a.ip_address, NULL as icon, u.username
        FROM activity a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.time DESC
        LIMIT ?
        ''', (limit,))
    
    activities = [dict(row) for row in cursor.fetchall()]
    
    # Set default icons based on action if icon is NULL
    for activity in activities:
        if not activity.get('icon'):
            icon_map = {
                'login': 'bi-box-arrow-in-right',
                'logout': 'bi-box-arrow-left',
                'create_api_key': 'bi-key-fill',
                'revoke_api_key': 'bi-key',
                'delete_api_key': 'bi-trash',
                'register': 'bi-person-plus',
                'update_user': 'bi-person-gear',
                'delete_user': 'bi-person-x',
                'admin_revoke_api_key': 'bi-shield-lock',
                'admin_delete_api_key': 'bi-shield-exclamation',
                'create_user': 'bi-person-plus-fill',
                'reset_password': 'bi-key-fill'
            }
            activity['icon'] = icon_map.get(activity.get('action'), 'bi-activity')
    
    conn.close()
    return activities

init_db() 