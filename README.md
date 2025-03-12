# PermaLog - Immutable Logging Service

PermaLog is a secure, immutable logging service built with Flask and SQLite that ensures logs cannot be modified or deleted once recorded. It provides a comprehensive API and real-time WebSocket updates for log monitoring.

## Features

- **Immutable Logging**: Logs cannot be modified or deleted once recorded
- **Secure Storage**: SQLite with append-only design
- **Tamper Detection**: SHA-256 hash chaining for log integrity
- **Comprehensive API**: Well-documented endpoints for logging and verification
- **API Key Authentication**: Secure API access with granular permissions
- **Rate Limiting**: Protection against API abuse with configurable limits
- **Export Functionality**: Export logs in JSON or CSV format
- **Real-time Updates**: WebSocket integration for live log monitoring
- **Web UI**: Modern dashboard for searching, viewing, and verifying logs
- **Syntax Highlighted Documentation**: Interactive API documentation with code examples

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/log | Store a new log entry |
| GET | /api/logs | Fetch logs with optional filtering |
| GET | /api/total-logs | Get the total number of logs |
| GET | /api/verify/:id | Verify specific log integrity |
| GET | /api/verify | Verify entire log chain integrity |

## WebSocket Events

| Event | Description |
|-------|-------------|
| connect | Fired when client connects to server |
| disconnect | Fired when client disconnects from server |
| new_log | Fired when a new log is added to the system |

## Setup

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure environment variables:
   - Copy the `.env.example` file to `.env` (or create a new `.env` file)
   - Update the values in the `.env` file as needed:
     ```
     # Flask Secret Key (used for session management)
     FLASK_SECRET_KEY=change-this-to-a-secure-random-string

     # Debug mode (set to False in production)
     FLASK_DEBUG=True

     # Initial Admin User (created on first run if no users exist)
     PERMALOG_ADMIN_USERNAME=admin
     PERMALOG_ADMIN_EMAIL=admin@example.com
     # If not set, a random password will be generated and displayed on first run
     PERMALOG_ADMIN_PASSWORD=
     ```
4. Run the application:
   ```
   python run.py
   ```
5. Access the web interface at `http://localhost:5000`

### Initial Admin User

On first startup, if no users exist in the system, PermaLog will automatically create an admin user:

- If `PERMALOG_ADMIN_PASSWORD` is set in your `.env` file, that password will be used
- If not set, a random secure password will be generated and displayed in the console
- The default username is `admin` and email is `admin@example.com` (can be changed in `.env`)
- Use these credentials to log in, and change the password after first login

## Security Features

- **Hash Chaining**: Each log entry contains a hash of the previous log for integrity verification
- **Append-Only Database**: SQLite configured to prevent modifications
- **No UPDATE/DELETE**: Database operations restricted to INSERT only
- **Cryptographic Verification**: SHA-256 hashing for tamper detection
- **Chain Verification**: Ability to verify the entire log chain or specific ranges
- **API Key Authentication**: Secure API access with read, write, and verify permissions
- **Rate Limiting**: Protection against API abuse with per-key rate limits
- **User Authentication**: Secure login system with role-based access control
- **Session Management**: Secure session handling with automatic expiration

## Authentication System

PermaLog includes a comprehensive authentication system with the following features:

- **User Registration**: Self-service user registration with email verification
- **Role-Based Access Control**: Three user roles with different permissions:
  - **User**: Can view dashboard, logs, verify logs, and API documentation
  - **Moderator**: User permissions plus API key management
  - **Admin**: Moderator permissions plus user management and system administration
- **API Key Management**: Users can create and manage their own API keys
- **Session Management**: Secure session handling with automatic expiration
- **Password Security**: Passwords are hashed using bcrypt for maximum security

## Web Dashboard

Access the web dashboard at `http://localhost:5000` to:
- View all logs with advanced filtering
- Search and filter logs by level, source, and time range
- Monitor real-time log updates via WebSockets
- Verify log integrity for individual logs or ranges

## API Documentation

PermaLog includes comprehensive API documentation with:
- Detailed endpoint descriptions
- Request and response examples
- Code examples in multiple languages (cURL, Python, JavaScript, Go)
- WebSocket integration examples
- Interactive syntax highlighting
- API key management interface

Access the API documentation at `http://localhost:5000/api-docs`

## Example: Adding a Log

```python
import requests
import json

url = "http://your-permalog-server/api/log"
headers = {
    "Content-Type": "application/json",
    "X-API-Key": "your_api_key_here"
}
data = {
    "level": "info",
    "message": "User logged in",
    "source": "auth-service",
    "metadata": {
        "user_id": 123,
        "ip": "192.168.1.1"
    }
}

response = requests.post(url, headers=headers, json=data)
print(response.status_code)  # Should be 201
print(json.dumps(response.json(), indent=2))
```

## Example: Convenient Logging Function

Here's a more convenient way to use PermaLog in your applications:

```python
import requests
import json
from typing import Dict, Any, Optional

class PermaLogger:
    def __init__(self, base_url: str, api_key: str, default_source: str = "app"):
        """
        Initialize the PermaLogger.
        
        Args:
            base_url: The base URL of your PermaLog server
            api_key: Your PermaLog API key
            default_source: Default source name for logs
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.default_source = default_source
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }
    
    def log(self, 
            message: str, 
            level: str = "info", 
            source: Optional[str] = None, 
            metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send a log entry to PermaLog.
        
        Args:
            message: The log message
            level: Log level (info, warning, error, debug, etc.)
            source: Source of the log (defaults to the one set in constructor)
            metadata: Additional metadata for the log entry
            
        Returns:
            The response from the PermaLog server as a dictionary
        """
        url = f"{self.base_url}/api/log"
        
        data = {
            "level": level,
            "message": message,
            "source": source or self.default_source,
            "metadata": metadata or {}
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data)
            response.raise_for_status()  # Raise exception for 4XX/5XX responses
            return response.json()
        except requests.exceptions.RequestException as e:
            # Handle the error or re-raise
            print(f"Error sending log to PermaLog: {e}")
            return {"error": str(e)}
    
    def info(self, message: str, source: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience method for info logs."""
        return self.log(message, "info", source, metadata)
    
    def warning(self, message: str, source: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience method for warning logs."""
        return self.log(message, "warning", source, metadata)
    
    def error(self, message: str, source: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience method for error logs."""
        return self.log(message, "error", source, metadata)
    
    def debug(self, message: str, source: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience method for debug logs."""
        return self.log(message, "debug", source, metadata)


# Usage example:
if __name__ == "__main__":
    # Initialize the logger
    logger = PermaLogger(
        base_url="http://your-permalog-server",
        api_key="your_api_key_here",
        default_source="user-service"
    )
    
    # Simple log
    logger.info("User logged in")
    
    # Log with metadata
    logger.info(
        message="User profile updated",
        metadata={
            "user_id": 123,
            "changes": {"name": "New Name", "email": "new@example.com"}
        }
    )
    
    # Error log from a different source
    logger.error(
        message="Database connection failed",
        source="database-service",
        metadata={"error_code": "DB_CONN_001", "retry_count": 3}
    )
```
## Example: WebSocket Integration

```python
import socketio
import json

# Create a Socket.IO client
sio = socketio.Client()

# Define event handlers
@sio.event
def connect():
    print('Connected to PermaLog WebSocket')

@sio.event
def disconnect():
    print('Disconnected from PermaLog WebSocket')

@sio.event
def new_log(log):
    print(f'New log received: {json.dumps(log, indent=2)}')
    # Process the new log...

# Connect to the server
sio.connect('http://your-permalog-server')

# Keep the connection alive (in a real application, you might have other code running)
try:
    sio.wait()
except KeyboardInterrupt:
    # Gracefully disconnect on keyboard interrupt
    sio.disconnect()
```

## Screenshots

Main dashboard
![image](https://github.com/user-attachments/assets/ccb3f666-b093-4774-8c75-2ac18209a298)


Log explorer
![image](https://github.com/user-attachments/assets/0aba49d4-d277-4aec-8d27-cd4ab88a027d)
![image](https://github.com/user-attachments/assets/777e0d88-2770-4247-ba72-b884f5930642)


Log verification
![image](https://github.com/user-attachments/assets/1ec85e1f-f1b8-4ee6-a6f0-2524fe06449b)
![image](https://github.com/user-attachments/assets/1038a9a7-cfa9-4e3e-baa7-fc20169f4dad)

![image](https://github.com/user-attachments/assets/b9a1bd8d-6a99-4422-bbcb-80ba33f8fe69)
![image](https://github.com/user-attachments/assets/ba5d6aeb-6e0f-434f-b88b-3100ca43931c)


## License

[MIT License](LICENSE) 


## Security

For information about reporting security vulnerabilities, please see our [Security Policy](SECURITY.md). 