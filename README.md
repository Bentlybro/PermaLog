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

## Example: WebSocket Integration

```javascript
// Connect to WebSocket
const socket = io('http://your-permalog-server');

// Handle connection events
socket.on('connect', () => {
  console.log('Connected to PermaLog WebSocket');
});

// Handle new log events
socket.on('new_log', (log) => {
  console.log('New log received:', log);
  // Process the new log...
});
```

## License

[MIT License](LICENSE) 