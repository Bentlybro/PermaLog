# PermaLog - Immutable Logging Service

PermaLog is a secure, immutable logging service built with Flask and SQLite. It ensures logs cannot be modified or deleted once recorded and provides a comprehensive API and real-time WebSocket updates for log monitoring.

## Features

- **Immutable Logging**: Logs cannot be changed.
- **Secure Storage**: Uses SQLite with append-only design.
- **Real-time Monitoring**: WebSocket updates.
- **API and Web Interface**: Offers both API and a web UI.

## Setup

1. Clone the repository: `git clone <repo-url>`
2. Navigate into the directory: `cd PermaLog`
3. Run using Docker:
   ```
   docker-compose up
   ```

Access the application at `http://localhost:5000`.

## Docker Installation

Ensure you have Docker installed along with Docker Compose. The `docker-compose.yml` is already configured for quick setup.

## Contributing

We welcome contributions! Please open issues and submit pull requests with improvements.

```