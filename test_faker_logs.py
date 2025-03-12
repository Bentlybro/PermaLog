#!/usr/bin/env python
"""
PermaLog - Realistic Test Data Generator
This script uses Faker to generate realistic log data for testing the PermaLog application.
"""

import requests
import json
import time
import random
import argparse
import uuid
from datetime import datetime, timedelta
from faker import Faker

# Initialize Faker
fake = Faker()

# API endpoint
API_URL = "http://localhost:5000/api"

# Log sources
SOURCES = [
    "auth-service",
    "user-service",
    "payment-service",
    "notification-service",
    "api-gateway",
    "database-service",
    "file-service",
    "search-service",
    "recommendation-engine",
    "analytics-service"
]

# Log levels with weighted probabilities
LOG_LEVELS = {
    "info": 0.2,      # 20% chance
    "warning": 0.2,   # 20% chance
    "error": 0.2,     # 20% chance
    "debug": 0.2,    # 20% chance
    "critical": 0.2  # 20% chance
}

def add_log(level, message, source=None, metadata=None):
    """Add a new log entry via the API."""
    url = f"{API_URL}/log"
    
    data = {
        "level": level,
        "message": message
    }
    
    if source:
        data["source"] = source
    
    if metadata:
        data["metadata"] = metadata
    
    response = requests.post(url, json=data)
    
    if response.status_code == 201:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Log added: [{level.upper()}] {message}")
        return response.json()
    else:
        print(f"Failed to add log: {response.text}")
        return None

def get_weighted_log_level():
    """Get a log level based on weighted probabilities."""
    r = random.random()
    cumulative = 0
    for level, weight in LOG_LEVELS.items():
        cumulative += weight
        if r <= cumulative:
            return level
    return "info"  # Default fallback

def generate_auth_log():
    """Generate authentication-related log entries."""
    actions = ["logged in", "logged out", "failed login attempt", "password reset", "account locked", "account unlocked", "changed password"]
    action = random.choice(actions)
    
    if "failed" in action or "locked" in action:
        level = random.choice(["warning", "error"])
    elif "reset" in action or "unlocked" in action:
        level = "info"
    else:
        level = get_weighted_log_level()
    
    username = fake.user_name()
    
    if "failed" in action:
        message = f"User {username} made a {action} from {fake.ipv4()}"
    else:
        message = f"User {username} {action} successfully"
    
    metadata = {
        "user_id": str(uuid.uuid4())[:8],
        "ip_address": fake.ipv4(),
        "user_agent": fake.user_agent(),
        "timestamp_ms": int(time.time() * 1000)
    }
    
    # Add some conditional metadata
    if random.random() > 0.7:
        metadata["location"] = fake.city() + ", " + fake.country_code()
    
    if "failed" in action:
        metadata["failure_reason"] = random.choice(["Invalid password", "Account not found", "Account locked", "Suspicious activity"])
        metadata["attempt_number"] = random.randint(1, 5)
    
    return level, message, "auth-service", metadata

def generate_payment_log():
    """Generate payment-related log entries."""
    actions = ["payment processed", "payment failed", "refund issued", "subscription renewed", "payment method updated", "invoice generated"]
    action = random.choice(actions)
    
    if "failed" in action:
        level = random.choice(["warning", "error"])
    elif "refund" in action:
        level = "warning"
    else:
        level = get_weighted_log_level()
    
    amount = round(random.uniform(5.99, 299.99), 2)
    payment_method = random.choice(["credit card", "PayPal", "bank transfer", "cryptocurrency"])
    
    if "failed" in action:
        message = f"Customer payment of ${amount} via {payment_method} {action}"
    else:
        message = f"${amount} {action} via {payment_method}"
    
    metadata = {
        "transaction_id": str(uuid.uuid4()),
        "customer_id": str(uuid.uuid4())[:8],
        "amount": amount,
        "currency": random.choice(["USD", "EUR", "GBP", "JPY", "CAD"]),
        "payment_method": payment_method
    }
    
    if "failed" in action:
        metadata["error_code"] = random.choice(["INSUFFICIENT_FUNDS", "CARD_DECLINED", "EXPIRED_CARD", "INVALID_DETAILS"])
        metadata["attempt_number"] = random.randint(1, 3)
    
    if random.random() > 0.7:
        metadata["subscription_id"] = f"sub_{random.randint(10000, 99999)}"
    
    return level, message, "payment-service", metadata

def generate_api_log():
    """Generate API-related log entries."""
    endpoints = ["/api/users", "/api/products", "/api/orders", "/api/payments", "/api/auth", "/api/search"]
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    
    endpoint = random.choice(endpoints)
    method = random.choice(methods)
    status_code = random.choice([200, 201, 204, 400, 401, 403, 404, 500])
    
    if status_code >= 500:
        level = "error"
    elif status_code >= 400:
        level = "warning"
    else:
        level = "info"
    
    response_time = round(random.uniform(50, 2000), 2)  # ms
    
    message = f"{method} {endpoint} - {status_code} ({response_time}ms)"
    
    if status_code >= 400:
        message += f" - {random.choice(['Bad request', 'Unauthorized', 'Not found', 'Server error'])}"
    
    metadata = {
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "response_time_ms": response_time,
        "ip_address": fake.ipv4(),
        "user_agent": fake.user_agent()
    }
    
    if random.random() > 0.7:
        metadata["request_id"] = str(uuid.uuid4())
    
    if status_code >= 400:
        metadata["error_details"] = random.choice([
            "Invalid input parameters",
            "Authentication token expired",
            "Resource not found",
            "Permission denied",
            "Internal server error",
            "Database connection failed"
        ])
    
    return level, message, "api-gateway", metadata

def generate_database_log():
    """Generate database-related log entries."""
    actions = [
        "query executed",
        "connection established",
        "connection closed",
        "transaction committed",
        "transaction rolled back",
        "table created",
        "index created",
        "backup completed",
        "query timeout",
        "deadlock detected"
    ]
    
    action = random.choice(actions)
    
    if "timeout" in action or "deadlock" in action or "rolled back" in action:
        level = random.choice(["warning", "error"])
    else:
        level = get_weighted_log_level()
    
    tables = ["users", "orders", "products", "payments", "logs", "sessions", "settings"]
    table = random.choice(tables)
    
    if "query" in action:
        query_time = round(random.uniform(1, 500), 2)
        message = f"Database {action} on {table} table in {query_time}ms"
    elif "timeout" in action or "deadlock" in action:
        message = f"Database {action} on {table} table"
    else:
        message = f"Database {action} successfully"
    
    metadata = {
        "database": random.choice(["main", "analytics", "archive", "reporting"]),
        "server": f"db-{random.randint(1, 5)}.example.com"
    }
    
    if "query" in action:
        metadata["query_time_ms"] = query_time
        metadata["rows_affected"] = random.randint(0, 1000)
        metadata["query_type"] = random.choice(["SELECT", "INSERT", "UPDATE", "DELETE"])
    
    if "timeout" in action or "deadlock" in action:
        metadata["error_code"] = random.randint(1000, 9999)
    
    return level, message, "database-service", metadata

def generate_system_log():
    """Generate system-related log entries."""
    events = [
        "server started",
        "server stopped",
        "memory usage high",
        "disk space low",
        "CPU usage spike",
        "service restarted",
        "configuration updated",
        "cache cleared",
        "scheduled maintenance started",
        "backup initiated",
        "security update applied"
    ]
    
    event = random.choice(events)
    
    if "high" in event or "low" in event or "spike" in event:
        level = "warning"
    elif "stopped" in event:
        level = random.choice(["info", "warning"])
    else:
        level = get_weighted_log_level()
    
    server = f"srv-{random.randint(1, 10)}"
    message = f"System event: {event} on {server}"
    
    metadata = {
        "server": server,
        "environment": random.choice(["production", "staging", "development", "testing"]),
        "uptime": f"{random.randint(1, 30)} days, {random.randint(0, 23)} hours"
    }
    
    if "memory" in event:
        metadata["memory_usage"] = f"{random.randint(70, 95)}%"
        metadata["available_memory"] = f"{random.randint(100, 1000)} MB"
    
    if "disk" in event:
        metadata["disk_usage"] = f"{random.randint(80, 98)}%"
        metadata["available_space"] = f"{random.randint(1, 50)} GB"
    
    if "CPU" in event:
        metadata["cpu_usage"] = f"{random.randint(80, 100)}%"
        metadata["load_average"] = round(random.uniform(1.0, 10.0), 2)
    
    return level, message, random.choice(SOURCES), metadata

def generate_user_activity_log():
    """Generate user activity log entries."""
    actions = [
        "created account",
        "updated profile",
        "changed email",
        "uploaded file",
        "downloaded file",
        "deleted account",
        "subscribed to newsletter",
        "unsubscribed from newsletter",
        "shared content",
        "commented on post",
        "liked content"
    ]
    
    action = random.choice(actions)
    level = get_weighted_log_level()
    
    username = fake.user_name()
    message = f"User {username} {action}"
    
    metadata = {
        "user_id": str(uuid.uuid4())[:8],
        "username": username,
        "email": fake.email(),
        "ip_address": fake.ipv4(),
        "user_agent": fake.user_agent()
    }
    
    if "file" in action:
        metadata["file_name"] = fake.file_name()
        metadata["file_size"] = f"{random.randint(1, 100)} MB"
        metadata["file_type"] = random.choice(["image/jpeg", "application/pdf", "text/csv", "application/zip"])
    
    if "account" in action:
        metadata["account_age"] = f"{random.randint(1, 365)} days"
    
    return level, message, "user-service", metadata

def generate_random_log():
    """Generate a random log entry using one of the specialized generators."""
    generators = [
        generate_auth_log,
        generate_payment_log,
        generate_api_log,
        generate_database_log,
        generate_system_log,
        generate_user_activity_log
    ]
    
    # Choose a random generator with weighted probabilities
    weights = [0.2, 0.15, 0.25, 0.15, 0.1, 0.15]  # Must sum to 1.0
    generator = random.choices(generators, weights=weights, k=1)[0]
    
    return generator()

def generate_logs_for_timespan(days_back, count_per_day, interval=0):
    """Generate logs spread over a past timespan."""
    print(f"Generating {count_per_day} logs per day for the past {days_back} days...")
    
    # Get current time
    now = datetime.now()
    
    # For each day in the past
    for day in range(days_back, 0, -1):
        day_date = now - timedelta(days=day)
        print(f"\nGenerating logs for {day_date.strftime('%Y-%m-%d')}:")
        
        # Generate logs for this day
        for i in range(count_per_day):
            # Create a random time for this day
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            log_time = day_date.replace(hour=hour, minute=minute, second=second)
            
            # Generate the log
            level, message, source, metadata = generate_random_log()
            
            # Add timestamp to metadata
            if metadata is None:
                metadata = {}
            metadata["generated_at"] = log_time.isoformat()
            
            # Add the log
            add_log(level, message, source, metadata)
            
            # Sleep if interval is specified
            if interval > 0:
                time.sleep(interval)

def main():
    """Main function to generate logs."""
    parser = argparse.ArgumentParser(description='Generate realistic logs for PermaLog testing')
    parser.add_argument('--interval', type=float, default=0.5, help='Interval between logs in seconds (default: 0.5)')
    parser.add_argument('--count', type=int, default=0, help='Number of logs to generate (0 for infinite, default: 0)')
    parser.add_argument('--historical', action='store_true', help='Generate historical logs over past days')
    parser.add_argument('--days', type=int, default=7, help='Number of days back to generate logs for (default: 7)')
    parser.add_argument('--per-day', type=int, default=20, help='Number of logs per day for historical mode (default: 20)')
    args = parser.parse_args()
    
    print(f"PermaLog Realistic Test Data Generator")
    print(f"=====================================")
    
    # Check if the server is running
    try:
        response = requests.get(f"{API_URL}/logs", params={"limit": 1})
        if response.status_code == 200:
            print("Server is running!")
        else:
            print("Server returned an unexpected response.")
            exit(1)
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure PermaLog is running.")
        exit(1)
    
    # Historical mode
    if args.historical:
        generate_logs_for_timespan(args.days, args.per_day, args.interval)
        print(f"\nGenerated historical logs for the past {args.days} days ({args.days * args.per_day} logs total)")
        return
    
    # Real-time mode
    print(f"Generating logs every {args.interval} seconds")
    if args.count > 0:
        print(f"Will generate {args.count} logs")
    else:
        print(f"Will generate logs until interrupted (Ctrl+C)")
    print(f"Open http://localhost:5000/logs in your browser to see the logs")
    print(f"--------------------------------")
    
    count = 0
    try:
        while args.count == 0 or count < args.count:
            level, message, source, metadata = generate_random_log()
            add_log(level, message, source, metadata)
            count += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nLog generation interrupted by user")
    
    print(f"Generated {count} logs")
    print("Done!")

if __name__ == "__main__":
    main() 