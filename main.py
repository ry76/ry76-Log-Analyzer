import re
import json
from collections import defaultdict
from datetime import datetime
import requests

def parse_log_line(line):
    #Extracts timestamp, username, IP, and status from a log line.
    pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (?P<username>\S+) - (?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<status>\S+)'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

def get_ip_location(ip):
    #Fetches geolocation of an IP address using a free API.
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return f"{data.get('country', 'Unknown')}, {data.get('city', 'Unknown')}"
    except Exception:
        return "Unknown Location"

def detect_suspicious_activity(log_lines):
    #Detects multiple failed attempts, geo-location changes, and rate-limiting issues.
    failed_attempts = defaultdict(list)
    last_login_location = {}
    login_attempts = defaultdict(list)
    alerts = []

    for line in log_lines:
        log_data = parse_log_line(line)
        if not log_data:
            continue

        timestamp, username, ip, status = log_data['timestamp'], log_data['username'], log_data['ip'], log_data['status']
        time_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        location = "Unknown Location"  # Ensure location is always initialized

        # Track failed login attempts
        if status == "FAILED":
            failed_attempts[username].append(time_obj)
            if len(failed_attempts[username]) >= 3:
                alert_msg = f"[ALERT] Multiple failed login attempts for user {username}"
                print(alert_msg)
                alerts.append(alert_msg)
        else:
            failed_attempts[username] = []  # Reset on successful login
            location = get_ip_location(ip)
            if username in last_login_location and last_login_location[username] != ip:
                alert_msg = f"[ALERT] {username} logged in from a different IP: {ip} ({location})"
                print(alert_msg)
                alerts.append(alert_msg)
            last_login_location[username] = ip

        # Detect rate-limiting issues
        login_attempts[ip].append(time_obj)
        if len(login_attempts[ip]) >= 5:
            time_diff = (login_attempts[ip][-1] - login_attempts[ip][0]).total_seconds()
            if time_diff < 30:
                alert_msg = f"[ALERT] Possible brute-force attack from {ip} ({location})"
                print(alert_msg)
                alerts.append(alert_msg)
            login_attempts[ip] = login_attempts[ip][-4:]  # Keep only last 4 entries

    # Save alerts to a log file
    with open("alerts.log", "a") as log_file:
        for alert in alerts:
            log_file.write(alert + "\n")

if __name__ == "__main__":
    print("Enter log data (leave blank to finish):")
    user_logs = []
    while True:
        log_entry = input()
        if not log_entry:
            break
        user_logs.append(log_entry)

    print("\nAnalyzing logs...\n")
    detect_suspicious_activity(user_logs)
