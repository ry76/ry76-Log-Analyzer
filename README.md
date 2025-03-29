# ry76-Log-Analyzer

Simple Log Analyzer Project in Python which analyzes log data and detect suspicious activities related to user logins.

For Example:

- Multiple Failed Login Attempts: It identifies users who have failed to log in multiple times, which could indicate a brute-force attack.

- Geolocation Changes: It checks if a user logs in from a different IP address than the last known one and reports the change, including geolocation information.

- Rate-Limiting (Brute-Force Attack): It flags IP addresses that attempt multiple logins in a short time frame (e.g., 5 attempts within 30 seconds), suggesting a potential brute-force attack.

- Logging Alerts: It saves any suspicious activity alerts to a log file (alerts.log) for future review and displays them in the console for immediate attention.

The code helps monitor and secure systems by identifying potential unauthorized access attempts or malicious behavior.
