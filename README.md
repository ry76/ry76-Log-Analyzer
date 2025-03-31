# ry76-Log-Analyzer

My Simple Log Analyzer Project in Python which analyzes log data and detect suspicious activities related to user logins.

For Example:

- Multiple Failed Login Attempts: It identifies users who have failed to log in multiple times, which could indicate a brute-force attack.

- Geolocation Changes: It checks if a user logs in from a different IP address than the last known one and reports the change, including geolocation information.

- Rate-Limiting (Brute-Force Attack): It flags IP addresses that attempt multiple logins in a short time frame (e.g., 5 attempts within 30 seconds), suggesting a potential brute-force attack.

- Logging Alerts: It saves any suspicious activity alerts to a log file (alerts.log) for future review and displays them in the console for immediate attention.

The code helps monitor and secure systems by identifying potential unauthorized access attempts or malicious behavior.
_________________________________________________________________________________________________________________________________________________________________________
Example of deployment of program:

1. Input Following Logs when prompted:
(example case as shown below:)

2025-03-30 13:00:00 - user1 - 10.0.0.1 - FAILED‎ 
2025-03-30 13:00:05 - user1 - 10.0.0.1 - FAILED‎ 
2025-03-30 13:00:10 - user1 - 10.0.0.1 - FAILED‎ 
2025-03-30 13:00:15 - user1 - 10.0.0.1 - SUCCESS‎ 
2025-03-30 13:00:20 - user1 - 10.0.1.2 - SUCCESS‎ 
2025-03-30 13:00:25 - hacker - 192.168.2.5 - FAILED‎ 
2025-03-30 13:00:27 - hacker - 192.168.2.5 - FAILED‎ 
2025-03-30 13:00:29 - hacker - 192.168.2.5 - FAILED‎ 
2025-03-30 13:00:31 - hacker - 192.168.2.5 - FAILED‎ 
2025-03-30 13:00:33 - hacker - 192.168.2.5 - FAILED‎ 


3. Output as shown:
Analyzing logs...


[ALERT] Multiple failed login attempts for user user1
[ALERT] user1 logged in from a different IP: 10.0.1.2 (Unknown Location)
[ALERT] Multiple failed login attempts for user hacker
[ALERT] Possible brute-force attack from 192.168.2.5 (Unknown Location)

Alerts saved to alerts.log


3. In alerts.log file:
   
[ALERT] Multiple failed login attempts for user user1
[ALERT] user1 logged in from a different IP: 10.0.1.2 (Unknown Location)
[ALERT] Multiple failed login attempts for user hacker
[ALERT] Possible brute-force attack from 192.168.2.5 (Unknown Location)

______________________________________________________________________________________________________________________________________________________________________________
Summarised Explanation:
- User "user1" had multiple failed login attempts → Possible attack.
- User "user1" logged in successfully but from a different IP (10.0.1.2) → Possible account compromise.
- User "hacker" attempted five failed logins in quick succession → Possible brute-force attack.
______________________________________________________________________________________________________________________________________________________________________________
