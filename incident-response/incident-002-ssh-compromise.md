# Incident Report – SSH Brute Force Leading to Successful Login #
# 1.Executive Summary
A brute-force attack was detected against the Ubuntu host (192.168.50.129).
Multiple failed SSH authentication attempts were observed from the attacker machine (Kali Linux), followed by a successful login using valid credentials.
The activity was detected through Splunk SIEM using authentication logs from /var/log/auth.log.

# 2. Environment
SIEM: Splunk Enterprise 8.2.6
Target Host: Ubuntu (192.168.50.129)
Attacker Host: Kali Linux
Log Source: /var/log/auth.log
Index: main

# 3. Timeline of Events
Time	Event
T1	    Multiple failed SSH login attempts detected
T2	    Alert triggered in Splunk
T3	    Successful SSH login observed
T4	    Interactive session opened

# 4. Detection Logic
## Brute Force Detection
index=main "Failed password"
| stats count by src, user
| where count >= 5

## Successfull Login Detection
index=main "Accepted password"

## Success After Multiple Failures
index=main ("Failed password" OR "Accepted password")
| stats count(eval(searchmatch("Failed password"))) as failed_attempts
        count(eval(searchmatch("Accepted password"))) as successful_logins
        by src, user
| where failed_attempts >= 3 AND successful_logins >= 1

# 5. MITRE ATT&CK Mapping
T1110 – Brute Force
T1078 – Valid Accounts
T1021 – Remote Services (SSH)

# 6. Impact Assessment
Successful authentication achieved
No privilege escalation detected
No persistence mechanisms observed

# 7. Response Actions
Alert generated in Splunk
Source IP identified
Recommended mitigation:
        Enable fail2ban
        Enforce strong passwords
        Disable password-based SSH authentication
        Implement firewall blocking

# 8. Lessons Learned
SIEM detection effectively identified brute-force attempts.
Correlating failed and successful login attempts increases detection accuracy.
Monitoring authentication logs is critical for early compromise detection.

# incident-002-ssh-compromise-evidence folder #

![Brute Force Attempt](../screenshots/incident-002-ssh-compromise-evidence/Kali%20attack%20brute%20force%20attempt.png)
![Splunk Detection](../screenshots/incident-002-ssh-compromise-evidence/Ubuntu%20Splunk%20detection.png)

## Post-Compromise Activity

After successful authentication, a session was opened for user jara.

Relevant log events:
- "Accepted password"
- "session opened"
- "session closed"

This confirms interactive access to the system.

# MITE ATT&CK Mapping
T1078 – Valid Accounts
T1021 – Remote Services

## Privilege Escalation Attempt

After gaining access, the user executed sudo commands.

Logs show:
- sudo activity associated with user jara
- Command execution attempts under elevated privileges

This indicates potential privilege escalation behavior.
