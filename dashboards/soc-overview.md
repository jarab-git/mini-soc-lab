## DASHBOARD SOC OVERVIEW
# OBJECTIVE
This dashboard provides visibility into SSH authentication activity on the monitored Ubuntu host.
It allows detection of brute-force attempts, identification of attacker IPs, targeted accounts, and verification of successful logins.

# LOG SOURCE
/var/log/auth.log
ingested into Splunk (index=main)
# Mapped MITRE Technique
    T1110 – Brute Force
    T1078 – Valid Accounts (if successful login detected)

## PANEL 1. SSH Failed Logins Over Time
## Purpouse: Identify when suspicious authentication activity started and determine if the attack is ongoing.
# SPL Query:
index=main "Failed password"
| timechart count
# Analyst use case: Detect spikes in failed logins | Identify attack windows | Correlate with other security events

## PANEL 2. Top Attacking IPs
## Purpouse: Identify source IP addresses generating the highest number of failed authentication attempts.
# SPL Query:
index=main "Failed password"
| stats count by src
| sort - count
# Analyst use case: Identify attacker infrastructure | Support firewall blocking decisions | Detect repeated attempts from same source

## PANEL 3. Targeted Users
## Purpouse: Identify accounts being targeted in brute-force attempts.
# SPL Query:
index=main "Failed password"
| stats count by user
| sort - count
# Analyst use case: Detect high-value accounts under attack | Identify attempts against non-existent users | Support password reset decisions

## PANEL 4. Successful vs Failed Logins
## Purpouse: Determine whether brute-force attempts resulted in successful authentication.
# SPL Query:
index=main ("Failed password" OR "Accepted password")
| eval status=if(searchmatch("Failed password"),"Failed","Success")
| stats count by status
# Analyst use case: Identify account compromise | Escalate incident severity | Trigger containment procedures
