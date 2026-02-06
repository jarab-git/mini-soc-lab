# SSH Brute Force Detection

## Log Source
/var/log/auth.log

## Tool
Splunk Enterprise

## Detection Logic
Multiple failed SSH authentication attempts from same source IP.

## SPL Query
index=main "Failed password"
| stats count by src, user
| where count > 5

## MITRE ATT&CK
Credential Access - T1110

## OUTCOME
Detected SSH brute-force attempts from Kali attacker machine.
