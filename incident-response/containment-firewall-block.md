## Incident Containment – Firewall Block

### Objective
Block malicious IP after detecting brute force attack.

### Attacker IP
192.168.50.X

### Action Taken
sudo ufw deny from 192.168.50.130

### Result
Connection attempts from attacker IP were blocked.

### Verification
- SSH connection from attacker failed
- UFW logs confirmed blocked traffic

### MITRE ATT&CK Mapping
T1078 – Valid Accounts
T1562 – Impair Defenses (attempted before block)

# containment-firewall-block-evidence folder #

![Firewall Rules](../screenshots/containment-firewall-block-evidence/Ubuntu%20activacion%20firewall.png)
![Brute Force Failed Attempt](../screenshots/containment-firewall-block-evidence/Kali%20attack%20intento%20sin%20exito.png)
![Splunk detection](../screenshots/containment-firewall-block-evidence/Splunk%20detección%20sin%20exito.png)
