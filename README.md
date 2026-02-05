# Linux Auth Log Incident Analysis (SSH)

This project analyses Linux auth.log files to reconstruct attacker behaviour during SSH incidents.
It detects brute-force activity, successful logins, privilege escalation, suspicious admin actions, and produces a timeline and risk-scored narrative per IP.

The goal of this project was not just to parse logs, but to model how a security engineer can infer attacker progression from raw system events.


## What it detects
1. **Brute force / noisy IPs**
   - `maximum authentication attempts exceeded`
   - `Invalid user`
   - `Did not receive identification string`

2. **Successful SSH logins**
   - `Accepted <method> for <user> from <ip>`

3. **Privilege escalation indicators**
   - `sudo:` commands
   - `su:` successful switch user
   - `session opened for user root`

4. **Suspicious admin behaviour**
   - Installing tools (apt/dpkg/curl/wget)
   - Editing configs (`/etc/...`)
   - Service control (service/systemctl)
   - Deleting registry/state files

5. **Incident timeline**
   - Prints key events (login, sudo, su, root sessions, suspicious actions) in log order.

6. **Summary for Each IP Address**
- Prints out a summary of activies for each IP address in order of most to least activity 

7. **Assigning a Risk Score to Each IP Address**
- Assigns a score and risk level to each IP address to asses potential risk/threat levels 

## Repository Structure 
data/auth.log 
src/analyser.py 
src/script_analyser.py 
report.txt

## Why Two Versions?
**analyser.py - Programming Style**
This verison was written to clearly demonstrate the logic behind: 
- Parsing logs 
- Detecting patterns 
- Correlating events 
- Building an incident timeline 
- Reconstructing attacker behaviour

It is written in a readable, step-by-step way to show how the detection thinking works. 

**How to run**
From the project root: 
```bash
python3 src/analyser.py > report.txt
```
**script_analyser.py - Script/Tool Style**
This verison refactors the same logic into a proper command-line tool
- Accepts input log files as arguments 
- Allows configurable output size 
- Can export structures JSON for integration into other tools 
- Uses exit codes and argument parsing liek a real CLI utility 

This is a more tangible script which can be dropped into an existing SOC pipeline or tooling 

**How to run**
From the project root 
```bash 
python3 src/script_analyser.py -i data/auth.log 
```

Options: 
```bash 
# Analyse the sample log
python3 src/script_analyser.py -i data/auth.log

# Analyse any system auth.log
python3 src/script_analyser.py -i /var/log/auth.log

# Show top results
python3 src/script_analyser.py -i data/auth.log --top 10

# Expand timeline view to max 50 events 
python3 src/script_analyser.py -i data/auth.log --timeline-limit 50

# Export full results for tooling
python3 src/script_analyser.py -i data/auth.log --json-out report.json

# Example of combination of options
python3 src/script_analyser.py -i data/auth.log --top 15 --timeline-limit 100 --json-out full_report.json

```

## What this Demonstrates 
**This project shows:**
- Log passing with regex 
- Detection engineering thinking 
- Correlation of events across time 
- Threat modellling from system logs 
- Writing both clear programs and resuable scripts 
- Producing outputs suitable for humans and tooling 

## Example Output 
See ```bash report.txt ``` and ```bash report.json``` for a sample output 

## Key Insight 
A key improvement during development was recognising that:

Privileged actions (sudo, root sessions) are only suspicious when preceded by attack signals such as brute-force or reconnaissance.

This mirrors how real SOC detection logic avoids false positives from normal administrative behaviour.
