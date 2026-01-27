# Linux Auth Log Incident Analysis (SSH)

A Python tool that analyses Linux `auth.log` data to detect SSH brute-force activity, successful logins, privilege escalation, suspicious admin behaviour, and reconstructs a timeline of key events.

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

## How to run
```bash
python3 analyser.py > report.txt
