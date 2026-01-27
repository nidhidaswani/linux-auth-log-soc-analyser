import re
from collections import Counter

#loading in the linux log file
logs = "auth.log"

# identifying common patterns such as: 
# reaching maximum number of authentications reached (password bruteforce)
# invalid user details - (details incorrect)
# checking if an IP opened a connection to SSH port 22 but did not send a vaild SHH identification (performing recon)
# 
attackPatterns = {
    "maxAuth": re.compile(r"maximum authentication attempts exceeded.*from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
    "invalidUser": re.compile(r"Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
    "noIdentity": re.compile(r"Did not receive identification string from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
}

#pattern to identify accepted users 
acceptedPatterns = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: "
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

#identifying common privilage escalations patterns: 
#using sudo commands 
#using su commands - successful switch to root accounts 
#checking if a session has been opened for a root user 
privilageEscPatterns = {
    "sudoPattern": re.compile(r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sudo:\s+(?P<actor>\S+)\s*:.*COMMAND=(?P<cmd>.+)$"), 
    "suPattern": re.compile(r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*su\[\d+\]:\s+Successful su for\s+(?P<target>\S+)\s+by\s+(?P<by>\S+)"),
    "rootSession": re.compile(r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*pam_unix\((?P<service>[^)]+)\): session opened for user root\b")
}

# Step 4: suspicious admin behaviour patterns
# installing tools, editing configs, restarting services, deleting registry/state
suspiciousCmdPatterns = {
    # Installing tools
    "install_tools": re.compile(r"\b(apt-get install|apt install|dpkg -i|curl -L -O|wget)\b"),
    # Editing configs / system files
    "edit_configs": re.compile(r"\b(vim|nano)\s+/etc/|tee\s+-a\s+/etc/"),
    # Restarting / controlling services
    "service_control": re.compile(r"\b(service|systemctl)\s+\S+\s+(start|stop|restart|reload)\b|update-rc\.d"),
    # Deleting registry / state (common in tampering)
    "delete_registry": re.compile(r"\brm\s+/var/lib/|rm\s+\S*registry\b"),
}

# counters per category + overall number of attacks
countsByAttType = {name: Counter() for name in attackPatterns}
overallAtt = Counter()

# counters per category + overall number of privilage escalations
countsByPrivType = {name: Counter() for name in privilageEscPatterns}
overallPriv = Counter()

# counters for suspicious commands 
countsBySuspType = {name: Counter() for name in suspiciousCmdPatterns}
overallSusp = Counter()

#list to store all accepted users 
accepted = []

#Privilage escalation users/attack lists 
sudoEvents = []
suEvents = []
rootSessions = []

# store exact suspicious events
suspiciousEvents = []  

# timeline of important events
timeline = []

#read through logs, deal with errors 
with open(logs, "r", errors="replace") as file:
    for line in file:

        # find a match for accepted users
        # store the timestamp/user ID/method/IP addresses 
        # add it to the stored list of accepted users 
        match = acceptedPatterns.search(line)
        if match: 
            accepted.append({
                "timestamp": match.group("timestamp"),
                "user": match.group("user"),
                "method": match.group("method"),
                "ip": match.group("ip")
            })

        #in each line see if there is a match for an attack pattern 
        # if there is note down the IP and add it to the count and overall     
        for name, pattern in attackPatterns.items():
            m = pattern.search(line)
            if m:
                ip = m.group("ip")
                countsByAttType[name][ip] += 1
                overallAtt[ip] += 1
                break  # stop after first match (one line = identified a signal)
        
        #checks through each line to see if there is privilage escalations being made 
        #classifies them by type and stores important information 
        for name, pattern in privilageEscPatterns.items():
            m = pattern.search(line)
            if m:
                countsByPrivType[name]["_matches_"] += 1
                overallPriv["_matches_"] += 1

                if name == "sudoPattern":
                    sudoEvents.append({
                        "timestamp": m.group("timestamp"),
                        "actor": m.group("actor"),
                        "cmd": m.group("cmd").strip()
                    })
                elif name == "suPattern":
                    suEvents.append({
                        "timestamp": m.group("timestamp"),
                        "by": m.group("by"),
                        "target": m.group("target")
                    })
                elif name == "rootSession":
                    rootSessions.append({
                        "timestamp": m.group("timestamp"),
                        "service": m.group("service")
                    })

                break  # one line should count once

        #suspicious admin behaviour detection
        # this is to try  classify sudo commands
        sudoLine = privilageEscPatterns["sudoPattern"].search(line)
        if sudoLine:
            cmd = sudoLine.group("cmd").strip()

            for sname, sp in suspiciousCmdPatterns.items():
                if sp.search(cmd):
                    # sudo lines don't include IP, so we count by actor here
                    actor = sudoLine.group("actor")
                    countsBySuspType[sname][actor] += 1
                    overallSusp[actor] += 1

                    suspiciousEvents.append({
                        "timestamp": sudoLine.group("timestamp"),
                        "type": sname,
                        "actor": actor,
                        "detail": cmd
                    })
                    break

        #scan raw lines to identify non-sudo events mentioning filebeat(log events)/packetbeat(network events)          
        for sname, sp in suspiciousCmdPatterns.items():
            if sp.search(line):
                countsBySuspType[sname]["_logline_"] += 1
                overallSusp["_logline_"] += 1
                suspiciousEvents.append({
                    "timestamp": line[:15],
                    "type": sname,
                    "actor": "_logline_",
                    "detail": line.strip()
                })
                break

        # Build a timeline of key events

        # check for successful login
        if match:
            timeline.append({
                "timestamp": match.group("timestamp"),
                "event": "LOGIN",
                "detail": f"{match.group('user')} from {match.group('ip')}"
            })

        # check any sudo commands 
        sudoLine = privilageEscPatterns["sudoPattern"].search(line)
        if sudoLine:
            timeline.append({
                "timestamp": sudoLine.group("timestamp"),
                "event": "SUDO",
                "detail": f"{sudoLine.group('actor')} ran: {sudoLine.group('cmd').strip()}"
            })

        # check for su events
        suLine = privilageEscPatterns["suPattern"].search(line)
        if suLine:
            timeline.append({
                "timestamp": suLine.group("timestamp"),
                "event": "SU",
                "detail": f"{suLine.group('by')} -> {suLine.group('target')}"
            })

        # check when root session opened
        rootLine = privilageEscPatterns["rootSession"].search(line)
        if rootLine:
            timeline.append({
                "timestamp": rootLine.group("timestamp"),
                "event": "ROOT_SESSION",
                "detail": f"session opened via {rootLine.group('service')}"
            })

        # check any suspicious commands
        for sname, sp in suspiciousCmdPatterns.items():
            if sp.search(line):
                timeline.append({
                    "timestamp": line[:15],
                    "event": sname.upper(),
                    "detail": line.strip()
                })
                break


#print statments
#step one 
print("\n=== Step 1: Brute-force / noisy IP detection ===")

print("\nTop IPs overall (across the 3 signals):")
for ip, c in overallAtt.most_common(5):
    print(f"  {ip}: {c}")

print("\nBreakdown by signal:")
for name, counter in countsByAttType.items():
    print(f"\n{name}:")
    for ip, c in counter.most_common(5):
        print(f"  {ip}: {c}")

#step two 
print("\n=== Step 2: Successful SSH logins (Accepted ...) ===")

unique_ips = sorted({a["ip"] for a in accepted})
unique_users = sorted({a["user"] for a in accepted})
unique_methods = sorted({a["method"] for a in accepted})

print("\nSummary:")
print(f"  Total successful logins: {len(accepted)}")
print(f"  Users: {', '.join(unique_users)}")
print(f"  Source IPs: {', '.join(unique_ips)}")
print(f"  Methods: {', '.join(unique_methods)}")

#step three 
print("\n=== Step 3: Privilege escalation indicators ===")
print(f"sudo events: {len(sudoEvents)}")
print(f"su events: {len(suEvents)}")
print(f"root sessions opened: {len(rootSessions)}")

#step four
print("\n=== Step 4: Suspicious admin behaviour ===")

print("\nTop actors overall (across suspicious behaviours):")
for actor, c in overallSusp.most_common(5):
    print(f"  {actor}: {c}")

print("\nBreakdown by suspicious behaviour type:")
for name, counter in countsBySuspType.items():
    print(f"\n{name}:")
    for actor, c in counter.most_common(5):
        print(f"  {actor}: {c}")

print("\nExamples (first 10):")
for event in suspiciousEvents[:10]:
    print(f"  {event['timestamp']} | {event['type']} | actor={event['actor']} | {event['detail']}")

#step five
print("\n=== Step 5: Incident Timeline ===")

for t in timeline[:30]:
    print(f"{t['timestamp']} | {t['event']} | {t['detail']}")
