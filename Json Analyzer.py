#!/usr/bin/env python3
# Cowrie JSON Analyzer — generates detailed analysis report

import json
import os
from datetime import datetime
from collections import Counter, defaultdict

LOG_FILE   = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_DIR = "/home/cowrie/HoneypotLogs"

def analyze():
    events = []
    with open(LOG_FILE) as f:
        for line in f:
            try: events.append(json.loads(line))
            except: pass

    logins = [e for e in events if e.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]]
    cmds   = [e for e in events if e.get("eventid") == "cowrie.command.input"]

    ip_counter    = Counter(e.get("src_ip") for e in logins)
    user_counter  = Counter(e.get("username") for e in logins)
    pass_counter  = Counter(e.get("password") for e in logins)
    cmd_counter   = Counter(e.get("input") for e in cmds)

    report = {
        "generated": str(datetime.now()),
        "totals": {
            "unique_ips": len(ip_counter),
            "total_login_attempts": len(logins),
            "failed_logins": sum(1 for e in logins if "failed" in e["eventid"]),
            "successful_logins": sum(1 for e in logins if "success" in e["eventid"]),
            "total_commands": len(cmds)
        },
        "top_attacking_ips": ip_counter.most_common(10),
        "top_usernames": user_counter.most_common(10),
        "top_passwords": pass_counter.most_common(10),
        "top_commands": cmd_counter.most_common(10)
    }

    out = os.path.join(OUTPUT_DIR, "analysis_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=4)

    # Print to terminal
    print("\n====== COWRIE ATTACK ANALYSIS ======")
    print(f"Unique IPs        : {report['totals']['unique_ips']}")
    print(f"Total Attempts    : {report['totals']['total_login_attempts']}")
    print(f"Failed            : {report['totals']['failed_logins']}")
    print(f"Successful        : {report['totals']['successful_logins']}")
    print(f"Commands Run      : {report['totals']['total_commands']}")

    print("\n--- Top 5 Attacking IPs ---")
    for ip, n in ip_counter.most_common(5):
        print(f"  {ip:<20} {n} attempts")

    print("\n--- Top 5 Usernames Tried ---")
    for u, n in user_counter.most_common(5):
        print(f"  {u:<20} {n} times")

    print("\n--- Top 5 Passwords Tried ---")
    for p, n in pass_counter.most_common(5):
        print(f"  {p:<20} {n} times")

    print("\n--- Top 5 Commands Run ---")
    for c, n in cmd_counter.most_common(5):
        print(f"  {c:<30} {n} times")

    print(f"\n[✓] Full report saved → {out}")

if __name__ == "__main__":
    analyze()