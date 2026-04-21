#!/usr/bin/env python3
# ============================================================
# Log Organizer — Creates IP-based folder structure
# Run: python3 log_organizer.py
# ============================================================

import json
import os
import shutil
from datetime import datetime
from collections import defaultdict

# ── CONFIG ───────────────────────────────────────────────────
COWRIE_JSON  = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
COWRIE_LOG   = "/home/cowrie/cowrie/var/log/cowrie/cowrie.log"
OUTPUT_DIR   = "/home/cowrie/HoneypotLogs"
DESKTOP_DIR  = "/home/aviral/Desktop/HoneypotLogs"
# ─────────────────────────────────────────────────────────────

def parse_all_logs():
    data = defaultdict(lambda: {
        "login_attempts": [],
        "commands": [],
        "sessions": [],
        "files_downloaded": [],
        "tunnels": []
    })

    if not os.path.exists(COWRIE_JSON):
        print(f"[!] JSON log not found: {COWRIE_JSON}")
        return data

    with open(COWRIE_JSON, "r") as f:
        for line in f:
            try:
                e   = json.loads(line.strip())
                ip  = e.get("src_ip", "unknown")
                evt = e.get("eventid", "")
                ts  = e.get("timestamp", "")

                if evt in ["cowrie.login.failed", "cowrie.login.success"]:
                    data[ip]["login_attempts"].append({
                        "time": ts,
                        "user": e.get("username", ""),
                        "pass": e.get("password", ""),
                        "status": "SUCCESS" if "success" in evt else "FAILED",
                        "session": e.get("session", "")
                    })

                elif evt == "cowrie.command.input":
                    data[ip]["commands"].append({
                        "time": ts,
                        "command": e.get("input", ""),
                        "session": e.get("session", "")
                    })

                elif evt == "cowrie.session.connect":
                    data[ip]["sessions"].append({
                        "time": ts,
                        "port": e.get("src_port", ""),
                        "protocol": e.get("protocol", "ssh"),
                        "session": e.get("session", "")
                    })

                elif evt == "cowrie.session.file_download":
                    data[ip]["files_downloaded"].append({
                        "time": ts,
                        "url": e.get("url", ""),
                        "filename": e.get("filename", ""),
                        "shasum": e.get("shasum", "")
                    })

            except (json.JSONDecodeError, KeyError):
                continue

    return data

def save_ip_logs(ip, d, base_dir):
    ip_dir = os.path.join(base_dir, ip)
    os.makedirs(ip_dir, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── login_attempts.txt ───────────────────────────────────
    with open(os.path.join(ip_dir, "login_attempts.txt"), "w") as f:
        total   = len(d["login_attempts"])
        failed  = sum(1 for x in d["login_attempts"] if x["status"] == "FAILED")
        success = total - failed
        f.write(f"LOGIN ATTEMPTS FROM IP: {ip}\n")
        f.write(f"Generated : {now}\n")
        f.write("="*55 + "\n\n")
        f.write(f"Total Attempts : {total}\n")
        f.write(f"Failed         : {failed}\n")
        f.write(f"Successful     : {success}\n\n")
        f.write("-"*55 + "\n")
        for a in d["login_attempts"]:
            ts = a["time"][:19].replace("T", " ")
            f.write(f"[{ts}] {a['status']:7s} | user: {a['user']:15s} | pass: {a['pass']}\n")

    # ── commands_typed.txt ───────────────────────────────────
    with open(os.path.join(ip_dir, "commands_typed.txt"), "w") as f:
        f.write(f"COMMANDS TYPED BY: {ip}\n")
        f.write(f"Generated: {now}\n")
        f.write("="*55 + "\n\n")
        if d["commands"]:
            for c in d["commands"]:
                ts = c["time"][:19].replace("T", " ")
                f.write(f"[{ts}]  $ {c['command']}\n")
        else:
            f.write("No commands recorded for this IP.\n")

    # ── session_details.json ─────────────────────────────────
    with open(os.path.join(ip_dir, "session_details.json"), "w") as f:
        json.dump({
            "ip": ip,
            "generated": now,
            "stats": {
                "total_login_attempts": len(d["login_attempts"]),
                "failed_logins": sum(1 for x in d["login_attempts"] if x["status"]=="FAILED"),
                "successful_logins": sum(1 for x in d["login_attempts"] if x["status"]=="SUCCESS"),
                "commands_run": len(d["commands"]),
                "sessions": len(d["sessions"]),
                "files_downloaded": len(d["files_downloaded"])
            },
            "login_attempts": d["login_attempts"],
            "commands": d["commands"],
            "sessions": d["sessions"],
            "files_downloaded": d["files_downloaded"]
        }, f, indent=4)

    print(f"  [+] {ip} → {len(d['login_attempts'])} attempts, {len(d['commands'])} cmds")

def write_summary(data, base_dir):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_attempts = sum(len(v["login_attempts"]) for v in data.values())
    total_success  = sum(sum(1 for x in v["login_attempts"] if x["status"]=="SUCCESS") for v in data.values())
    total_cmds     = sum(len(v["commands"]) for v in data.values())

    with open(os.path.join(base_dir, "summary_report.txt"), "w") as f:
        f.write("="*60 + "\n")
        f.write("    COWRIE HONEYPOT — ATTACK SUMMARY REPORT\n")
        f.write(f"    Generated: {now}\n")
        f.write("="*60 + "\n\n")
        f.write(f"Unique Attackers   : {len(data)}\n")
        f.write(f"Total Login Tries  : {total_attempts}\n")
        f.write(f"Successful Logins  : {total_success}\n")
        f.write(f"Total Commands Run : {total_cmds}\n\n")
        f.write(f"{'IP':<20} {'ATTEMPTS':>10} {'SUCCESS':>8} {'CMDS':>6}\n")
        f.write("-"*50 + "\n")
        for ip, d in sorted(data.items()):
            s = sum(1 for x in d["login_attempts"] if x["status"]=="SUCCESS")
            f.write(f"{ip:<20} {len(d['login_attempts']):>10} {s:>8} {len(d['commands']):>6}\n")

    print(f"  [+] Summary → {base_dir}/summary_report.txt")

def main():
    print("\n[*] Cowrie Log Organizer Starting...")
    print(f"[*] Source : {COWRIE_JSON}")
    print(f"[*] Output : {OUTPUT_DIR}\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    data = parse_all_logs()

    if not data:
        print("[!] No data found. Run some attacks first!")
        return

    print(f"[+] Found {len(data)} unique attacker IPs")
    for ip, d in data.items():
        save_ip_logs(ip, d, OUTPUT_DIR)

    write_summary(data, OUTPUT_DIR)

    # Sync to desktop
    if os.path.exists("/home/aviral/Desktop"):
        os.makedirs(DESKTOP_DIR, exist_ok=True)
        shutil.copytree(OUTPUT_DIR, DESKTOP_DIR, dirs_exist_ok=True)
        print(f"  [+] Synced to Desktop → {DESKTOP_DIR}")

    print("\n[✓] All done!")

if __name__ == "__main__":
    main()