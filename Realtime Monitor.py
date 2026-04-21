#!/usr/bin/env python3
# ============================================================
# Cowrie Real-time Monitor — works with tail -f cowrie.log
# Run: python3 realtime_monitor.py
# ============================================================

import json
import time
import os
import sys
from datetime import datetime
from collections import defaultdict

# ── CONFIG ───────────────────────────────────────────────────
LOG_FILE   = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_DIR = "/home/cowrie/HoneypotLogs"
REFRESH    = 1  # seconds between checks
# ─────────────────────────────────────────────────────────────

# Terminal colors
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
D  = "\033[2m"    # dim
X  = "\033[0m"    # reset

stats = defaultdict(lambda: {
    "failed": 0,
    "success": 0,
    "commands": 0,
    "sessions": 0
})

def print_banner():
    print(f"""
{G}╔══════════════════════════════════════════════════════════╗
║          COWRIE HONEYPOT — REAL-TIME MONITOR             ║
║          Watching: {LOG_FILE[-30:]:<38}║
╚══════════════════════════════════════════════════════════╝{X}""")
    print(f"{D}  Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}\n")

def format_event(entry):
    event     = entry.get("eventid", "")
    ip        = entry.get("src_ip", "unknown")
    ts        = entry.get("timestamp", "")[:19].replace("T", " ")
    username  = entry.get("username", "")
    password  = entry.get("password", "")
    command   = entry.get("input", "")
    session   = entry.get("session", "")[:8]

    if event == "cowrie.login.failed":
        stats[ip]["failed"] += 1
        return (
            f"{D}[{ts}]{X} {R}✗ FAIL    {X}"
            f"{C}{ip:<18}{X} "
            f"user={Y}{username:<12}{X} "
            f"pass={Y}{password}{X}"
        )

    elif event == "cowrie.login.success":
        stats[ip]["success"] += 1
        return (
            f"{D}[{ts}]{X} {G}✓ SUCCESS {X}"
            f"{C}{ip:<18}{X} "
            f"user={G}{username:<12}{X} "
            f"pass={G}{password}{X} 🚨"
        )

    elif event == "cowrie.command.input":
        stats[ip]["commands"] += 1
        return (
            f"{D}[{ts}]{X} {M}$ CMD     {X}"
            f"{C}{ip:<18}{X} "
            f"{W}$ {command}{X}"
        )

    elif event == "cowrie.session.connect":
        stats[ip]["sessions"] += 1
        port = entry.get("src_port", "")
        return (
            f"{D}[{ts}]{X} {B}⟶ CONNECT {X}"
            f"{C}{ip:<18}{X} "
            f"port={port} session={D}{session}{X}"
        )

    elif event == "cowrie.session.closed":
        duration = entry.get("duration", 0)
        return (
            f"{D}[{ts}]{X} {D}✕ CLOSED  {X}"
            f"{C}{ip:<18}{X} "
            f"duration={duration:.1f}s"
        )

    elif event == "cowrie.direct-tcpip.request":
        return (
            f"{D}[{ts}]{X} {Y}⇒ TUNNEL  {X}"
            f"{C}{ip:<18}{X} TCP tunnel attempt"
        )

    return None

def print_stats():
    if not stats:
        return
    print(f"\n{D}{'─'*60}{X}")
    print(f"{W}  LIVE STATS — {datetime.now().strftime('%H:%M:%S')}{X}")
    print(f"{D}  {'IP':<18} {'FAILED':>8} {'SUCCESS':>8} {'CMDS':>6} {'SESS':>6}{X}")
    print(f"{D}  {'─'*18} {'─'*8} {'─'*8} {'─'*6} {'─'*6}{X}")
    for ip, s in sorted(stats.items()):
        print(
            f"  {C}{ip:<18}{X}"
            f" {R}{s['failed']:>8}{X}"
            f" {G}{s['success']:>8}{X}"
            f" {M}{s['commands']:>6}{X}"
            f" {B}{s['sessions']:>6}{X}"
        )
    print(f"{D}{'─'*60}{X}\n")

def follow_log():
    print_banner()
    print(f"{G}[*] Monitoring started. Waiting for attacks...{X}\n")

    last_stat_time = time.time()
    last_size = 0

    while True:
        try:
            current_size = os.path.getsize(LOG_FILE)
            if current_size > last_size:
                with open(LOG_FILE, "r") as f:
                    f.seek(last_size)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            msg = format_event(entry)
                            if msg:
                                print(msg)
                                sys.stdout.flush()
                        except json.JSONDecodeError:
                            pass
                last_size = current_size

            # Print stats every 30 seconds
            if time.time() - last_stat_time > 30:
                print_stats()
                last_stat_time = time.time()

            time.sleep(REFRESH)

        except KeyboardInterrupt:
            print(f"\n\n{Y}[!] Monitor stopped.{X}")
            print_stats()
            break
        except FileNotFoundError:
            print(f"{R}[!] Log file not found. Is Cowrie running?{X}")
            time.sleep(5)

if __name__ == "__main__":
    follow_log()