#!/usr/bin/env python3
# ================================================================
# Cowrie SOC Dashboard — Backend API Server
# Reads cowrie.json and serves all frontend API endpoints
# Run: python3 server.py
# ================================================================

from flask import Flask, jsonify
from flask_cors import CORS
import json, os
from collections import Counter, defaultdict
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow all origins (frontend can be on any machine)

# ── CONFIG ───────────────────────────────────────────────────────
LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
# ─────────────────────────────────────────────────────────────────

# Command intent patterns
COMMAND_PATTERNS = {
    "RECON":     ["uname","id","whoami","hostname","ifconfig","ip addr","cat /proc","lscpu","lsb_release","arch"],
    "SYS-DISCO": ["cat /etc","df -h","ps aux","netstat","ls -la","find /","mount","who ","w ","last ","uptime"],
    "MALWARE":   ["wget","curl","ftp","tftp","nc -e","python -c","perl -e","bash -i","chmod +x","./"],
    "PERSIST":   ["crontab","bashrc","chpasswd","authorized_keys",".profile","rc.local","init.d","systemctl enable"],
    "PRIVESC":   ["sudo","chmod 777","chmod 4755","su root","passwd","visudo","pkexec"],
    "LATERAL":   ["ssh-keygen","known_hosts",".ssh","scp ","rsync "],
    "CLEANUP":   ["history -c","rm -rf /tmp","unset HIST","shred",">/dev/null"],
}

def classify_command(cmd):
    cmd_lower = cmd.lower()
    for intent, keywords in COMMAND_PATTERNS.items():
        if any(k in cmd_lower for k in keywords):
            return intent
    return "OTHER"

def calculate_aps(login_attempts, command_count, duration_secs):
    return login_attempts + (command_count * 2) + int(duration_secs / 60)

def classify_aps(aps):
    if aps > 70: return "PERSISTENT"
    if aps > 40: return "BRUTE-FORCE"
    if aps > 15: return "AUTO-SCAN"
    return "SCANNER"

def load_and_parse():
    """Load cowrie.json and parse into structured data."""
    events = []
    if not os.path.exists(LOG_FILE):
        return [], {}, {}

    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e: events.append(e)
            except: pass

    # Group by IP
    by_ip = defaultdict(lambda: {
        "logins": [], "commands": [], "sessions": [], "downloads": []
    })

    # Group by session ID
    by_session = defaultdict(lambda: {
        "events": [], "ip": "", "start": None, "end": None
    })

    for e in events:
        ip   = e.get("src_ip", "unknown")
        evt  = e.get("eventid", "")
        sess = e.get("session", "")
        ts   = e.get("timestamp", "")

        if ip and ip != "unknown":
            if evt in ["cowrie.login.failed", "cowrie.login.success"]:
                by_ip[ip]["logins"].append(e)
            elif evt == "cowrie.command.input":
                by_ip[ip]["commands"].append(e)
            elif evt == "cowrie.session.connect":
                by_ip[ip]["sessions"].append(e)
            elif evt == "cowrie.session.file_download":
                by_ip[ip]["downloads"].append(e)

        if sess:
            by_session[sess]["events"].append(e)
            if ip: by_session[sess]["ip"] = ip
            if ts:
                if not by_session[sess]["start"] or ts < by_session[sess]["start"]:
                    by_session[sess]["start"] = ts
                if not by_session[sess]["end"] or ts > by_session[sess]["end"]:
                    by_session[sess]["end"] = ts

    return events, by_ip, by_session

def get_ip_durations(by_session):
    """Calculate total connection duration per IP."""
    ip_duration = defaultdict(float)
    for sid, s in by_session.items():
        if s["start"] and s["end"] and s["ip"]:
            try:
                start = datetime.fromisoformat(s["start"].replace("Z", "+00:00"))
                end   = datetime.fromisoformat(s["end"].replace("Z", "+00:00"))
                ip_duration[s["ip"]] += (end - start).total_seconds()
            except: pass
    return ip_duration

# ── ENDPOINTS ────────────────────────────────────────────────────

@app.route('/api/overview/stats')
def overview_stats():
    events, by_ip, by_session = load_and_parse()
    logins   = [e for e in events if e.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]]
    commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    sessions = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    return jsonify({
        "total_attempts": len(logins),
        "unique_ips":     len(by_ip),
        "commands":       len(commands),
        "sessions":       len(sessions)
    })

@app.route('/api/timeline/24h')
def timeline_24h():
    events, _, _ = load_and_parse()
    logins = [e for e in events if e.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]]
    hourly = [0] * 24
    for e in logins:
        ts = e.get("timestamp", "")
        if ts:
            try: hourly[int(ts[11:13])] += 1
            except: pass
    return jsonify({
        "labels": [str(h).zfill(2) for h in range(24)],
        "data":   hourly
    })

@app.route('/api/feed/recent')
def feed_recent():
    events, _, _ = load_and_parse()
    relevant = [e for e in events if e.get("eventid") in [
        "cowrie.login.failed", "cowrie.login.success",
        "cowrie.command.input", "cowrie.session.connect",
        "cowrie.session.file_download"
    ]]
    recent = relevant[-50:][::-1]
    badge_map = {
        "RECON":"bb","MALWARE":"br","PERSIST":"br",
        "SYS-DISCO":"bb","PRIVESC":"ba","LATERAL":"ba","OTHER":"bm","CLEANUP":"bm"
    }
    rows = []
    for e in recent:
        evt  = e.get("eventid", "")
        ip   = e.get("src_ip", "unknown")
        ts   = e.get("timestamp", "")
        tstr = ts[11:16] if ts else "--:--"
        if evt == "cowrie.login.failed":
            rows.append({"time": tstr, "ip": ip, "event": f"LOGIN FAIL {e.get('username','')}:{e.get('password','')}", "badge": "BRUTE", "cls": "bg"})
        elif evt == "cowrie.login.success":
            rows.append({"time": tstr, "ip": ip, "event": f"LOGIN SUCCESS {e.get('username','')}:{e.get('password','')}", "badge": "CRITICAL", "cls": "br"})
        elif evt == "cowrie.command.input":
            intent = classify_command(e.get("input", ""))
            rows.append({"time": tstr, "ip": ip, "event": f"CMD: {e.get('input','')[:55]}", "badge": intent, "cls": badge_map.get(intent, "bm")})
        elif evt == "cowrie.session.connect":
            rows.append({"time": tstr, "ip": ip, "event": f"CONNECTION established port {e.get('src_port','?')}", "badge": "CONN", "cls": "bm"})
        elif evt == "cowrie.session.file_download":
            rows.append({"time": tstr, "ip": ip, "event": f"FILE DOWNLOAD: {e.get('url','?')[:45]}", "badge": "MALWARE", "cls": "br"})
    return jsonify(rows)

@app.route('/api/credentials/top')
def top_credentials():
    events, _, _ = load_and_parse()
    logins = [e for e in events if e.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]]
    pairs  = Counter(f"{e.get('username','')}:{e.get('password','')}" for e in logins)
    top    = pairs.most_common(20)
    max_ct = top[0][1] if top else 1
    result = []
    for pair, ct in top:
        u, p = (pair.split(":", 1) + [""])[:2]
        bar_color = "var(--crimson)" if ct > max_ct * 0.6 else "var(--gold)" if ct > max_ct * 0.3 else "var(--ivory4)"
        result.append({"user": u, "pass": p, "count": ct, "pct": round(ct / max_ct * 100), "color": bar_color})
    return jsonify(result)

@app.route('/api/ips/top')
def top_ips():
    events, by_ip, _ = load_and_parse()
    counts = {ip: len(d["logins"]) for ip, d in by_ip.items()}
    top    = sorted(counts.items(), key=lambda x: -x[1])[:10]
    max_ct = top[0][1] if top else 1
    result = []
    for ip, ct in top:
        col = "var(--crimson-bright)" if ct > max_ct * 0.6 else "var(--gold-text)" if ct > max_ct * 0.3 else "var(--ivory2)"
        result.append({"ip": ip, "count": ct, "pct": round(ct / max_ct * 100), "color": col})
    return jsonify(result)

@app.route('/api/sessions/durations')
def session_durations():
    _, _, by_session = load_and_parse()
    buckets = {"< 10s": 0, "10–30s": 0, "30s–1m": 0, "1–5m": 0, "5–15m": 0, "15–30m": 0, "> 30m": 0}
    for sid, s in by_session.items():
        if s["start"] and s["end"]:
            try:
                start = datetime.fromisoformat(s["start"].replace("Z", "+00:00"))
                end   = datetime.fromisoformat(s["end"].replace("Z", "+00:00"))
                dur   = (end - start).total_seconds()
                if dur < 10:    buckets["< 10s"]   += 1
                elif dur < 30:  buckets["10–30s"]  += 1
                elif dur < 60:  buckets["30s–1m"]  += 1
                elif dur < 300: buckets["1–5m"]    += 1
                elif dur < 900: buckets["5–15m"]   += 1
                elif dur < 1800:buckets["15–30m"]  += 1
                else:           buckets["> 30m"]   += 1
            except: pass
    return jsonify({"labels": list(buckets.keys()), "data": list(buckets.values())})

@app.route('/api/behavior/aps')
def behavior_aps():
    events, by_ip, by_session = load_and_parse()
    ip_dur = get_ip_durations(by_session)
    result = []
    for ip, d in by_ip.items():
        aps = calculate_aps(len(d["logins"]), len(d["commands"]), ip_dur.get(ip, 0))
        result.append({"ip": ip, "aps": aps, "category": classify_aps(aps),
                        "attempts": len(d["logins"]), "commands": len(d["commands"])})
    result.sort(key=lambda x: -x["aps"])
    max_aps = result[0]["aps"] if result else 1
    for r in result:
        r["pct"] = round(r["aps"] / max_aps * 100)
        cat = r["category"]
        r["color"]      = "var(--crimson)" if cat == "PERSISTENT" else "var(--gold)" if cat == "BRUTE-FORCE" else "var(--azure)" if cat == "AUTO-SCAN" else "var(--emerald-text)"
        r["text_color"] = "var(--crimson-bright)" if cat == "PERSISTENT" else "var(--gold-text)" if cat == "BRUTE-FORCE" else "var(--azure-text)" if cat == "AUTO-SCAN" else "var(--emerald-text)"
    return jsonify(result[:15])

@app.route('/api/commands/classified')
def commands_classified():
    events, _, _ = load_and_parse()
    cmds = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    cats = Counter(classify_command(e.get("input", "")) for e in cmds)
    badge_map = {"RECON":"bb","MALWARE":"br","PERSIST":"br","SYS-DISCO":"bb","PRIVESC":"ba","LATERAL":"ba","CLEANUP":"be","OTHER":"bm"}
    result = []
    for cat, count in cats.most_common():
        examples = list(set(e.get("input","") for e in cmds if classify_command(e.get("input","")) == cat))[:3]
        result.append({"category": cat, "count": count, "examples": examples, "badge_class": badge_map.get(cat,"bm")})
    return jsonify(result)

@app.route('/api/commands/categories')
def commands_categories():
    events, _, _ = load_and_parse()
    cmds = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    cats = Counter(classify_command(e.get("input", "")) for e in cmds)
    items = [{"name": k, "count": v} for k, v in cats.most_common()]
    max_ct = items[0]["count"] if items else 1
    color_map = {"RECON":"var(--crimson)","MALWARE":"var(--crimson)","PERSIST":"var(--gold)","SYS-DISCO":"var(--azure)","PRIVESC":"var(--amber)","LATERAL":"var(--amber)","CLEANUP":"var(--emerald-text)","OTHER":"var(--ivory4)"}
    for i in items:
        i["pct"]   = round(i["count"] / max_ct * 100)
        i["color"] = color_map.get(i["name"], "var(--ivory4)")
    return jsonify(items)

@app.route('/api/behavior/types')
def behavior_types():
    events, by_ip, by_session = load_and_parse()
    ip_dur = get_ip_durations(by_session)
    type_counts = Counter()
    for ip, d in by_ip.items():
        aps = calculate_aps(len(d["logins"]), len(d["commands"]), ip_dur.get(ip, 0))
        type_counts[classify_aps(aps)] += 1
    labels = list(type_counts.keys())
    return jsonify({"labels": labels, "data": [type_counts[l] for l in labels]})

@app.route('/api/sessions/list')
def sessions_list():
    events, by_ip, by_session = load_and_parse()
    ip_dur = get_ip_durations(by_session)
    result = []
    for sid, s in by_session.items():
        ip  = s["ip"]
        d   = by_ip.get(ip, {"logins":[], "commands":[]})
        aps = calculate_aps(len(d["logins"]), len(d["commands"]), ip_dur.get(ip, 0))
        dur_secs = 0
        if s["start"] and s["end"]:
            try:
                start = datetime.fromisoformat(s["start"].replace("Z", "+00:00"))
                end   = datetime.fromisoformat(s["end"].replace("Z", "+00:00"))
                dur_secs = (end - start).total_seconds()
            except: pass
        result.append({
            "session_id":  sid,
            "ip":          ip,
            "aps":         aps,
            "category":    classify_aps(aps),
            "duration":    f"{int(dur_secs//60)}m {int(dur_secs%60)}s",
            "event_count": len(s["events"])
        })
    result.sort(key=lambda x: -x["aps"])
    return jsonify(result[:15])

@app.route('/api/narrative/<session_id>')
def narrative(session_id):
    events, by_ip, by_session = load_and_parse()
    s   = by_session.get(session_id, {"events":[], "ip":""})
    ip  = s["ip"]
    evts = sorted(s["events"], key=lambda e: e.get("timestamp",""))
    lines = []
    for e in evts:
        evt = e.get("eventid","")
        ts  = e.get("timestamp","")
        tstr = ts[11:19] if ts else "--:--:--"
        if evt == "cowrie.login.failed":
            lines.append({"ts":tstr,"type":"fail","text":f"AUTH FAIL — {e.get('username','')}:{e.get('password','')}"})
        elif evt == "cowrie.login.success":
            lines.append({"ts":tstr,"type":"success","text":f"AUTH SUCCESS — {e.get('username','')}:{e.get('password','')}"})
        elif evt == "cowrie.command.input":
            intent = classify_command(e.get("input",""))
            lines.append({"ts":tstr,"type":"cmd","intent":intent,"text":e.get("input","")})
        elif evt == "cowrie.session.connect":
            lines.append({"ts":tstr,"type":"conn","text":f"CONNECTION ESTABLISHED from port {e.get('src_port','?')}"})
        elif evt == "cowrie.session.closed":
            lines.append({"ts":tstr,"type":"close","text":f"SESSION CLOSED — duration {e.get('duration',0):.1f}s"})
        elif evt == "cowrie.session.file_download":
            lines.append({"ts":tstr,"type":"malware","text":f"FILE DOWNLOAD: {e.get('url','?')}"})
    d   = by_ip.get(ip, {"logins":[],"commands":[]})
    aps = calculate_aps(len(d["logins"]), len(d["commands"]), 0)
    return jsonify({
        "lines":       lines,
        "conclusion":  f"Attacker {ip} — APS {aps} ({classify_aps(aps)}). {len(d['logins'])} login attempts, {len(d['commands'])} commands executed.",
        "ip":          ip,
        "aps":         aps,
        "category":    classify_aps(aps),
        "duration":    s.get("duration","unknown")
    })

@app.route('/api/soc/summary')
def soc_summary():
    events, by_ip, by_session = load_and_parse()
    ip_dur = get_ip_durations(by_session)
    persistent = [ip for ip, d in by_ip.items()
                  if calculate_aps(len(d["logins"]), len(d["commands"]), ip_dur.get(ip,0)) > 70]
    malware_count = sum(1 for e in events if e.get("eventid")=="cowrie.command.input" and classify_command(e.get("input",""))=="MALWARE")
    success_count = sum(1 for e in events if e.get("eventid")=="cowrie.login.success")
    downloads     = sum(1 for e in events if e.get("eventid")=="cowrie.session.file_download")
    threat = "CRITICAL" if persistent and malware_count else "HIGH" if persistent or malware_count else "MEDIUM" if success_count else "LOW"
    return jsonify({
        "threat_level":    threat,
        "actions_pending": len(persistent) + (2 if malware_count else 0) + 3,
        "ips_to_block":    len(persistent),
        "iocs":            malware_count + downloads + len(set(e.get("src_ip","") for e in events if e.get("eventid")=="cowrie.login.success"))
    })

@app.route('/api/soc/decisions')
def soc_decisions():
    events, by_ip, by_session = load_and_parse()
    ip_dur = get_ip_durations(by_session)
    actions = []
    persistent_ips = [ip for ip, d in by_ip.items()
                      if calculate_aps(len(d["logins"]), len(d["commands"]), ip_dur.get(ip,0)) > 70]
    malware_evts   = [e for e in events if e.get("eventid")=="cowrie.command.input" and classify_command(e.get("input",""))=="MALWARE"]
    success_evts   = [e for e in events if e.get("eventid")=="cowrie.login.success"]
    all_ips        = list(by_ip.keys())

    if persistent_ips:
        actions.append({"priority":"URGENT","icon":"⛔","action":f"Block IPs at Firewall — {', '.join(persistent_ips[:3])}",
            "detail":f"APS > 70 · confirmed persistent attacker activity · {len(persistent_ips)} IP(s) identified","cls":"su","badge":"br"})
    if malware_evts:
        actions.append({"priority":"URGENT","icon":"🚨","action":"Create SIEM Alert — Malware Command Detected",
            "detail":f"{len(malware_evts)} malware-related commands logged · wget/curl/nc to external hosts","cls":"su","badge":"br"})
    if all_ips:
        actions.append({"priority":"HIGH","icon":"📋","action":f"Add {len(all_ips)} Attacker IPs to Blocklist / Watchlist",
            "detail":"All observed IPs — export-ready for SIEM or threat intel platform","cls":"sh","badge":"bg"})
    if success_evts:
        success_ips = list(set(e.get("src_ip","") for e in success_evts))
        actions.append({"priority":"HIGH","icon":"🔒","action":"Enforce Key-Based SSH — Disable Password Authentication",
            "detail":f"{len(success_evts)} successful password logins recorded from {len(success_ips)} IP(s)","cls":"sh","badge":"bg"})
    actions.append({"priority":"MEDIUM","icon":"📊","action":"Submit Attacker IPs to AbuseIPDB",
        "detail":f"Contribute {len(all_ips)} newly observed IPs to shared threat intelligence","cls":"sm","badge":"bb"})
    actions.append({"priority":"MEDIUM","icon":"🛡️","action":"Configure Fail2Ban — SSH Brute-Force Rate Limiting",
        "detail":"Block IPs after 3 failed SSH attempts within 10 min · reduces attack surface ~80%","cls":"sm","badge":"bb"})
    actions.append({"priority":"LOW","icon":"📄","action":"Generate Full SOC Incident Report",
        "detail":"Export complete behavioral analysis · IOC list · narrative · MITRE ATT&CK mapping","cls":"sl","badge":"be"})
    return jsonify(actions)

@app.route('/api/viz/all')
def viz_all():
    events, by_ip, by_session = load_and_parse()
    logins   = [e for e in events if e.get("eventid") in ["cowrie.login.failed","cowrie.login.success"]]
    cmds     = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    ip_dur   = get_ip_durations(by_session)

    # Timeline
    hourly = [0]*24
    for e in logins:
        ts = e.get("timestamp","")
        if ts:
            try: hourly[int(ts[11:13])] += 1
            except: pass

    # Passwords
    pw_ctr = Counter(e.get("password","") for e in logins if e.get("password"))
    top_pw = pw_ctr.most_common(10)

    # Attacker types
    type_counts = Counter()
    aps_list    = []
    for ip, d in by_ip.items():
        aps = calculate_aps(len(d["logins"]), len(d["commands"]), ip_dur.get(ip,0))
        cat = classify_aps(aps)
        type_counts[cat] += 1
        aps_list.append({"ip":ip,"aps":aps,"category":cat})

    # Command categories
    cmd_cats = Counter(classify_command(e.get("input","")) for e in cmds)

    return jsonify({
        "timeline":    {"labels": [str(h).zfill(2) for h in range(24)], "data": hourly},
        "types":       {"labels": list(type_counts.keys()), "data": [type_counts[k] for k in type_counts]},
        "passwords":   {"labels": [p[0] for p in top_pw], "data": [p[1] for p in top_pw]},
        "cmd_cats":    {"labels": list(cmd_cats.keys()), "data": list(cmd_cats.values())},
        "aps_scores":  sorted(aps_list, key=lambda x: -x["aps"])[:20],
        "totals":      {"attempts":len(logins),"unique_ips":len(by_ip),"commands":len(cmds)}
    })

@app.route('/api/status')
def status():
    exists = os.path.exists(LOG_FILE)
    size   = os.path.getsize(LOG_FILE) if exists else 0
    return jsonify({"log_found": exists, "log_size_bytes": size, "log_path": LOG_FILE})

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  Cowrie SOC Dashboard — Backend API Server")
    print("="*55)
    print(f"  Log file : {LOG_FILE}")
    print(f"  API URL  : http://0.0.0.0:5000")
    print("="*55 + "\n")
    if not os.path.exists(LOG_FILE):
        print(f"  WARNING: Log file not found at {LOG_FILE}")
        print("  Make sure Cowrie is running first!\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
