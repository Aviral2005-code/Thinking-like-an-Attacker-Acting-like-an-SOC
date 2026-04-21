# Thinking-like-an-Attacker-Acting-like-an-SOC
SSH honeypot research project using Cowrie on Kali Linux. Captures real attacks, analyzes behavior with Python, integrates threat intelligence, and visualizes findings through interactive SOC dashboard. Demonstrates threat hunting and incident response skills.
##  Dashboard Preview

| Overview | Attack Feed | Behavior |
|---|---|---|
| Live metrics, 24h timeline, attacker type distribution | Real-time credential attempts with SSE stream | APS scoring, command intent classification |

| Threat Intel | Narrative | SOC Report |
|---|---|---|
| IP confidence scoring per attacker | Per-session attack story reconstruction | Full PDF-ready incident report |

---

##  What This Project Does

This project deploys a **Cowrie SSH honeypot** on Kali Linux and builds a complete analyst-grade SOC dashboard on top of it. Real attackers from the internet SSH into the honeypot thinking it's a real server. Every login attempt, command typed, and file downloaded is logged and fed live into the dashboard.

The dashboard gives you:
- **Live attack feed** — every credential attempt appears in real time via Server-Sent Events
- **Behavioral scoring** — each attacker gets an APS (Attacker Persistence Score) from 0–100
- **Command intent classification** — commands auto-classified into RECON, MALWARE, PERSIST, PRIVESC, etc.
- **Session narrative** — human-readable attack story reconstructed per session
- **SOC action recommendations** — automated priority-based response suggestions
- **SOC Report** — a full incident investigation report with MITRE ATT&CK TTPs

---

##  Architecture

```
Internet Attackers
       │
       ▼ SSH port 2222
┌─────────────────────┐
│   Cowrie Honeypot   │  ← fake Linux shell, logs everything
│   (cowrie user)     │
│   cowrie.json       │  ← one JSON event per line
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   server.py         │  ← Flask API reads cowrie.json
│   (Flask + SSE)     │  ← serves REST endpoints + live stream
│   port 5000         │
└────────┬────────────┘
         │  http://localhost:5000
         ▼
┌─────────────────────┐
│   index.html        │  ← SOC Dashboard frontend
│   (Chart.js)        │  ← fetches API, updates in real time
└─────────────────────┘
```

---

##  Project Structure

```
project/
│
├── scripts/                        ← runs as cowrie user
│   ├── server.py                   ← Flask API backend (main file)
│   ├── realtime_monitor.py         ← terminal live monitor
│   ├── log_organizer.py            ← organizes logs by IP into folders
│   ├── json_analyzer.py            ← deep statistical analysis
│   └── auto_watcher.sh             ← bash watcher script
│
├── Dashboard/                      ← runs as aayush user (desktop)
│   └── index.html                  ← complete SOC frontend
│
└── HoneypotLogs/                   ← auto-generated log output
    ├── summary_report.txt
    ├── analysis_report.json
    └── <attacker-ip>/
        ├── login_attempts.txt
        ├── commands_typed.txt
        └── session_details.json
```

---

##  Tech Stack

| Component | Technology |
|---|---|
| Honeypot | Cowrie (medium-interaction SSH honeypot) |
| Backend | Python 3, Flask, Flask-CORS |
| Real-time | Server-Sent Events (SSE) |
| Frontend | Vanilla HTML/CSS/JS, Chart.js |
| Log Analysis | Python (json, collections, datetime) |
| OS | Kali Linux |
| Fonts | Cinzel, JetBrains Mono, Figtree |

---

##  Setup & Installation

### Prerequisites
- Kali Linux (VM or bare metal)
- Python 3.10+
- A separate cowrie system user
- Port 2222 open for incoming SSH

---

### Step 1 — Install Cowrie

```bash
# Create cowrie user
sudo adduser --disabled-password cowrie

# Switch to cowrie user
sudo su - cowrie

# Clone Cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie

# Create virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy config
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

### Step 2 — Configure Cowrie

Edit `etc/cowrie.cfg`:
```ini
[honeypot]
hostname = srv04
listen_endpoints = tcp:2222:interface=0.0.0.0
```

Redirect port 22 → 2222:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Start Cowrie:
```bash
bin/cowrie start
bin/cowrie status
```

Verify logs are being written:
```bash
tail -f var/log/cowrie/cowrie.json
```

---

### Step 3 — Install Flask

```bash
sudo su - cowrie
cd ~/cowrie
source cowrie-env/bin/activate
pip install flask flask-cors
```

---

### Step 4 — Deploy server.py

Place `server.py` in `/home/cowrie/scripts/` and update the config at the top:

```python
COWRIE_JSON   = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
DASHBOARD_DIR = "/home/YOUR_USER/Desktop/Dashboard"   # ← change this
```

---

### Step 5 — Deploy the Dashboard

Place `index.html` in `/home/YOUR_USER/Desktop/Dashboard/`

---

### Step 6 — Run the server

```bash
sudo su - cowrie
cd ~/cowrie
source cowrie-env/bin/activate
python3 /home/cowrie/scripts/server.py
```

Open browser: **http://localhost:5000**

---

### Step 7 — Auto-start on boot (optional)

```bash
crontab -e
# Add this line:
@reboot /home/cowrie/cowrie/cowrie-env/bin/python3 /home/cowrie/scripts/server.py &
```

Or run in background:
```bash
nohup python3 /home/cowrie/scripts/server.py > /tmp/dashboard.log 2>&1 &
```

---

##  API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Serves the dashboard HTML |
| `GET /api/overview` | Total attacks, unique IPs, commands, sessions |
| `GET /api/timeline` | Hourly attack count for 24h chart |
| `GET /api/feed` | Recent 60 events for live feed |
| `GET /api/passwords` | Top 10 most used passwords |
| `GET /api/attacktypes` | Attacker type distribution (APS-based) |
| `GET /api/ips/top` | Top 10 attacking IPs by volume |
| `GET /api/credentials` | Top credential pairs tried |
| `GET /api/sessions/durations` | Session duration distribution |
| `GET /api/behavior/aps` | APS scores for all attackers |
| `GET /api/commands/classified` | Commands grouped by intent category |
| `GET /api/sessions/list` | All sessions sorted by APS |
| `GET /api/sessions/<id>` | Single session detail + event timeline |
| `GET /api/intel/ips` | IP confidence scoring table |
| `GET /api/viz/geo` | Top IPs for geo chart |
| `GET /api/viz/cmdcat` | Command categories for polar chart |
| `GET /api/stream` | SSE stream — pushes live events instantly |

---

##  Attacker Persistence Score (APS)

Each attacker is scored 0–100 based on their behavior:

| Component | Max Points | Formula |
|---|---|---|
| Login attempts | 20 pts | attempts ÷ 5 |
| Commands executed | 40 pts | commands × 2 |
| Session count | 15 pts | sessions × 3 |
| Total time in session | 25 pts | duration ÷ 60 |

**Classification:**

| Score | Type | Description |
|---|---|---|
| > 70 | 🔴 PERSISTENT | Long sessions, many commands. Likely human or semi-automated. |
| 40–70 | 🟡 BRUTE-FORCE BOT | High login attempts, scripted spray. |
| 15–40 | 🔵 AUTO SCANNER | Short sessions, default credential check only. |
| < 15 | 🟢 SCANNER | Single connection, banner grab only. |

---

##  Command Intent Classification

Commands are automatically classified into threat categories:

| Category | Examples |
|---|---|
| `RECON` | `uname -a`, `id`, `whoami`, `hostname` |
| `SYS-DISCO` | `cat /etc/passwd`, `ps aux`, `netstat` |
| `MALWARE` | `wget`, `curl`, `nc`, `/dev/tcp` |
| `PERSIST` | `crontab`, `.bashrc`, `authorized_keys` |
| `PRIVESC` | `sudo`, `chmod 4755`, `su root` |
| `LATERAL` | `ssh-keygen`, `known_hosts`, `scp` |
| `CLEANUP` | `history -c`, `rm -rf /tmp`, `unset HIST` |

---

##  Dashboard Tabs

| Tab | What it shows |
|---|---|
| **Overview** | Key metrics, live feed, top origins, 24h timeline |
| **Attack Feed** | All credential attempts, top IPs, session durations |
| **Behavior** | APS leaderboard, command intent classification |
| **Threat Intel** | IP confidence table (AbuseIPDB-ready) |
| **Narrative** | Per-session attack story with timeline |
| **SOC Actions** | Prioritized response recommendations |
| **Visualizations** | 6 charts: heatmap, donut, polar, bar, scatter, geo |
| **SOC Report** | Full incident investigation report (print to PDF) |
| **Phases** | Project phases with commands and status |

---

##  Real-Time Streaming

The dashboard uses **Server-Sent Events (SSE)** for zero-delay updates:

```
Attacker SSH → Cowrie logs → server.py detects new line (0.5s)
→ SSE push to browser → DOM updates instantly
```

- Live feed updates the moment Cowrie writes a new log line
- Attack counter increments in real time
- No page refresh needed
- Auto-reconnects if connection drops

---

##  Security Notes

- Cowrie runs as a **non-root dedicated user** (`cowrie`)
- The honeypot is a **fake shell** — attackers cannot escape it
- All attacker commands are **simulated**, not executed
- Recommend running inside a **VM or isolated network segment**
- Consider enabling UFW to restrict outbound connections from the cowrie user

```bash
sudo ufw default deny outgoing
sudo ufw allow out to any port 53    # DNS
sudo ufw allow out to any port 443   # HTTPS
sudo ufw allow 2222/tcp
sudo ufw enable
```

---

##  Requirements

```
Python 3.10+
flask
flask-cors
cowrie (and its dependencies)
```

Install:
```bash
pip install flask flask-cors
```

---

##  Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
---

##  Author

**Aviral verma
Aayush Gusain
Vidit Surana
Aayan Akhtar**
Bennett University · Cybersecurity Department

---
- [MITRE ATT&CK](https://attack.mitre.org/) — TTP framework used in SOC report

---
