/* ================================================================
   Cowrie SOC Dashboard — Live Data Connector
   Include this AFTER Chart.js in your index.html:
   <script src="data_connector.js"></script>

   Change API_URL to your honeypot VM's IP address.
================================================================ */

const API_URL = 'http://10.252.173.100:5000'; // ← CHANGE THIS to your honeypot VM IP

// ── HELPERS ────────────────────────────────────────────────────
async function api(path) {
  try {
    const r = await fetch(API_URL + path);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  } catch (e) {
    console.warn('[Cowrie Connector] Failed:', path, e.message);
    return null;
  }
}

function getChart(id) {
  const el = document.getElementById(id);
  return el ? Chart.getChart(el) : null;
}

function updateChart(id, labels, data) {
  const chart = getChart(id);
  if (!chart) return;
  if (labels) chart.data.labels = labels;
  chart.data.datasets[0].data = data;
  chart.update('none');
}

// ── STATUS CHECK ───────────────────────────────────────────────
async function checkStatus() {
  const status = await api('/api/status');
  if (!status) {
    console.warn('[Cowrie Connector] Backend not reachable at ' + API_URL);
    return false;
  }
  if (!status.log_found) {
    console.warn('[Cowrie Connector] cowrie.json not found on server. Is Cowrie running?');
  }
  return true;
}

// ── OVERVIEW TAB ──────────────────────────────────────────────
async function loadOverview() {
  // Metrics
  const stats = await api('/api/overview/stats');
  if (stats) {
    const mvals = document.querySelectorAll('#tab-overview .mrow .mval');
    if (mvals[0]) mvals[0].textContent = stats.total_attempts.toLocaleString();
    if (mvals[1]) mvals[1].textContent = stats.unique_ips.toLocaleString();
    if (mvals[2]) mvals[2].textContent = stats.sessions.toLocaleString();
    if (mvals[3]) mvals[3].textContent = stats.commands.toLocaleString();
  }

  // Timeline chart
  const tl = await api('/api/timeline/24h');
  if (tl) updateChart('ch-timeline', tl.labels, tl.data);

  // Attacker type donut
  const types = await api('/api/behavior/types');
  if (types) {
    const chart = getChart('ch-donut');
    if (chart) {
      chart.data.labels   = types.labels;
      chart.data.datasets[0].data = types.data;
      chart.update('none');
    }
  }

  // Password bar chart
  const creds = await api('/api/credentials/top');
  if (creds && creds.length) {
    updateChart('ch-pw', creds.slice(0,7).map(c => c.pass), creds.slice(0,7).map(c => c.count));
  }

  // Live feed
  const feed = await api('/api/feed/recent');
  if (feed) populateLiveFeed(feed.slice(0, 8));

  // Top origins (geo)
  const ips = await api('/api/ips/top');
  if (ips) populateGeo(ips.slice(0, 5));

  // Command categories
  const cats = await api('/api/commands/categories');
  if (cats) populateCmdCategories(cats.slice(0, 6));
}

function populateLiveFeed(rows) {
  const container = document.getElementById('live-feed');
  if (!container || !rows.length) return;
  container.innerHTML = rows.map(r =>
    `<div class="fr rnew">
      <span class="ft">${r.time}</span>
      <span class="fi">${r.ip}</span>
      <span class="fe">${escHtml(r.event)}</span>
      <span class="badge ${r.cls}">${r.badge}</span>
    </div>`
  ).join('');
  const ts = document.getElementById('feed-ts');
  if (ts) ts.textContent = 'updated ' + new Date().toLocaleTimeString();
}

function populateGeo(ips) {
  const geo = document.querySelector('#tab-overview .clist');
  if (!geo || !ips.length) return;
  const maxCount = ips[0].count;
  const barColors = ['var(--crimson)', 'var(--crimson)', 'var(--gold)', 'var(--ivory4)', 'var(--ivory4)'];
  geo.innerHTML = ips.map((item, i) =>
    `<div class="crow">
      <span class="cfl">${item.ip.slice(0,8)}</span>
      <span class="cnm" style="font-family:var(--ff-m);font-size:10px;color:var(--azure-text)">${item.ip}</span>
      <div class="mb-w"><div class="mb-f" style="width:${item.pct}%;background:${barColors[i]||'var(--ivory4)'}"></div></div>
      <span class="cct">${item.count}</span>
    </div>`
  ).join('');
}

function populateCmdCategories(cats) {
  const list = document.querySelector('#tab-overview .catlist');
  if (!list || !cats.length) return;
  list.innerHTML = cats.map(c =>
    `<div class="catrow">
      <span class="catnm">${c.name}</span>
      <div class="mb-w"><div class="mb-f" style="width:${c.pct}%;background:${c.color}"></div></div>
      <span class="catct">${c.count}</span>
    </div>`
  ).join('');
}

// ── ATTACK FEED TAB ───────────────────────────────────────────
async function loadFeedTab() {
  // Credentials list
  const creds = await api('/api/credentials/top');
  if (creds) {
    populateCredList(creds.slice(0, 15));
    // Feed tab metrics
    const feedMvals = document.querySelectorAll('#tab-feed .mrow .mval');
    const uniqueUsers = new Set(creds.map(c => c.user)).size;
    const uniquePasses = new Set(creds.map(c => c.pass)).size;
    if (feedMvals[1]) feedMvals[1].textContent = uniqueUsers.toLocaleString();
    if (feedMvals[2]) feedMvals[2].textContent = uniquePasses.toLocaleString();
  }

  // Top IPs
  const ips = await api('/api/ips/top');
  if (ips) populateIPList(ips);

  // Duration chart
  const dur = await api('/api/sessions/durations');
  if (dur) updateChart('ch-duration', dur.labels, dur.data);
}

function populateCredList(creds) {
  const list = document.getElementById('cred-list');
  if (!list || !creds.length) return;
  const maxCount = creds[0].count;
  list.innerHTML = creds.map(c =>
    `<div class="credrow" data-user="${escHtml(c.user)}" data-pass="${escHtml(c.pass)}" data-ct="${c.count}">
      <span class="credkv">${escHtml(c.user)} : ${escHtml(c.pass)}</span>
      <div class="mb-w"><div class="mb-f" style="width:${c.pct}%;background:${c.color}"></div></div>
      <span class="credct">${c.count}</span>
    </div>`
  ).join('');
  const lbl = document.getElementById('cred-count-lbl');
  if (lbl) lbl.textContent = `showing ${creds.length} entries`;
}

function populateIPList(ips) {
  const list = document.getElementById('ip-list');
  if (!list || !ips.length) return;
  list.innerHTML = ips.map(item =>
    `<div class="fr">
      <span class="fi">${item.ip}</span>
      <span class="fe">— ${item.count} login attempts</span>
      <span style="font-family:var(--ff-m);font-size:11px;font-weight:600;${styleForCount(item.pct)}">${item.count}</span>
    </div>`
  ).join('');
}

function styleForCount(pct) {
  if (pct > 60) return 'color:var(--crimson-bright)';
  if (pct > 30) return 'color:var(--gold-text)';
  return 'color:var(--ivory2)';
}

// ── BEHAVIOR TAB ──────────────────────────────────────────────
async function loadBehavior() {
  const aps = await api('/api/behavior/aps');
  if (aps) populateAPSList(aps);

  const cmds = await api('/api/commands/classified');
  if (cmds) populateCmdList(cmds);
}

function populateAPSList(aps) {
  const list = document.querySelector('#tab-behavior .apslist');
  if (!list || !aps.length) return;
  list.innerHTML = aps.slice(0, 10).map(a =>
    `<div class="apsrow">
      <span class="apsip">${a.ip}</span>
      <div class="mb-w"><div class="mb-f" style="width:${a.pct}%;background:${a.color}"></div></div>
      <span class="apssc" style="color:${a.text_color}">${a.aps}</span>
      <span class="apsty" style="color:${a.text_color}">${a.category}</span>
    </div>`
  ).join('');
}

function populateCmdList(cmds) {
  const list = document.querySelector('#tab-behavior .cmdlist');
  if (!list || !cmds.length) return;
  list.innerHTML = cmds.slice(0, 8).map(c => {
    const example = c.examples.length ? c.examples[0].slice(0, 55) : c.category;
    return `<div class="cmditem">
      <span class="cmdcat badge ${c.badge_class}">${c.category}</span>
      <span class="cmdtxt">${escHtml(example)}</span>
      <span class="cmdn">×${c.count}</span>
    </div>`;
  }).join('');
}

// ── NARRATIVE TAB ─────────────────────────────────────────────
async function loadNarrativeSessions() {
  const sessions = await api('/api/sessions/list');
  if (!sessions || !sessions.length) return;
  const sel = document.getElementById('sess-select');
  if (!sel) return;
  sel.innerHTML = sessions.map((s, i) =>
    `<option value="${s.session_id}">${s.ip} — ${s.category} — APS ${s.aps}</option>`
  ).join('');
  // Load first session
  if (sessions[0]) loadSession(sessions[0].session_id);
}

async function loadSession(sessionId) {
  const n = await api('/api/narrative/' + sessionId);
  if (!n) return;

  // Update badges
  const typeBadge = document.getElementById('sess-type-badge');
  const apsBadge  = document.getElementById('sess-aps-badge');
  const durBadge  = document.getElementById('sess-dur-badge');
  if (typeBadge) typeBadge.textContent = n.category;
  if (apsBadge)  apsBadge.textContent  = 'APS: ' + n.aps;
  if (durBadge)  durBadge.textContent  = 'SESSION: ' + n.ip;

  // Update title
  const title = document.getElementById('narr-title');
  if (title) title.textContent = 'Attack Session Report — ' + n.ip;

  // Render narrative
  const body = document.getElementById('narr-body');
  if (!body) return;

  const typeColors = {
    "fail":    "<span class='nred'>✗ AUTH FAIL</span>",
    "success": "<span class='ngrn'>✓ AUTH SUCCESS</span>",
    "cmd":     "<span class='ngld'>$ CMD</span>",
    "conn":    "<span class='nev'>⟶ CONNECT</span>",
    "close":   "<span class='nev'>✕ CLOSED</span>",
    "malware": "<span class='nred'>⬇ MALWARE</span>",
  };

  const lineHtml = n.lines.map(l => {
    const typeTag = typeColors[l.type] || "<span class='nev'>EVENT</span>";
    const intentTag = l.intent ? `<span class="badge bb" style="font-size:7px;padding:1px 6px;margin:0 6px">${l.intent}</span>` : '';
    return `<div><span class="nts">${l.ts}</span>${typeTag}${intentTag} <span class="nev">${escHtml(l.text)}</span></div>`;
  }).join('');

  body.innerHTML = lineHtml + (n.conclusion
    ? `<div class="nconc"><strong>CONCLUSION:</strong> ${escHtml(n.conclusion)}</div>` : '');
}

// Make loadSession globally accessible (called by onchange in HTML)
window.loadSession = loadSession;

// ── SOC ACTIONS TAB ───────────────────────────────────────────
async function loadSOC() {
  const summary = await api('/api/soc/summary');
  if (summary) {
    const socMvals = document.querySelectorAll('#tab-soc .mrow .mval');
    if (socMvals[0]) socMvals[0].textContent = summary.threat_level;
    if (socMvals[1]) socMvals[1].textContent = summary.actions_pending;
    if (socMvals[2]) socMvals[2].textContent = summary.ips_to_block;
    if (socMvals[3]) socMvals[3].textContent = summary.iocs;
  }

  const decisions = await api('/api/soc/decisions');
  if (decisions) populateSOCActions(decisions);
}

function populateSOCActions(actions) {
  const list = document.querySelector('#tab-soc .soclist');
  if (!list || !actions.length) return;
  list.innerHTML = actions.map(a =>
    `<div class="socitem ${a.cls}">
      <span class="soci">${a.icon}</span>
      <div class="socm">
        <div class="soca">${escHtml(a.action)}</div>
        <div class="socd">${escHtml(a.detail)}</div>
      </div>
      <span class="badge ${a.badge}">${a.priority}</span>
    </div>`
  ).join('');
}

// ── VISUALIZATIONS TAB ────────────────────────────────────────
async function loadVisualizations() {
  const viz = await api('/api/viz/all');
  if (!viz) return;

  // Stat row totals
  const vstats = document.querySelectorAll('#tab-viz .vstat-v');
  if (vstats[0]) vstats[0].textContent = viz.totals.attempts.toLocaleString();
  if (vstats[1]) vstats[1].textContent = viz.totals.unique_ips.toLocaleString();
  if (vstats[2]) vstats[2].textContent = viz.totals.commands.toLocaleString();

  // 1. Timeline bar chart
  updateChart('v-timeline', viz.timeline.labels, viz.timeline.data);

  // 2. Attacker type donut
  const donut = getChart('v-donut');
  if (donut && viz.types.labels.length) {
    donut.data.labels              = viz.types.labels;
    donut.data.datasets[0].data   = viz.types.data;
    donut.update('none');
  }

  // 3. Command category polar
  const cmdcat = getChart('v-cmdcat');
  if (cmdcat && viz.cmd_cats.labels.length) {
    cmdcat.data.labels            = viz.cmd_cats.labels;
    cmdcat.data.datasets[0].data  = viz.cmd_cats.data;
    cmdcat.update('none');
  }

  // 4. Password bar chart
  if (viz.passwords.labels.length) {
    updateChart('v-pw', viz.passwords.labels, viz.passwords.data);
  }

  // 5. APS scatter (keep mock if no data, else update)
  const apsChart = getChart('v-aps');
  if (apsChart && viz.aps_scores.length) {
    const catMap = { "PERSISTENT":0, "BRUTE-FORCE":1, "AUTO-SCAN":2, "SCANNER":3 };
    const datasets = [
      {label:'Persistent', data:[], backgroundColor:'rgba(192,23,45,0.6)',  borderColor:'#c0172d', pointRadius:8},
      {label:'Brute-Force',data:[], backgroundColor:'rgba(201,150,58,0.6)', borderColor:'#c9963a', pointRadius:7},
      {label:'Auto-Scan',  data:[], backgroundColor:'rgba(61,127,255,0.5)', borderColor:'#3d7fff', pointRadius:6},
      {label:'Scanner',    data:[], backgroundColor:'rgba(26,138,90,0.5)',  borderColor:'#1a8a5a', pointRadius:5},
    ];
    viz.aps_scores.forEach((s, i) => {
      const idx = catMap[s.category] ?? 2;
      datasets[idx].data.push({x: s.aps, y: i+1});
    });
    apsChart.data.datasets = datasets;
    apsChart.update('none');
  }

  // 6. Geo chart — show top IPs since we have no real geo lookup
  const geoChart = getChart('v-geo');
  if (geoChart) {
    const ips = await api('/api/ips/top');
    if (ips && ips.length) {
      geoChart.data.labels              = ips.map(i => i.ip);
      geoChart.data.datasets[0].data    = ips.map(i => i.count);
      geoChart.update('none');
    }
  }
}

// ── AUTO-REFRESH ──────────────────────────────────────────────
function startAutoRefresh(intervalMs = 30000) {
  setInterval(async () => {
    const activeTab = document.querySelector('.nav-tab.active');
    if (!activeTab) return;
    const tabId = activeTab.dataset.tab;
    if (tabId === 'overview') { await loadOverview(); }
    else if (tabId === 'feed')     { await loadFeedTab(); }
    else if (tabId === 'behavior') { await loadBehavior(); }
    else if (tabId === 'soc')      { await loadSOC(); }
    else if (tabId === 'viz')      { await loadVisualizations(); }
  }, intervalMs);
}

// ── UTILITY ───────────────────────────────────────────────────
function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── INIT ──────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async function () {
  // Wait for original charts to initialize first
  await new Promise(r => setTimeout(r, 200));

  const ok = await checkStatus();
  if (!ok) {
    console.warn('[Cowrie Connector] Cannot reach backend. Make sure server.py is running.');
    return;
  }

  console.log('[Cowrie Connector] Connected to backend at ' + API_URL);

  // Load all tabs
  await loadOverview();
  await loadFeedTab();
  await loadBehavior();
  await loadNarrativeSessions();
  await loadSOC();
  await loadVisualizations();

  // Reload active tab every 30 seconds
  startAutoRefresh(30000);

  // Hook into tab switching to reload data on tab change
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', async () => {
      await new Promise(r => setTimeout(r, 100));
      const tabId = tab.dataset.tab;
      if (tabId === 'overview')  await loadOverview();
      else if (tabId === 'feed')     await loadFeedTab();
      else if (tabId === 'behavior') await loadBehavior();
      else if (tabId === 'narrative') await loadNarrativeSessions();
      else if (tabId === 'soc')      await loadSOC();
      else if (tabId === 'viz')      await loadVisualizations();
    });
  });
});
