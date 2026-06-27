/* ===========================================================================
   PhishWatch console — front-end logic
   Talks to the FastAPI backend:  POST /analyze, GET /stats, GET /cache/stats
   Populates every panel from real scan data. No build step, no dependencies.
   =========================================================================== */

const API = ""; // same origin (served by FastAPI). Set to "http://127.0.0.1:8000" if hosting the page elsewhere.
const REFRESH_MS = 15000;
const CIRC = 326.7;     // circumference of the score gauge (2 * pi * 52)
const $ = (id) => document.getElementById(id);

const SEV_ORDER = ["low", "med", "high", "crit"];
const VERDICT_CLASS = { "LOW RISK": "low", "CAUTION": "med", "HIGH RISK": "high", "CRITICAL": "crit" };
const SEV_ICON = { crit: "!", high: "▲", med: "•", low: "·" };

/* ---------- Run a scan ---------- */
async function analyze() {
  const input = $("urlInput");
  const url = input.value.trim();
  if (!url) return;
  const btn = $("analyzeBtn");
  btn.disabled = true;
  btn.textContent = "…";
  try {
    const res = await fetch(`${API}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const entry = await res.json();
    renderHero(entry);
    renderChecks(entry);
    await refresh();        // update KPIs, table, charts
  } catch (err) {
    setBackend(false);
    console.error("Analyze failed:", err);
  } finally {
    btn.disabled = false;
    btn.textContent = "ANALYZE";
  }
}

/* ---------- Poll aggregate stats ---------- */
async function refresh() {
  try {
    const [stats, cache] = await Promise.all([
      fetch(`${API}/stats`).then((r) => r.json()),
      fetch(`${API}/cache/stats`).then((r) => r.json()),
    ]);
    setBackend(true);
    renderKpis(stats);
    renderDistribution(stats.distribution);
    renderVolume(stats.volume);
    renderRecent(stats.recent);
    renderCache(cache);
    if (stats.latest) {
      renderHero(stats.latest);
      renderChecks(stats.latest);
    }
  } catch (err) {
    setBackend(false);
  }
}

/* ---------- Renderers ---------- */
function renderKpis(s) {
  $("kpiScans24h").textContent = s.scans_24h;
  $("kpiScansTotal").textContent = `total ${s.scans_total}`;
  $("kpiFlagged").textContent = s.flagged;
  $("kpiCritical").textContent = s.critical;
  $("kpiAvg").textContent = s.avg_score;
}

function renderHero(e) {
  $("latestScore").textContent = e.score;
  const arc = $("scoreArc");
  const filled = (e.score / 100) * CIRC;
  arc.setAttribute("stroke-dasharray", `${filled.toFixed(1)} ${CIRC}`);
  arc.setAttribute("stroke", `var(--${e.severity})`);

  const badge = $("latestVerdict");
  badge.textContent = e.verdict;
  badge.className = "verdict-badge " + (VERDICT_CLASS[e.verdict] || "");

  $("latestMeta").textContent = `scan #${e.id} · ${timeAgo(e.ts)}`;
  $("latestTarget").innerHTML =
    `<span class="lbl">target </span><span class="host">${escapeHtml(e.url || e.target)}</span>`;

  const box = $("latestSignals");
  box.innerHTML = "";
  if (!e.signals || e.signals.length === 0) {
    box.innerHTML = `<div class="none">No risk signals fired — looks clean.</div>`;
    return;
  }
  for (const sig of e.signals) {
    const row = document.createElement("div");
    row.className = `signal ${sig.severity}`;
    row.innerHTML =
      `<div class="ico">${SEV_ICON[sig.severity] || "•"}</div>` +
      `<div><div>${escapeHtml(sig.label)}</div>` +
      `<div class="detail">${escapeHtml(sig.detail)}</div></div>` +
      `<div class="wt">+${sig.weight}</div>`;
    box.appendChild(row);
  }
}

function renderChecks(entry) {
  const title = entry.panel_title || "Network Checks";
  $("checksTitle").textContent = title;
  $("checksMeta").textContent =
    entry.kind === "email" ? "SPF · DKIM · DMARC" : "WHOIS · Redirect · TLS";
  const row = $("checksRow");
  row.innerHTML = "";
  const checks = entry.checks || {};
  for (const [name, text] of Object.entries(checks)) {
    const cell = document.createElement("div");
    cell.className = "auth " + checkClass(text);
    cell.innerHTML = `<div class="k">${escapeHtml(name)}</div>` +
                     `<div class="v">${escapeHtml(text)}</div>`;
    row.appendChild(cell);
  }
}

function checkClass(text) {
  const t = String(text).toUpperCase();
  if (t === "OK" || t === "PASS") return "ok";
  if (t === "FAIL") return "fail";
  return "skip"; // SKIP, NONE, N/A, unverified
}

function renderDistribution(d) {
  const total = SEV_ORDER.reduce((a, k) => a + (d[k] || 0), 0);
  $("distTotal").textContent = `last ${total}`;
  $("ctLow").textContent = d.low || 0;
  $("ctMed").textContent = d.med || 0;
  $("ctHigh").textContent = d.high || 0;
  $("ctCrit").textContent = d.crit || 0;

  const segs = { low: "segLow", med: "segMed", high: "segHigh", crit: "segCrit" };
  let offset = 25; // start at 12 o'clock
  for (const sev of SEV_ORDER) {
    const pct = total ? ((d[sev] || 0) / total) * 100 : 0;
    const seg = $(segs[sev]);
    seg.setAttribute("stroke-dasharray", `${pct.toFixed(2)} ${(100 - pct).toFixed(2)}`);
    seg.setAttribute("stroke-dashoffset", offset.toFixed(2));
    offset -= pct; // next segment starts where this one ends
  }
}

function renderVolume(v) {
  const wrap = $("volumeBars");
  wrap.innerHTML = "";
  const max = Math.max(1, ...v.buckets);
  v.buckets.forEach((count, i) => {
    const h = Math.round((count / max) * 100);
    const hot = count === max && count > 0;
    const b = document.createElement("div");
    b.className = "b";
    b.innerHTML =
      `<div class="fill${hot ? " hot" : ""}" style="height:${h}%"></div>` +
      `<div class="t">${v.labels[i]}</div>`;
    wrap.appendChild(b);
  });
}

function renderRecent(rows) {
  const body = $("recentBody");
  if (!rows || rows.length === 0) {
    body.innerHTML = `<tr><td colspan="4" class="empty">No scans recorded yet.</td></tr>`;
    return;
  }
  body.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="host">${escapeHtml(r.target)}</td>` +
      `<td><span class="pill ${r.severity}">${r.verdict.split(" ")[0]}</span></td>` +
      `<td class="score" style="color:var(--${r.severity})">${r.score}</td>` +
      `<td class="time">${clock(r.ts)}</td>`;
    body.appendChild(tr);
  }
}

function renderCache(c) {
  $("cacheHit").textContent = Math.round((c.hit_rate || 0) * 100) + "%";
  $("cacheEntries").textContent = c.entries ?? 0;
  $("cacheSaved").textContent = (c.avg_saved_seconds ?? 0).toFixed(1) + "s";
}

/* ---------- Status + helpers ---------- */
function setBackend(online) {
  const ring = $("backendRing");
  const label = $("backendLabel");
  ring.className = "ring " + (online ? "online" : "offline");
  label.textContent = online ? "BACKEND · ONLINE" : "BACKEND · OFFLINE";
}

function clock(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function timeAgo(ts) {
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------- Email analysis modal ---------- */
async function analyzeEmail() {
  const raw = $("emailInput").value.trim();
  if (!raw) return;
  const btn = $("emailAnalyze");
  btn.disabled = true;
  btn.textContent = "Analyzing…";
  try {
    const res = await fetch(`${API}/analyze-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const entry = await res.json();
    renderHero(entry);
    renderChecks(entry);
    closeEmailModal();
    await refresh();
  } catch (err) {
    setBackend(false);
    console.error("Email analyze failed:", err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze Email";
  }
}

function openEmailModal() {
  $("emailModal").hidden = false;
  $("emailInput").focus();
}
function closeEmailModal() {
  $("emailModal").hidden = true;
}

/* ---------- Wire up ---------- */
$("analyzeBtn").addEventListener("click", analyze);
$("urlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") analyze(); });
$("emailBtn").addEventListener("click", openEmailModal);
$("emailClose").addEventListener("click", closeEmailModal);
$("emailCancel").addEventListener("click", closeEmailModal);
$("emailAnalyze").addEventListener("click", analyzeEmail);
$("emailModal").addEventListener("click", (e) => { if (e.target.id === "emailModal") closeEmailModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeEmailModal(); });

refresh();
setInterval(refresh, REFRESH_MS);