"""
PhishWatch - phishing URL analyzer API
======================================

A FastAPI service that scores a URL for phishing risk, combining:

  STRUCTURAL checks (no network) - 13 rules ported from the original
    front-end engine: no-HTTPS, IP-as-host, '@' trick, punycode/homograph,
    misplaced brand, risky TLD, URL shortener, excessive subdomains,
    credential-bait keywords, hyphen/digit-swap, explicit port, long URL,
    heavy encoding.

  NETWORK checks (cached) - the signals a browser can't compute: domain age
    via WHOIS, the real redirect chain via httpx, and TLS certificate
    validity. Each expensive lookup is wrapped with @cached_lookup so repeat
    scans of the same domain are instant.

Every check runs inside the runner's try/except, so a slow or failing lookup
never breaks the response - it just contributes nothing (graceful degradation).

Scans are recorded in an in-memory history store that feeds the dashboard
(KPIs, recent detections, risk distribution, scan volume). History is lost on
restart - swap _HISTORY for SQLite when you want it to persist.

RUN
    pip install -r requirements.txt
    uvicorn app:app --reload
    # dashboard at http://127.0.0.1:8000/
    # API docs  at http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import ssl
import time
from collections import deque
from typing import Any, Callable
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import email_analyzer
from cache import cache_stats, cached_lookup

# Optional deps - the service still boots and every other check still runs if
# these aren't installed.
try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None

try:
    import whois as whois_lib
except Exception:  # pragma: no cover
    whois_lib = None

try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline mode
except Exception:  # pragma: no cover
    tldextract = None
    _EXTRACT = None


# ==========================================================================
# Reference data
# ==========================================================================
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "country",
    "kim", "work", "click", "link", "loan", "review", "win", "bid", "stream",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}
BRANDS = {
    "paypal", "microsoft", "apple", "amazon", "google", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "coinbase", "outlook",
    "office365", "linkedin", "dropbox", "docusign",
}
CREDENTIAL_WORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "billing", "bank", "wallet", "unlock", "suspend", "validate",
}
# Common letter->lookalike swaps used in typosquats.
DIGIT_SWAPS = {"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "rn": "m"}


# ==========================================================================
# URL parsing context
# ==========================================================================
def build_context(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw  # tolerate bare domains
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    reg_domain, subdomain, tld = split_domain(host)
    return {
        "url": raw,
        "scheme": parsed.scheme.lower(),
        "host": host.lower(),
        "port": parsed.port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "registered_domain": reg_domain,
        "subdomain": subdomain,
        "tld": tld,
        "netloc": parsed.netloc.lower(),
    }


def split_domain(host: str) -> tuple[str, str, str]:
    """Return (registered_domain, subdomain, tld). Uses tldextract when
    available for correct multi-part suffixes (.co.uk); naive fallback else."""
    if not host or _is_ip(host):
        return host, "", ""
    if _EXTRACT is not None:
        ext = _EXTRACT(host)
        reg = ".".join(p for p in [ext.domain, ext.suffix] if p)
        return reg, ext.subdomain, ext.suffix
    parts = host.split(".")
    if len(parts) <= 2:
        return host, "", parts[-1] if parts else ""
    return ".".join(parts[-2:]), ".".join(parts[:-2]), parts[-1]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ==========================================================================
# Signal helpers
# ==========================================================================
def signal(label: str, detail: str, weight: int) -> dict[str, Any]:
    return {"label": label, "detail": detail, "weight": weight,
            "severity": severity_for(weight)}


def severity_for(weight: int) -> str:
    if weight >= 25:
        return "crit"
    if weight >= 15:
        return "high"
    if weight >= 8:
        return "med"
    return "low"


# ==========================================================================
# STRUCTURAL checks  (no network)
# ==========================================================================
def chk_no_https(ctx):
    if ctx["scheme"] != "https":
        return [signal("No HTTPS", f"Uses {ctx['scheme']} instead of https", 10)]
    return []


def chk_ip_host(ctx):
    if _is_ip(ctx["host"]):
        return [signal("IP address host", "Link points at a raw IP, not a domain", 20)]
    return []


def chk_at_symbol(ctx):
    before_path = ctx["url"].split(ctx["path"], 1)[0] if ctx["path"] else ctx["url"]
    if "@" in before_path:
        return [signal("'@' in URL", "Everything before '@' is ignored by browsers", 18)]
    return []


def chk_punycode(ctx):
    if "xn--" in ctx["host"]:
        return [signal("Punycode host", "Possible homograph/look-alike domain", 22)]
    return []


def chk_brand_misplacement(ctx):
    reg = ctx["registered_domain"].lower()
    haystack = f"{ctx['subdomain']} {ctx['path']} {ctx['query']}".lower()
    for brand in BRANDS:
        if brand in haystack and brand not in reg:
            return [signal("Misplaced brand name",
                           f"'{brand}' appears outside the real domain", 16)]
    return []


def chk_risky_tld(ctx):
    if ctx["tld"] in RISKY_TLDS:
        return [signal("Risky TLD", f".{ctx['tld']} is heavily abused", 12)]
    return []


def chk_shortener(ctx):
    if ctx["host"] in SHORTENERS:
        return [signal("URL shortener", "Hides the real destination", 10)]
    return []


def chk_excessive_subdomains(ctx):
    depth = len([p for p in ctx["subdomain"].split(".") if p])
    if depth >= 3:
        return [signal("Excessive subdomains", f"{depth} subdomain levels", 8)]
    return []


def chk_credential_keywords(ctx):
    haystack = f"{ctx['host']} {ctx['path']}".lower()
    hits = sorted({w for w in CREDENTIAL_WORDS if w in haystack})
    if hits:
        return [signal("Credential-bait keywords",
                       "Contains: " + ", ".join(hits), 12)]
    return []


def chk_hyphen_digit_swap(ctx):
    reg = ctx["registered_domain"].lower()
    name = reg.split(".")[0] if reg else ""
    deswapped = name
    for digit, letter in DIGIT_SWAPS.items():
        deswapped = deswapped.replace(digit, letter)
    if deswapped != name and any(b in deswapped for b in BRANDS):
        return [signal("Look-alike spelling",
                       "Digit/letter swap mimics a known brand", 14)]
    if name.count("-") >= 2 and any(b in name for b in BRANDS):
        return [signal("Hyphenated brand",
                       "Hyphen-padded brand name is a common typosquat", 14)]
    return []


def chk_explicit_port(ctx):
    if ctx["port"] and ctx["port"] not in (80, 443):
        return [signal("Non-standard port", f"Explicit port :{ctx['port']}", 8)]
    return []


def chk_long_url(ctx):
    if len(ctx["url"]) > 100:
        return [signal("Very long URL", f"{len(ctx['url'])} characters", 6)]
    return []


def chk_heavy_encoding(ctx):
    pct = ctx["url"].count("%")
    if pct > 4:
        return [signal("Heavy encoding", f"{pct} percent-encoded chars", 8)]
    return []


STRUCTURAL_CHECKS: list[Callable] = [
    chk_no_https, chk_ip_host, chk_at_symbol, chk_punycode,
    chk_brand_misplacement, chk_risky_tld, chk_shortener,
    chk_excessive_subdomains, chk_credential_keywords, chk_hyphen_digit_swap,
    chk_explicit_port, chk_long_url, chk_heavy_encoding,
]


# ==========================================================================
# Cached raw lookups  (the only things that touch the network)
# ==========================================================================
@cached_lookup("whois")
def fetch_whois(domain: str):
    if whois_lib is None:
        raise RuntimeError("python-whois not installed")
    return whois_lib.whois(domain)


@cached_lookup("redirects")
def trace_redirects(url: str) -> list[str]:
    if httpx is None:
        raise RuntimeError("httpx not installed")
    hops: list[str] = []
    with httpx.Client(follow_redirects=True, timeout=6.0) as client:
        resp = client.get(url)
        for r in resp.history:
            hops.append(str(r.url))
        hops.append(str(resp.url))
    return hops


@cached_lookup("tls")
def fetch_cert(host: str, port: int = 443) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=6.0) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert()


# ==========================================================================
# NETWORK checks  (call the cached lookups; degrade gracefully)
# ==========================================================================
def chk_domain_age(ctx):
    domain = ctx["registered_domain"]
    if not domain or _is_ip(ctx["host"]):
        return []
    info = fetch_whois(domain)
    created = getattr(info, "creation_date", None)
    if isinstance(created, list):
        created = created[0] if created else None
    if not isinstance(created, dt.datetime):
        return []
    age_days = (dt.datetime.now() - created).days
    if age_days < 30:
        return [signal("Brand-new domain", f"Registered {age_days} days ago", 30)]
    if age_days < 90:
        return [signal("Young domain", f"Registered {age_days} days ago", 15)]
    return []


def chk_redirects(ctx):
    hops = trace_redirects(ctx["url"])
    if len(hops) <= 1:
        return []
    final_host = (urlparse(hops[-1]).hostname or "").lower()
    if final_host and final_host != ctx["host"]:
        return [signal("Off-domain redirect",
                       f"Lands on {final_host} after {len(hops) - 1} hop(s)", 18)]
    return []


def chk_tls(ctx):
    if ctx["scheme"] != "https" or _is_ip(ctx["host"]):
        return []
    try:
        fetch_cert(ctx["host"])
        return []  # valid cert -> no signal
    except ssl.SSLCertVerificationError as e:
        return [signal("TLS cert invalid", str(getattr(e, "verify_message", e)), 20)]


NETWORK_CHECKS: list[Callable] = [chk_domain_age, chk_redirects, chk_tls]


# ==========================================================================
# Runner + scoring
# ==========================================================================
def run_checks(ctx) -> tuple[list[dict], dict[str, str]]:
    """Run all checks. Returns (signals, network_status) where network_status
    reports ok/fail/skip per network check for the dashboard's panel."""
    signals: list[dict] = []
    for check in STRUCTURAL_CHECKS:
        try:
            signals.extend(check(ctx))
        except Exception:
            pass

    net_status = {"whois": "skip", "redirects": "skip", "tls": "skip"}
    net_map = {chk_domain_age: "whois", chk_redirects: "redirects", chk_tls: "tls"}
    for check in NETWORK_CHECKS:
        name = net_map[check]
        try:
            result = check(ctx)
            signals.extend(result)
            net_status[name] = "ok"
        except Exception:
            net_status[name] = "fail"  # lookup couldn't run (offline, timeout)
    return signals, net_status


def verdict_for(score: int) -> tuple[str, str]:
    if score >= 80:
        return "CRITICAL", "crit"
    if score >= 55:
        return "HIGH RISK", "high"
    if score >= 30:
        return "CAUTION", "med"
    return "LOW RISK", "low"


# ==========================================================================
# In-memory scan history  (feeds the dashboard)
# ==========================================================================
_HISTORY: deque[dict] = deque(maxlen=500)
_SCAN_SEQ = 0


def _record(*, kind, target, detail_line, signals, checks, panel_title) -> dict:
    """Record any scan (URL or email) into history. `checks` is the small
    status map shown in the side panel; `panel_title` labels that panel."""
    global _SCAN_SEQ
    _SCAN_SEQ += 1
    score = min(100, sum(s["weight"] for s in signals))
    verdict, sev = verdict_for(score)
    entry = {
        "id": _SCAN_SEQ,
        "kind": kind,                      # "url" | "email"
        "target": target,                  # host or sender address (table column)
        "url": detail_line,                # full URL or "From: … · Subj: …"
        "score": score,
        "verdict": verdict,
        "severity": sev,
        "signals": sorted(signals, key=lambda s: -s["weight"]),
        "checks": checks,                  # {"WHOIS": "OK", …} | {"SPF": "FAIL", …}
        "panel_title": panel_title,        # "Network Checks" | "Sender Authentication"
        "ts": time.time(),
    }
    _HISTORY.appendleft(entry)
    return entry


# ==========================================================================
# FastAPI app
# ==========================================================================
app = FastAPI(title="PhishWatch", version="2.0")

# CORS open for local dev; lock to your front-end origin before deploying.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str


class AnalyzeEmailRequest(BaseModel):
    raw: str


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    ctx = build_context(req.url)
    signals, net_status = run_checks(ctx)
    checks = {
        "WHOIS": net_status["whois"].upper(),
        "REDIRECT": net_status["redirects"].upper(),
        "TLS": net_status["tls"].upper(),
    }
    return _record(kind="url", target=ctx["host"] or ctx["url"],
                   detail_line=ctx["url"], signals=signals,
                   checks=checks, panel_title="Network Checks")


@app.post("/analyze-email")
def analyze_email(req: AnalyzeEmailRequest):
    r = email_analyzer.analyze_email(req.raw)
    return _record(kind="email", target=r["target"], detail_line=r["summary"],
                   signals=r["signals"], checks=r["checks"],
                   panel_title=r["panel_title"])


@app.get("/stats")
def stats():
    """Everything the dashboard needs in one call: KPIs, distribution,
    volume buckets, recent detections, and the latest full verdict."""
    now = time.time()
    day_ago = now - 86_400
    items = list(_HISTORY)

    bands = {"low": 0, "med": 0, "high": 0, "crit": 0}
    for e in items:
        bands[e["severity"]] = bands.get(e["severity"], 0) + 1

    # 12 hourly buckets of scan volume.
    buckets = [0] * 12
    labels = []
    for i in range(12):
        hour_start = now - (11 - i) * 3600
        labels.append(_hour_label(hour_start))
    for e in items:
        hrs_ago = int((now - e["ts"]) // 3600)
        if 0 <= hrs_ago < 12:
            buckets[11 - hrs_ago] += 1

    return {
        "scans_total": len(items),
        "scans_24h": sum(1 for e in items if e["ts"] >= day_ago),
        "flagged": sum(1 for e in items if e["severity"] in ("high", "crit")),
        "critical": sum(1 for e in items if e["severity"] == "crit"),
        "avg_score": round(sum(e["score"] for e in items) / len(items)) if items else 0,
        "distribution": bands,
        "volume": {"buckets": buckets, "labels": labels},
        "recent": [_slim(e) for e in items[:8]],
        "latest": items[0] if items else None,
    }


@app.get("/history")
def history(limit: int = 50):
    return [_slim(e) for e in list(_HISTORY)[:limit]]


@app.get("/cache/stats")
def cache_statistics():
    return cache_stats()


def _slim(e: dict) -> dict:
    return {k: e[k] for k in
            ("id", "target", "score", "verdict", "severity", "ts")}


def _hour_label(ts: float) -> str:
    h = dt.datetime.fromtimestamp(ts).hour
    suffix = "a" if h < 12 else "p"
    h12 = h % 12 or 12
    return f"{h12}{suffix}"


# Serve the dashboard. Mount static AFTER routes so /analyze etc. win.
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")