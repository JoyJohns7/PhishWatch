"""
email_analyzer.py - v2 sender-analysis engine for PhishWatch
============================================================

Lifts detection from the URL up to the whole email - the layer where most
phishing actually announces itself (the sender, not the link). Mirrors the URL
analyzer's design: independent checks that each return signals shaped exactly
like app.py's  {"label", "detail", "weight", "severity"}  so the existing
dashboard, scoring, and history work unchanged.

What it inspects
----------------
  Sender / headers : From display-name vs address-domain mismatch, free-webmail
                     impersonation, Reply-To / Return-Path divergence.
  Authentication   : SPF / DKIM / DMARC - read from the Authentication-Results
                     header when present; live DNS existence check as a fallback
                     (optional, needs dnspython + network).
  Look-alike       : punycode / homoglyph / edit-distance sender domains.
  Body content     : generic greeting, urgency, credential/payment asks,
                     off-platform redirection, self-name (legal-suffix) typos,
                     consumer meeting links posing as official.

Input is forgiving: it parses a real RFC822 / .eml message, and also falls back
to best-effort extraction from text pasted out of a mail client (the realistic
"I pasted what I saw in Gmail" case).
"""

from __future__ import annotations

import email
import re
from email import policy
from email.utils import getaddresses, parseaddr
from typing import Any

# Optional: live DNS fallback for SPF/DMARC existence when the email carries no
# Authentication-Results header. Degrades gracefully if unavailable/offline.
try:
    import dns.resolver  # dnspython
except Exception:  # pragma: no cover
    dns = None


# ==========================================================================
# Reference data
# ==========================================================================
FREE_WEBMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "zoho.com",
    "yandex.com", "yandex.ru", "mail.ru", "mail.com", "daum.net", "naver.com",
    "hanmail.net", "163.com", "126.com", "qq.com", "tutanota.com",
}
BRANDS = {
    "paypal", "microsoft", "apple", "amazon", "google", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "coinbase", "outlook",
    "office365", "linkedin", "dropbox", "docusign", "fedex", "ups", "dhl",
}
CORPORATE_TOKENS = re.compile(
    r"\b(inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|"
    r"plc|gmbh|therapeutics|pharma|pharmaceuticals|bank|financial|capital|"
    r"solutions|systems|technologies|group|holdings|services|labs|"
    r"recruiting|talent|hr|support|team)\b", re.I)
SUFFIX_TYPOS = re.compile(r"\b(lnc|l\.n\.c|incc|ll\.c|l\.l\.c\.c|iinc)\b", re.I)
GENERIC_GREETINGS = re.compile(
    r"\bdear\s+(applicant|candidate|customer|user|member|account\s*holder|"
    r"sir\s*/?\s*madam|valued\s+customer|client)\b", re.I)
URGENCY = re.compile(
    r"\b(immediately|urgent(ly)?|right\s+away|within\s+\d+\s*(hours?|hrs?|"
    r"minutes?)|act\s+now|as\s+soon\s+as\s+possible|asap|expire[sd]?|"
    r"suspend(ed|ing)?|deactivat|final\s+notice|last\s+chance)\b", re.I)
CRED_PAYMENT = re.compile(
    r"\b(social\s+security|ssn|bank\s+account|routing\s+number|account\s+number|"
    r"direct\s+deposit|wire\s+transfer|gift\s+card|bitcoin|crypto|"
    r"reimburs(e|ed|ement)|equipment\s+(fee|cost|purchase)|processing\s+fee|"
    r"credit\s+card\s+number|debit\s+card|paypal\s+me)\b", re.I)
OFF_PLATFORM = re.compile(
    r"\b(whatsapp|telegram|signal\s+app|wechat|text\s+me\s+at|"
    r"contact\s+me\s+(at|on)\s+\+?\d|personal\s+(email|cell|number))\b", re.I)
CONSUMER_MEETING = re.compile(
    r"(teams\.live\.com|meet\.google\.com/[a-z-]+\?|zoom\.us/j/\d+\?pwd)", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")


# ==========================================================================
# Signal helper (matches app.py's shape)
# ==========================================================================
def signal(label: str, detail: str, weight: int) -> dict[str, Any]:
    return {"label": label, "detail": detail, "weight": weight,
            "severity": _severity(weight)}


def _severity(weight: int) -> str:
    if weight >= 25:
        return "crit"
    if weight >= 15:
        return "high"
    if weight >= 8:
        return "med"
    return "low"


def _domain_of(addr: str) -> str:
    return addr.split("@", 1)[1].lower().strip() if "@" in addr else ""


def _alpha_core(text: str) -> str:
    return re.sub(r"[^a-z]", "", (text or "").lower())


# ==========================================================================
# Parsing  (RFC822 with a best-effort fallback for pasted client text)
# ==========================================================================
def parse_email(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    msg = None
    try:
        msg = email.message_from_string(raw, policy=policy.default)
    except Exception:
        msg = None

    from_name, from_addr = "", ""
    if msg is not None and msg["From"]:
        from_name, from_addr = parseaddr(str(msg["From"]))

    # Fallback: no real From header (text pasted out of a mail client).
    heuristic = False
    if not from_addr:
        heuristic = True
        from_name, from_addr = _heuristic_sender(raw)

    reply_to = _first_domain(msg, "Reply-To") if msg else ""
    return_path = _first_domain(msg, "Return-Path") if msg else ""
    subject = str(msg["Subject"]) if (msg and msg["Subject"]) else _heuristic_subject(raw)
    auth_raw = str(msg["Authentication-Results"]) if (msg and msg["Authentication-Results"]) else ""
    received = msg.get_all("Received", []) if msg else []
    body = _extract_body(msg) if (msg is not None and not heuristic) else raw

    return {
        "from_name": from_name or "",
        "from_addr": from_addr.lower(),
        "from_domain": _domain_of(from_addr),
        "reply_to_domain": reply_to,
        "return_path_domain": return_path,
        "subject": subject or "",
        "auth_raw": auth_raw,
        "received": received,
        "body": body or "",
        "heuristic": heuristic,
    }


def _heuristic_sender(raw: str) -> tuple[str, str]:
    head = "\n".join(raw.splitlines()[:6])  # sender usually near the top
    m = EMAIL_RE.search(head) or EMAIL_RE.search(raw)
    if not m:
        return "", ""
    addr = m.group(0)
    line = next((ln for ln in raw.splitlines() if addr in ln), "")
    name = line.replace(addr, "").replace("<", "").replace(">", "").strip(" \t-")
    return name, addr


def _heuristic_subject(raw: str) -> str:
    m = re.search(r"^\s*subject\s*:\s*(.+)$", raw, re.I | re.M)
    return m.group(1).strip() if m else ""


def _first_domain(msg, header: str) -> str:
    if not msg or not msg[header]:
        return ""
    pairs = getaddresses([str(msg[header])])
    return _domain_of(pairs[0][1]) if pairs and pairs[0][1] else ""


def _extract_body(msg) -> str:
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
        if part is not None:
            return part.get_content()
    except Exception:
        pass
    try:
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode(errors="replace")
        return str(msg.get_payload())
    except Exception:
        return ""


# ==========================================================================
# Authentication-Results  ->  {SPF, DKIM, DMARC}
# ==========================================================================
def parse_auth(p: dict) -> dict[str, str]:
    """Return display statuses for the dashboard panel: PASS / FAIL / NONE /
    N/A. Reads the Authentication-Results header first; falls back to a live
    DNS existence check for SPF/DMARC when available."""
    raw = p["auth_raw"]
    out = {"SPF": "N/A", "DKIM": "N/A", "DMARC": "N/A"}
    if raw:
        for key, mech in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
            m = re.search(rf"\b{mech}\s*=\s*(\w+)", raw, re.I)
            if m:
                out[key] = m.group(1).upper()
        return out

    # No header - try live DNS for whether the domain even publishes SPF/DMARC.
    domain = p["from_domain"]
    if dns is not None and domain:
        out["SPF"] = "PASS" if _dns_has(domain, "v=spf1") else "NONE"
        out["DMARC"] = "PASS" if _dns_has(f"_dmarc.{domain}", "v=DMARC1") else "NONE"
        # DKIM needs the selector + signature crypto; can't verify from DNS alone.
        out["DKIM"] = "N/A"
    return out


def _dns_has(name: str, marker: str) -> bool:
    try:
        for rec in dns.resolver.resolve(name, "TXT"):
            if marker.lower() in rec.to_text().lower():
                return True
    except Exception:
        return False
    return False


# ==========================================================================
# CHECKS  (each returns a list of weighted signals)
# ==========================================================================
def chk_free_webmail(p):
    dom = p["from_domain"]
    if dom in FREE_WEBMAIL:
        name_core = _alpha_core(p["from_name"])
        provider_core = _alpha_core(dom.split(".")[0])
        claims_identity = bool(p["from_name"]) and name_core != provider_core
        if claims_identity:
            return [signal("Free-webmail impersonation",
                           f"'{p['from_name']}' sent from free webmail ({dom})", 26)]
        return [signal("Free-webmail sender",
                       f"Sent from {dom}, not a corporate domain", 12)]
    return []


def chk_name_domain_mismatch(p):
    name = p["from_name"]
    dom = p["from_domain"]
    if not name or not dom:
        return []
    # Known brand named in the display but not in the sending domain.
    for brand in BRANDS:
        if brand in name.lower() and brand not in dom:
            return [signal("Display-name brand mismatch",
                           f"Name says '{brand}' but domain is {dom}", 16)]
    # Display name asserts a corporate identity its free-webmail domain can't back.
    if CORPORATE_TOKENS.search(name) and dom in FREE_WEBMAIL:
        return [signal("Name/domain mismatch",
                       f"Corporate name '{name}' on free webmail {dom}", 16)]
    return []


def chk_reply_divergence(p):
    out = []
    dom = p["from_domain"]
    if p["reply_to_domain"] and p["reply_to_domain"] != dom:
        out.append(signal("Reply-To divergence",
                          f"Replies go to {p['reply_to_domain']}, not {dom}", 14))
    if p["return_path_domain"] and p["return_path_domain"] != dom:
        out.append(signal("Return-Path divergence",
                          f"Bounce path {p['return_path_domain']} != {dom}", 10))
    return out


def chk_auth_signals(p, auth):
    out = []
    if auth["DMARC"] == "FAIL":
        out.append(signal("DMARC failed", "Sender failed DMARC alignment", 22))
    if auth["SPF"] == "FAIL":
        out.append(signal("SPF failed", "Sending server not authorized (SPF)", 18))
    if auth["DKIM"] == "FAIL":
        out.append(signal("DKIM failed", "Message signature did not verify", 12))
    return out


def chk_homoglyph_sender(p):
    dom = p["from_domain"]
    if not dom:
        return []
    if "xn--" in dom:
        return [signal("Punycode sender domain",
                       "Possible homograph/look-alike sender", 22)]
    if re.search(r"[^\x00-\x7f]", dom):
        return [signal("Non-ASCII sender domain", "Mixed-script look-alike risk", 22)]
    core = dom.split(".")[0]
    for brand in BRANDS:
        d = _edit_distance(core, brand)
        if 0 < d <= 2 and core != brand:
            return [signal("Look-alike sender domain",
                           f"'{core}' is one/two edits from '{brand}'", 20)]
    return []


def chk_generic_greeting(p):
    if GENERIC_GREETINGS.search(p["body"]):
        return [signal("Generic greeting",
                       "Impersonal 'Dear <role>' with no real name", 8)]
    return []


def chk_urgency(p):
    if URGENCY.search(p["body"]):
        return [signal("Urgency / pressure", "Pushes a fast, fearful action", 8)]
    return []


def chk_cred_payment(p):
    if CRED_PAYMENT.search(p["body"]):
        return [signal("Credential / payment request",
                       "Asks for sensitive data or money", 20)]
    return []


def chk_off_platform(p):
    if OFF_PLATFORM.search(p["body"]):
        return [signal("Off-platform redirect",
                       "Pushes the chat to WhatsApp/Telegram/personal contact", 12)]
    return []


def chk_suffix_typo(p):
    blob = f"{p['from_name']} {p['subject']} {p['body']}"
    if SUFFIX_TYPOS.search(blob):
        return [signal("Self-name typo",
                       "Misspells its own legal suffix (e.g., 'LNC')", 6)]
    return []


def chk_consumer_meeting(p):
    if CONSUMER_MEETING.search(p["body"]):
        return [signal("Consumer meeting link",
                       "Personal Teams/Zoom/Meet link posed as official", 8)]
    return []


SENDER_CHECKS = [
    chk_free_webmail, chk_name_domain_mismatch, chk_reply_divergence,
    chk_homoglyph_sender,
]
BODY_CHECKS = [
    chk_generic_greeting, chk_urgency, chk_cred_payment, chk_off_platform,
    chk_suffix_typo, chk_consumer_meeting,
]


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ==========================================================================
# Top-level analyze
# ==========================================================================
def analyze_email(raw: str) -> dict[str, Any]:
    """Parse + run all checks. Returns the pieces app.py needs to record a
    scan: signals, the SPF/DKIM/DMARC panel, a display target, and a summary."""
    p = parse_email(raw)
    auth = parse_auth(p)

    signals: list[dict] = []
    for check in SENDER_CHECKS:
        try:
            signals.extend(check(p))
        except Exception:
            pass
    try:
        signals.extend(chk_auth_signals(p, auth))
    except Exception:
        pass
    for check in BODY_CHECKS:
        try:
            signals.extend(check(p))
        except Exception:
            pass

    target = p["from_addr"] or "(unknown sender)"
    subj = (p["subject"][:60] + "…") if len(p["subject"]) > 60 else p["subject"]
    summary = f"From: {p['from_name']} <{p['from_addr']}>"
    if subj:
        summary += f" · Subj: {subj}"

    return {
        "signals": signals,
        "checks": auth,                 # {SPF, DKIM, DMARC} for the panel
        "panel_title": "Sender Authentication",
        "target": target,
        "summary": summary,
        "parsed": {k: p[k] for k in ("from_name", "from_domain", "heuristic")},
    }