# PhishWatch — Phishing URL Analyzer + Detection Console

A FastAPI service that scores URLs for phishing risk and a live SIEM-style
dashboard that visualizes the results. Structural checks run instantly;
network checks (WHOIS, redirect chain, TLS) are cached so repeat scans of the
same domain are free.

## Run it

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

<img width="1915" height="947" alt="Screenshot 2026-06-26 184814" src="https://github.com/user-attachments/assets/fc4944e3-9b09-4dd0-a866-0f40350f46c9" />

- Dashboard: <http://127.0.0.1:8000/>
- API docs:  <http://127.0.0.1:8000/docs>

Paste a URL into the bar at the top and hit **Analyze**. The console fills in
as you scan — every panel is driven by real data from the backend.

## Two analysis modes

**URL** — paste a link in the top bar and hit **Analyze**. Runs the 13
structural checks plus the cached network checks (WHOIS / redirect / TLS).

**Email** — click **✉ Email** to paste a full message. Accepts a raw `.eml`
(with headers) or just text copied out of a mail client. Runs the v2 sender
layer: free-webmail impersonation, display-name vs domain mismatch, Reply-To /
Return-Path divergence, homoglyph/look-alike sender domains, SPF/DKIM/DMARC
(read from the `Authentication-Results` header, with a live-DNS fallback for
SPF/DMARC existence), and body signals (generic greeting, urgency,
credential/payment asks, off-platform redirects, self-name typos, consumer
meeting links). Both modes feed the same dashboard, scoring, and history; the
side panel relabels itself (Network Checks ↔ Sender Authentication) per scan.

## Project layout

```
phishwatch/
├── app.py              # FastAPI backend: URL + email routes, scoring, history
├── cache.py            # In-memory TTL cache for the network lookups
├── email_analyzer.py   # v2 sender-analysis engine (header/auth/body checks)
├── requirements.txt
├── README.md
└── static/
    ├── index.html      # Dashboard markup (no inline styles)
    ├── style.css       # All styling — CUSTOMIZE HERE (see top of file)
    └── app.js          # Fetch layer: runs scans, paints the panels
```

## How it fits together

1. **`app.py`** runs two families of checks on each URL:
   - **Structural** (13 rules, no network): no-HTTPS, IP host, `@` trick,
     punycode, misplaced brand, risky TLD, shortener, excessive subdomains,
     credential keywords, look-alike spelling, odd port, long URL, heavy
     encoding.
   - **Network** (cached): domain age (WHOIS), redirect chain (httpx), TLS
     cert validity. Each lives behind `@cached_lookup` in `cache.py`.
   Each check is isolated in a `try/except`, so a slow or failing lookup never
   breaks a scan — it just contributes nothing.
2. Every scan is scored 0–100, assigned a verdict band (Low / Caution / High /
   Critical), and recorded in an in-memory history store.
3. **`/stats`** aggregates that history into everything the dashboard needs —
   KPIs, risk distribution, hourly volume, recent detections, and the latest
   full verdict — in a single call. **`/cache/stats`** feeds the cache panel.
4. **`app.js`** posts scans to `/analyze`, then polls `/stats` and
   `/cache/stats` every 15s and repaints the panels.

## Customizing the look

Open `static/style.css`. Everything you'll normally want to change lives in the
`:root` block at the very top, clearly marked — colors, fonts, panel shape,
spacing, severity palette. Change those values and the whole console re-themes;
you don't need to touch the markup or the JS. There's a note there on flipping
it to a light theme too.

## API reference

| Method | Path            | Purpose                                   |
|--------|-----------------|-------------------------------------------|
| POST   | `/analyze`      | Scan one URL → full verdict + signals     |
| POST   | `/analyze-email`| Scan a full email → sender/auth/body verdict |
| GET    | `/stats`        | Dashboard aggregate (KPIs, charts, recent)|
| GET    | `/history`      | Recent scans (slim form)                  |
| GET    | `/cache/stats`  | Cache hit rate / entries / time saved     |

`POST /analyze` body: `{"url": "https://example.com/login"}`
`POST /analyze-email` body: `{"raw": "From: …\nSubject: …\n\nDear …"}`

## Notes & limits

- **History is in memory.** It resets on restart and isn't shared across
  workers. Swap `_HISTORY` in `app.py` for a SQLite table when you want it to
  persist — the dashboard code won't change.
- **Cache is in memory too.** Same trade-off; see the Redis note at the bottom
  of `cache.py` for the shared/persistent upgrade.
- **CORS is wide open** (`*`) for local dev. Lock it to your front-end origin
  before deploying anywhere real.
- Registered-domain parsing uses `tldextract` when installed (correct for
  multi-part suffixes like `.co.uk`), with a naive fallback otherwise.

## Roadmap — what's done and what's next

The v2 sender-analysis layer (`email_analyzer.py`) is **shipped**: header/sender
checks, SPF/DKIM/DMARC, homoglyph detection, body signals, and a weighted score
that reuses the same bands as the URL engine. See
`phishing_analyzer_v2_spec.md` for the original plan.

Still worth building later:

- **True DKIM verification** — the current code reads DKIM results from the
  `Authentication-Results` header but doesn't verify the signature
  cryptographically from scratch (that needs the selector + public key + body
  hash). A `dkimpy`-based verifier is the clean next step.
- **URL signals inside email bodies** — extract links from an email and run
  them through the existing URL engine, folding those signals into the email
  score (cross-layer scoring).
- **Persistence** — move `_HISTORY` (app.py) and the caches (cache.py) to
  SQLite / Redis so data survives restarts and is shared across workers.
- **Tuning** — weights live in `email_analyzer.py` (`signal(...)` calls) and
  `app.py` (`verdict_for` bands). Adjust if you want, e.g., free-webmail
  impersonation to read HIGH on its own.
