# SkimAudit — Payment Security Auditor & Skimmer Detector

A production-ready web app that statically analyzes JavaScript for payment-card
skimming (Magecart-style) behavior: document-wide input monitoring, payment-field
discovery, keystroke buffering, storage staging, commented-out exfiltration, and
live network exfiltration paths — with severity-rated findings, line-accurate
explanations, safe replacements, CSP guidance, and an incident-response checklist.

**Honesty by design:** the analyzer distinguishes *confirmed* executable behavior
from *suspicious indicators*. Commented-out network code is reported as an
indicator and is never claimed to have transmitted anything. A plain `fetch()`
with no sensitive data flow is medium/review — never critical.

## What it does
- **Scanner** — paste code or upload `.js/.mjs/.txt` (512 KB cap). Rules cover:
  document/window input & key listeners, payment selectors, form harvesting,
  `.value` collection, keylog buffers, clipboard hooks, localStorage/cookie
  staging, console logging of values, fetch/XHR/sendBeacon/WebSocket/Image
  beacons, dynamic script loading, eval/Function, `_0x` obfuscation, base64
  payloads, card-shape regexes, unsafe `window.*` globals, missing listener
  cleanup, and deceptive "debugger" naming vs. actual behavior. A simple taint
  pass tracks variables assigned from `.value` and escalates network findings
  to **critical** only when collected data can actually flow to the send.
- **Dashboard** — totals + critical/high/medium/low counts, scan history with
  search & severity filter, per-finding status (open / investigating /
  resolved / false_positive).
- **Reports** — downloadable JSON and PDF. Card-like numbers and secrets are
  redacted; full source is never included in JSON reports.
- **Sandbox** — runs suspect code only in the visitor's browser inside a
  locked iframe: CSP `connect-src 'none'`, fetch/XHR/beacon/WebSocket stubbed
  and logged, synthetic test card `4111 1111 1111 1111`. The server NEVER
  executes submitted JavaScript.
- **Remediation assistant** — a safe scoped-debugger replacement (explicit
  payment/password field guard, metadata-only logging, proper cleanup), a
  recommended CSP, and a PCI-style incident checklist.
- **Auth** — anonymous sessions see only their own scans; the owner password
  (`SKIMAUDIT_OWNER_PASSWORD`) unlocks all scans. Signed, httponly cookies.
- **Privacy** — scans auto-purge after `SKIMAUDIT_RETENTION_DAYS` (default 30).
  No payment data is collected by this tool — inputs are code, and outputs redact.

## Run locally
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
SKIMAUDIT_OWNER_PASSWORD='choose-a-strong-one' .venv/bin/uvicorn app:app --port 8000
# open http://127.0.0.1:8000
```

## Tests
```bash
.venv/bin/python -m pytest tests/ -q
```
Covers: skimmer sample → critical + deceptive-debugger; commented exfil →
indicator (not a confirmed transmission); safe script → no critical findings;
plain fetch alone → not critical; redaction; finding completeness.

## Deploy to Render (same pattern as Drop / HERE / Order Up)
1. Push this folder to a GitHub repo (public is fine — no secrets in code).
2. Render → **New → Blueprint** → connect the repo. `render.yaml` provisions a
   Starter web service (~$7/mo) with a 1 GB persistent disk at `/data`.
3. Set the env var **`SKIMAUDIT_OWNER_PASSWORD`** when prompted (sync: false).
   `SKIMAUDIT_SESSION_SECRET` is auto-generated; the DB lives on the disk.
4. Deploy. Health check: `GET /healthz` → `{"ok": true}`.

## Limits (stated, not hidden)
- Static analysis proves code paths exist; it cannot prove a transmission
  already occurred on a live site — pair with server-log review, CSP,
  Subresource Integrity, and file-integrity monitoring.
- The taint pass is intentionally simple (variable-level, single file). It
  escalates only on evidence and downgrades accusations it cannot support.
- PDF export needs `reportlab` (in requirements); if unavailable, JSON export
  still works and the API says so.
