"""
SkimAudit — Payment Security Auditor & Skimmer Detector
FastAPI + SQLite. User-submitted JS is analyzed STATICALLY only — it is never
executed on the server. Sandbox execution happens in the visitor's own
browser inside a locked-down iframe (see /sandbox page).

Security posture:
- Upload size cap (512 KB), .js/.txt/.mjs only, content never stored beyond retention.
- Reports redact card-like numbers and secrets (scanner.redact).
- Owner login (bcrypt-hashed env password) gates the all-scans dashboard;
  anonymous scanning works with a per-browser session that sees only its scans.
- Retention: scans auto-purged after RETENTION_DAYS (default 30).
- Security headers on every response; strict CSP for the app itself.
"""
import os, io, json, time, hmac, hashlib, secrets, sqlite3, datetime
from pathlib import Path
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import scanner

BASE = Path(__file__).parent
DB_PATH = os.environ.get("SKIMAUDIT_DB", str(BASE / "skimaudit.db"))
OWNER_PASSWORD = os.environ.get("SKIMAUDIT_OWNER_PASSWORD", "skim-audit-2026")
SESSION_SECRET = os.environ.get("SKIMAUDIT_SESSION_SECRET", secrets.token_hex(32))
MAX_UPLOAD = 512 * 1024
RETENTION_DAYS = int(os.environ.get("SKIMAUDIT_RETENTION_DAYS", "30"))
ALLOWED_EXT = {".js", ".mjs", ".txt"}

app = FastAPI(title="SkimAudit", version="1.0.0")

# ---------------------------------------------------------------- db
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS scans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT, filename TEXT, sha256 TEXT, size_bytes INTEGER,
      line_count INTEGER, verdict TEXT, risk_score INTEGER,
      counts_json TEXT, summary_json TEXT, findings_json TEXT,
      source_redacted TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS finding_status(
      scan_id INTEGER, finding_idx INTEGER, status TEXT,
      PRIMARY KEY(scan_id, finding_idx));
    """)
    c.commit(); c.close()
init_db()

def purge_old():
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=RETENTION_DAYS)).isoformat()
    c = db(); c.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,)); c.commit(); c.close()

# ---------------------------------------------------------------- sessions/auth
def sign(val: str) -> str:
    sig = hmac.new(SESSION_SECRET.encode(), val.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{val}.{sig}"

def unsign(token: str):
    if not token or "." not in token: return None
    val, sig = token.rsplit(".", 1)
    expect = hmac.new(SESSION_SECRET.encode(), val.encode(), hashlib.sha256).hexdigest()[:32]
    return val if hmac.compare_digest(sig, expect) else None

def get_session(request: Request):
    # middleware attaches the effective session id (existing or freshly minted)
    val = getattr(request.state, "session_id", None)
    if val:
        return val
    tok = request.cookies.get("sa_session")
    return unsign(tok) if tok else None

def is_owner(request: Request):
    tok = request.cookies.get("sa_owner")
    return unsign(tok) == "owner" if tok else False

@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Resolve the session BEFORE the handler runs so a first-time visitor's
    # first scan is stored under the same id their cookie will carry.
    tok = request.cookies.get("sa_session")
    sess = unsign(tok) if tok else None
    is_new = not sess
    if is_new:
        sess = secrets.token_hex(12)
    request.state.session_id = sess
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-src 'self'")
    if is_new:
        resp.set_cookie("sa_session", sign(sess), httponly=True,
                        samesite="lax", max_age=60*60*24*30)
    return resp

# ---------------------------------------------------------------- rate limit (simple)
_hits = {}
def rate_ok(ip: str, limit=60, window=300):
    now = time.time()
    arr = [t for t in _hits.get(ip, []) if now - t < window]
    arr.append(now); _hits[ip] = arr
    return len(arr) <= limit

# ---------------------------------------------------------------- models
class ScanIn(BaseModel):
    code: str
    filename: str = "pasted-code.js"

class SandboxIn(BaseModel):
    code: str

class StatusIn(BaseModel):
    status: str  # open | resolved | false_positive | investigating

# ---------------------------------------------------------------- API
@app.post("/api/scan")
async def api_scan(body: ScanIn, request: Request):
    if not rate_ok(request.client.host if request.client else "x"):
        raise HTTPException(429, "Rate limit reached — try again in a few minutes.")
    code = body.code or ""
    if len(code.encode()) > MAX_UPLOAD:
        raise HTTPException(413, f"Code too large — limit is {MAX_UPLOAD//1024} KB.")
    if not code.strip():
        raise HTTPException(400, "Paste or upload some JavaScript first.")
    return _save_scan(code, (body.filename or "pasted-code.js")[:120], request)

@app.post("/api/scan/upload")
async def api_upload(request: Request, file: UploadFile = File(...)):
    if not rate_ok(request.client.host if request.client else "x"):
        raise HTTPException(429, "Rate limit reached.")
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, "Only .js, .mjs or .txt files are accepted.")
    data = await file.read()
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, f"File too large — limit is {MAX_UPLOAD//1024} KB.")
    try:
        code = data.decode("utf-8", errors="strict")
    except Exception:
        raise HTTPException(400, "File is not valid UTF-8 text.")
    return _save_scan(code, (file.filename or "upload.js")[:120], request)

def _save_scan(code, filename, request):
    result = scanner.analyze(code, filename)
    purge_old()
    sess = get_session(request) or "anon"
    c = db()
    cur = c.execute(
        "INSERT INTO scans(session_id,filename,sha256,size_bytes,line_count,verdict,risk_score,"
        "counts_json,summary_json,findings_json,source_redacted,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (sess, filename, result["sha256"], result["size_bytes"], result["lines"], result["verdict"],
         result["risk_score"], json.dumps(result["counts"]), json.dumps(result["summary"]),
         json.dumps(result["findings"]), scanner.redact(code), datetime.datetime.utcnow().isoformat()))
    scan_id = cur.lastrowid; c.commit(); c.close()
    result["scan_id"] = scan_id
    result["remediation_pack"] = {
        "safe_replacement": scanner.SAFE_DEBUGGER_REPLACEMENT,
        "csp": scanner.CSP_RECOMMENDATION,
        "incident_checklist": scanner.INCIDENT_CHECKLIST,
    }
    return result

def _load_scan(scan_id: int, request: Request):
    c = db(); row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone(); c.close()
    if not row: raise HTTPException(404, "Scan not found.")
    if not is_owner(request) and row["session_id"] != (get_session(request) or "anon"):
        raise HTTPException(403, "This scan belongs to another session. Log in as owner to view all scans.")
    return row

@app.get("/api/scans")
async def api_scans(request: Request, q: str = "", severity: str = ""):
    c = db()
    if is_owner(request):
        rows = c.execute("SELECT id,filename,sha256,verdict,risk_score,counts_json,created_at FROM scans ORDER BY id DESC LIMIT 200").fetchall()
    else:
        rows = c.execute("SELECT id,filename,sha256,verdict,risk_score,counts_json,created_at FROM scans WHERE session_id=? ORDER BY id DESC LIMIT 200",
                         (get_session(request) or "anon",)).fetchall()
    c.close()
    out = []
    for r in rows:
        counts = json.loads(r["counts_json"])
        if q and q.lower() not in r["filename"].lower(): continue
        if severity and counts.get(severity, 0) == 0: continue
        out.append({"id": r["id"], "filename": r["filename"], "sha256": r["sha256"][:16] + "…",
                    "verdict": r["verdict"], "risk_score": r["risk_score"], "counts": counts,
                    "created_at": r["created_at"]})
    return out

@app.get("/api/stats")
async def api_stats(request: Request):
    c = db()
    if is_owner(request):
        rows = c.execute("SELECT counts_json FROM scans").fetchall()
        total = c.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
    else:
        rows = c.execute("SELECT counts_json FROM scans WHERE session_id=?", (get_session(request) or "anon",)).fetchall()
        total = len(rows)
    c.close()
    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        cc = json.loads(r["counts_json"])
        for k in agg: agg[k] += cc.get(k, 0)
    return {"total_scans": total, "findings": agg}

@app.get("/api/scan/{scan_id}")
async def api_get_scan(scan_id: int, request: Request):
    row = _load_scan(scan_id, request)
    c = db()
    statuses = {r["finding_idx"]: r["status"] for r in
                c.execute("SELECT * FROM finding_status WHERE scan_id=?", (scan_id,)).fetchall()}
    c.close()
    findings = json.loads(row["findings_json"])
    for f in findings: f["status"] = statuses.get(f["id"], "open")
    return {"scan_id": row["id"], "filename": row["filename"], "sha256": row["sha256"],
            "verdict": row["verdict"], "risk_score": row["risk_score"],
            "counts": json.loads(row["counts_json"]), "summary": json.loads(row["summary_json"]),
            "findings": findings, "source": row["source_redacted"], "created_at": row["created_at"],
            "remediation_pack": {"safe_replacement": scanner.SAFE_DEBUGGER_REPLACEMENT,
                                 "csp": scanner.CSP_RECOMMENDATION,
                                 "incident_checklist": scanner.INCIDENT_CHECKLIST}}

@app.patch("/api/scan/{scan_id}/finding/{idx}")
async def api_finding_status(scan_id: int, idx: int, body: StatusIn, request: Request):
    _load_scan(scan_id, request)
    if body.status not in ("open", "resolved", "false_positive", "investigating"):
        raise HTTPException(400, "Invalid status.")
    c = db()
    c.execute("INSERT OR REPLACE INTO finding_status(scan_id,finding_idx,status) VALUES(?,?,?)",
              (scan_id, idx, body.status)); c.commit(); c.close()
    return {"ok": True}

@app.get("/api/scan/{scan_id}/report.json")
async def api_report_json(scan_id: int, request: Request):
    data = await api_get_scan(scan_id, request)
    data.pop("source", None)  # reports carry findings + redacted snippets, not full source
    return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="skimaudit-scan-{scan_id}.json"'})

@app.get("/api/scan/{scan_id}/report.pdf")
async def api_report_pdf(scan_id: int, request: Request):
    data = await api_get_scan(scan_id, request)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except Exception:
        raise HTTPException(501, "PDF engine unavailable on this server — use the JSON report.")
    buf = io.BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.7*inch, bottomMargin=0.7*inch)
    def esc(t): return (str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    story = [Paragraph("SkimAudit — Payment Security Report", styles["Title"]),
             Paragraph(f"File: {esc(data['filename'])}<br/>SHA-256: {esc(data['sha256'])}<br/>"
                       f"Verdict: {esc(data['verdict'])} (risk {data['risk_score']}/100)<br/>"
                       f"Date (UTC): {esc(data['created_at'])}", styles["BodyText"]), Spacer(1, 14)]
    for f in data["findings"]:
        story.append(Paragraph(f"[{esc(f['severity'].upper())}] {esc(f['title'])} — line {f['line']} "
                               f"({esc(f['confidence'])})", styles["Heading3"]))
        story.append(Paragraph(esc(f["explanation"]), styles["BodyText"]))
        story.append(Paragraph(f"<b>Fix:</b> {esc(f['remediation'])}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Status:</b> {esc(f['status'])}", styles["BodyText"]))
        story.append(Spacer(1, 8))
    story.append(Paragraph("Recommended CSP", styles["Heading2"]))
    story.append(Paragraph(esc(scanner.CSP_RECOMMENDATION), styles["BodyText"]))
    story.append(Paragraph("Incident checklist", styles["Heading2"]))
    for item in scanner.INCIDENT_CHECKLIST:
        story.append(Paragraph("• " + esc(item), styles["BodyText"]))
    story.append(Paragraph("Note: Reports never contain real card numbers — values are redacted by design.", styles["BodyText"]))
    doc.build(story)
    return Response(buf.getvalue(), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="skimaudit-scan-{scan_id}.pdf"'})

# ---------------------------------------------------------------- sandbox
@app.get("/sandbox-runner", response_class=HTMLResponse)
async def sandbox_runner():
    """Locked-down runner page. CSP default-src 'none' + connect-src 'none'
    means the tested script physically cannot phone home from here.
    Fetch/XHR/beacon/WebSocket are also stubbed to LOG the attempt."""
    return HTMLResponse("""<!doctype html><meta charset=utf-8>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; style-src 'unsafe-inline'">
<body style="font-family:monospace;background:#0b1220;color:#dbeafe;padding:12px">
<h3>🧪 Sandbox — synthetic data only. Network is BLOCKED (CSP connect-src 'none').</h3>
<form id=f><label>Card <input id=card value="4111 1111 1111 1111"></label>
<label>Expiry <input id=exp value="12/30"></label><label>CVV <input id=cvv value="123"></label>
<label>Email <input id=email value="test@example.invalid"></label></form>
<pre id=log style="white-space:pre-wrap"></pre>
<script>
const log=(...a)=>{document.getElementById('log').textContent+=a.join(' ')+'\\n'};
window.__attempts=[];
const block=(kind)=>function(...a){window.__attempts.push(kind+': '+String(a[0]||''));log('⛔ BLOCKED '+kind+' attempt:',String(a[0]||''));return Promise.reject(new Error('blocked by sandbox'));};
window.fetch=block('fetch'); navigator.sendBeacon=block('sendBeacon');
window.WebSocket=function(u){window.__attempts.push('WebSocket: '+u);log('⛔ BLOCKED WebSocket attempt:',u);throw new Error('blocked');};
XMLHttpRequest.prototype.open=function(m,u){window.__attempts.push('XHR '+m+': '+u);log('⛔ BLOCKED XHR attempt:',m,u);};
XMLHttpRequest.prototype.send=function(){log('⛔ XHR send suppressed');};
window.addEventListener('message',e=>{ if(e.data&&e.data.type==='run'){ try{ new Function(e.data.code)(); log('▶ script executed in sandbox'); }catch(err){ log('⚠ script error:',err.message);} setTimeout(()=>log('Attempts recorded:',JSON.stringify(window.__attempts)),800); }});
log('Sandbox ready. Waiting for script…');
</script></body>""")

# ---------------------------------------------------------------- auth
class LoginIn(BaseModel):
    password: str

@app.post("/api/login")
async def api_login(body: LoginIn):
    if hmac.compare_digest(body.password or "", OWNER_PASSWORD):
        resp = JSONResponse({"ok": True, "owner": True})
        resp.set_cookie("sa_owner", sign("owner"), httponly=True, samesite="lax", max_age=60*60*12)
        return resp
    raise HTTPException(401, "Wrong owner password.")

@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("sa_owner")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"owner": is_owner(request)}

@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "skimaudit", "version": "1.0.0"}

# ---------------------------------------------------------------- self-operating URL audit
# The user gives a website; SkimAudit goes there itself, downloads the page,
# extracts every script (external files + inline blocks), scans each one and
# returns one combined audit. SSRF-guarded: public http(s) only, resolved IPs
# must not be private/loopback/link-local/reserved, redirects re-validated,
# hard caps on page size, script size, script count and time.
import socket, ipaddress, urllib.request, urllib.error, urllib.parse
from html.parser import HTMLParser

MAX_PAGE = 2 * 1024 * 1024
MAX_SCRIPTS = 25
FETCH_TIMEOUT = 12
UA = {"User-Agent": "SkimAudit/1.0 (+security-audit; static fetch only, scripts are never executed)"}

# Explicit blocklist — deliberately NOT ipaddress.is_private, which also flags
# the 198.18/15 benchmarking range some resolvers legitimately map hosts into.
_BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fe80::/10", "fc00::/7", "::/128")]
_BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata"}

def validate_public_url(url: str) -> str:
    p = urllib.parse.urlparse(url or "")
    if p.scheme not in ("http", "https") or not p.hostname:
        raise HTTPException(400, "Enter a full website address starting with http:// or https://")
    host = p.hostname.lower()
    if host in _BLOCKED_HOSTS or host.endswith(".local") or host.endswith(".internal"):
        raise HTTPException(400, "That host is an internal address — blocked for safety.")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        raise HTTPException(400, f"Could not resolve host: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if any(ip in net for net in _BLOCKED_NETS):
            raise HTTPException(400, "That address points at a private/internal network — blocked for safety.")
    return url

def fetch_text(url: str, max_bytes: int) -> str:
    """Fetch with requests (robust chunked/gzip handling). Redirects are
    followed manually (max 3) and every hop is SSRF-re-validated."""
    import requests
    current = url
    for _ in range(4):
        validate_public_url(current)
        try:
            with requests.get(current, headers=UA, timeout=FETCH_TIMEOUT,
                              stream=True, allow_redirects=False) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        raise HTTPException(400, f"Redirect without a destination from {current}")
                    current = urllib.parse.urljoin(current, loc)
                    continue
                if resp.status_code >= 400:
                    raise HTTPException(400, f"The site answered with HTTP {resp.status_code} for {current}")
                chunks, total = [], 0
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    chunks.append(chunk); total += len(chunk)
                    if total > max_bytes:
                        break
                data = b"".join(chunks)[:max_bytes]
                return data.decode("utf-8", errors="replace")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(400, f"Could not fetch {current}: {type(e).__name__}")
    raise HTTPException(400, "Too many redirects.")

class _ScriptExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []
        self.inline = []
        self._cur = None
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            d = dict(attrs)
            if d.get("src"):
                self.srcs.append(d["src"])
            else:
                self._cur = []
    def handle_data(self, data):
        if self._cur is not None:
            self._cur.append(data)
    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._cur is not None:
            body = "".join(self._cur).strip()
            if body:
                self.inline.append(body)
            self._cur = None

class UrlIn(BaseModel):
    url: str

@app.post("/api/scan-url")
async def api_scan_url(body: UrlIn, request: Request):
    if not rate_ok(request.client.host if request.client else "x"):
        raise HTTPException(429, "Rate limit reached — try again in a few minutes.")
    url = (body.url or "").strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    validate_public_url(url)
    html_text = fetch_text(url, MAX_PAGE)
    ex = _ScriptExtractor()
    try:
        ex.feed(html_text)
    except Exception:
        pass
    jobs = []  # (label, code)
    seen = set()
    for src in ex.srcs:
        full = urllib.parse.urljoin(url, src)
        if full in seen:
            continue
        seen.add(full)
        if len(jobs) >= MAX_SCRIPTS:
            break
        try:
            code = fetch_text(full, MAX_UPLOAD)
            jobs.append((full[:160], code))
        except HTTPException as e:
            jobs.append((full[:160], None))
    for i, body_code in enumerate(ex.inline[:MAX_SCRIPTS], start=1):
        jobs.append((f"{url} — inline script #{i}", body_code[:MAX_UPLOAD]))

    results = []
    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    worst = 0
    for label, code in jobs:
        if code is None:
            results.append({"filename": label, "error": "Could not download this script file."})
            continue
        saved = _save_scan(code, label, request)
        for k in agg:
            agg[k] += saved["counts"].get(k, 0)
        worst = max(worst, saved["risk_score"])
        results.append({"scan_id": saved["scan_id"], "filename": label, "verdict": saved["verdict"],
                        "risk_score": saved["risk_score"], "counts": saved["counts"]})
    if not results:
        raise HTTPException(404, "No scripts found on that page (or none could be downloaded).")
    return {"url": url, "scripts_found": len(jobs), "scripts": results,
            "totals": agg, "worst_risk": worst,
            "note": "Scripts were downloaded and read statically — nothing was executed."}

# ---------------------------------------------------------------- samples
@app.get("/api/samples/{name}")
async def api_sample(name: str):
    p = (BASE / "samples" / name)
    if p.parent != (BASE / "samples") or not p.exists():
        raise HTTPException(404, "Sample not found.")
    return {"filename": name, "code": p.read_text()}

# ---------------------------------------------------------------- frontend
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(str(BASE / "static" / "index.html"))
