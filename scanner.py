"""
SkimAudit — Payment Security Auditor & Skimmer Detector
Static analysis engine for JavaScript.

Design principles (per spec):
- NEVER claim a script transmitted data unless executable (non-comment) code
  actually contains a network call AND (ideally) tainted data reaches it.
- Commented-out network code is reported separately as a *suspicious indicator*.
- Findings are typed: "confirmed" (executable behavior), "indicator"
  (suspicious pattern), "potential" (risk pattern, context-dependent).
- Sensitive values are redacted everywhere (card-like digit runs).
"""
import re
import hashlib

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------- redaction
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]")

def redact(text: str) -> str:
    if text is None:
        return ""
    text = _CARD_RE.sub("****-REDACTED-CARD-****", str(text))
    text = _SECRET_RE.sub(lambda m: m.group(0).split("=")[0].split(":")[0] + "= '****REDACTED****'", text)
    return text

# ---------------------------------------------------------------- comment handling
def split_comments(code: str):
    """Return (executable_code_with_comments_blanked, comments_list).
    comments_list: [{line, text}] preserving line numbers. Executable code
    keeps line alignment by blanking comment chars with spaces."""
    lines = code.split("\n")
    out_lines = []
    comments = []
    in_block = False
    for i, line in enumerate(lines, start=1):
        res = ""
        j = 0
        in_str = None
        while j < len(line):
            if in_block:
                end = line.find("*/", j)
                if end == -1:
                    comments.append({"line": i, "text": line[j:]})
                    res += " " * (len(line) - j)
                    j = len(line)
                else:
                    comments.append({"line": i, "text": line[j:end]})
                    res += " " * (end + 2 - j)
                    j = end + 2
                    in_block = False
                continue
            ch = line[j]
            if in_str:
                res += ch
                if ch == "\\":
                    if j + 1 < len(line):
                        res += line[j + 1]; j += 2; continue
                elif ch == in_str:
                    in_str = None
                j += 1; continue
            if ch in ("'", '"', "`"):
                in_str = ch; res += ch; j += 1; continue
            if line.startswith("//", j):
                comments.append({"line": i, "text": line[j + 2:]})
                res += " " * (len(line) - j)
                j = len(line); continue
            if line.startswith("/*", j):
                in_block = True; continue
            res += ch; j += 1
        out_lines.append(res)
    return "\n".join(out_lines), comments

# ---------------------------------------------------------------- patterns
SENSITIVE_IDENT = re.compile(
    r"(?i)(card|cc[_-]?(num|number|no)|credit|debit|cvv|cvc|cid|expir|exp[_-]?(date|month|year|mm|yy)|"
    r"billing|ccname|cardholder|pan\b|track[12]\b)")
PAYMENT_SELECTOR = re.compile(
    r"(?i)(querySelector(?:All)?|getElementById|getElementsBy(?:Name|ClassName))\s*\(\s*['\"][^'\"]*"
    r"(card|cc|cvv|cvc|expir|billing|checkout|payment)[^'\"]*['\"]")
NET_CALLS = [
    ("fetch", re.compile(r"\bfetch\s*\(")),
    ("XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b|\.open\s*\(\s*['\"](?:POST|GET|PUT)")),
    ("sendBeacon", re.compile(r"\bsendBeacon\s*\(")),
    ("WebSocket", re.compile(r"\bnew\s+WebSocket\s*\(")),
    ("Image beacon", re.compile(r"\bnew\s+Image\s*\(|Image\s*\(\s*\)\s*;?\s*\w*\.src\s*=")),
    ("axios", re.compile(r"\baxios\.(?:post|get|put)\s*\(")),
]
DOC_LISTENER = re.compile(
    r"\b(document|window)\s*\.\s*addEventListener\s*\(\s*['\"](input|keydown|keyup|keypress|change|paste|copy|submit)['\"]")
ANY_LISTENER = re.compile(r"addEventListener\s*\(\s*['\"](\w+)['\"]")
CLIPBOARD = re.compile(r"(?i)(navigator\.clipboard|execCommand\s*\(\s*['\"]copy|addEventListener\s*\(\s*['\"](?:copy|paste))")
STORAGE = re.compile(r"\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(|document\.cookie\s*=")
CONSOLE_LOG = re.compile(r"\bconsole\.(log|debug|info|warn)\s*\(")
FORM_HARVEST = re.compile(r"querySelectorAll\s*\(\s*['\"][^'\"]*input[^'\"]*['\"]\s*\)|getElementsByTagName\s*\(\s*['\"]input['\"]")
VALUE_READ = re.compile(r"\.value\b")
TARGET_VALUE = re.compile(r"(?:\.target\.value|\.srcElement\.value|this\.value)")
SCRIPT_LOAD = re.compile(r"createElement\s*\(\s*['\"]script['\"]\s*\)|import\s*\(|\.src\s*=\s*['\"]https?://")
OBFUSCATED_IDENT = re.compile(r"\b_0x[0-9a-fA-F]{4,}\b")
EVAL_USE = re.compile(r"\b(eval|Function)\s*\(")
BASE64_LONG = re.compile(r"\b(?:atob|btoa)\s*\(|['\"][A-Za-z0-9+/=]{80,}['\"]")
CARD_REGEX = re.compile(r"(\\d\{13|\\d\{15|\\d\{16|13,19|luhn|mod\s*10)", re.I)
GLOBAL_ASSIGN = re.compile(r"\bwindow\.[A-Za-z_$][\w$]*\s*=")
BUFFER_PUSH = re.compile(r"\b[A-Za-z_$][\w$]*\.(push|unshift)\s*\(")
DEBUGGER_CLAIM = re.compile(r"(?i)(debugger|debug|devtools|inspector|logger|analytics|tracker|telemetry)")

def _line_of(code_lines, idx_line):
    if 1 <= idx_line <= len(code_lines):
        return code_lines[idx_line - 1].strip()[:300]
    return ""

def _finding(rule, title, severity, confidence, category, line, snippet, explanation, remediation):
    return {
        "rule_id": rule, "title": title, "severity": severity,
        "confidence": confidence, "category": category, "line": line,
        "snippet": redact(snippet), "explanation": explanation,
        "remediation": remediation, "status": "open",
    }

def analyze(code: str, filename: str = "pasted-code.js") -> dict:
    raw = code or ""
    code_lines = raw.split("\n")
    exec_code, comments = split_comments(raw)
    exec_lines = exec_code.split("\n")
    findings = []

    # ---------- taint tracking (simple, honest) ----------
    # vars assigned from a .value read or event target value
    tainted_vars = set()
    for ln, line in enumerate(exec_lines, start=1):
        m = re.search(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;]*\.value\b", line)
        if m:
            tainted_vars.add(m.group(1))
        m2 = re.search(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;]*(?:target\.value|querySelector|getElementById)", line)
        if m2 and SENSITIVE_IDENT.search(line):
            tainted_vars.add(m2.group(1))
    has_global_value_flow = bool(TARGET_VALUE.search(exec_code)) or bool(tainted_vars)

    def tainted_in(text):
        if TARGET_VALUE.search(text or ""):
            return True
        return any(re.search(r"\b" + re.escape(v) + r"\b", text or "") for v in tainted_vars)

    # ---------- document-wide listeners ----------
    doc_listener_lines = []
    for ln, line in enumerate(exec_lines, start=1):
        if DOC_LISTENER.search(line):
            doc_listener_lines.append(ln)
            ev = DOC_LISTENER.search(line).group(2)
            findings.append(_finding(
                "DOC_WIDE_LISTENER",
                f"Document-wide '{ev}' event listener monitors all user input",
                "high", "confirmed", "Input Monitoring", ln, _line_of(exec_lines, ln),
                "A listener attached to document/window for input/key events sees EVERY keystroke and field "
                "change on the page — including payment card numbers, CVVs and passwords — not just one form. "
                "This is the core collection technique used by Magecart-style payment skimmers.",
                "Scope listeners to the specific non-payment element that needs them. Never attach input/key "
                "listeners at document or window level on pages that render payment fields. Use a payment "
                "provider's hosted fields (e.g. Stripe Elements) so card data never touches your DOM."))

    # ---------- payment field discovery ----------
    for ln, line in enumerate(exec_lines, start=1):
        if PAYMENT_SELECTOR.search(line):
            findings.append(_finding(
                "PAYMENT_FIELD_ACCESS",
                "Script looks up payment/checkout form fields directly",
                "high", "confirmed", "Payment Data Access", ln, _line_of(exec_lines, ln),
                "The code queries the DOM for fields whose names/ids reference cards, CVV, expiry or billing. "
                "Legitimate page code rarely needs to discover payment fields by selector from a separate "
                "script — skimmers do exactly this to locate the data.",
                "Payment fields should only be accessed by your own first-party checkout code, ideally "
                "replaced by hosted payment fields in an iframe from your processor so no script on the "
                "page can read the values at all."))

    # ---------- sensitive identifier references ----------
    sens_lines = [ln for ln, line in enumerate(exec_lines, start=1) if SENSITIVE_IDENT.search(line)]
    if sens_lines and not any(f["rule_id"] == "PAYMENT_FIELD_ACCESS" for f in findings):
        findings.append(_finding(
            "SENSITIVE_FIELD_REF",
            "References to card / CVV / expiry / billing identifiers",
            "medium", "indicator", "Payment Data Access", sens_lines[0], _line_of(exec_lines, sens_lines[0]),
            f"The code references sensitive payment concepts on {len(sens_lines)} line(s) "
            f"({', '.join(map(str, sens_lines[:8]))}). On its own this is an indicator, not proof of theft — "
            "context (collection + storage/network) decides the risk.",
            "Audit why this script needs payment identifiers at all. If it is a debugger/analytics tool, "
            "remove every payment reference — a real debugger never needs a CVV field name."))

    # ---------- form harvesting ----------
    for ln, line in enumerate(exec_lines, start=1):
        if FORM_HARVEST.search(line):
            findings.append(_finding(
                "FORM_HARVEST",
                "Script enumerates all input fields on the page",
                "high", "confirmed", "Input Monitoring", ln, _line_of(exec_lines, ln),
                "Enumerating every <input> is how skimmers discover card fields dynamically, even when field "
                "names change. Combined with .value reads it becomes bulk collection of everything typed.",
                "Select the exact fields the feature needs by id. Avoid wildcard input enumeration on "
                "checkout pages."))

    # ---------- value collection inside doc-wide listener context ----------
    if doc_listener_lines and VALUE_READ.search(exec_code):
        findings.append(_finding(
            "VALUE_COLLECTION",
            "Input values are read while a document-wide listener is active",
            "high", "confirmed", "Data Collection", doc_listener_lines[0], _line_of(exec_lines, doc_listener_lines[0]),
            "A page-wide listener plus .value reads means the script collects the actual contents of "
            "fields — the data itself, not just event metadata. If any payment field is on the page, its "
            "contents are collected too.",
            "If you only need event metadata (counts, timing), never read .value. Add an explicit guard "
            "that skips any field whose name/id/type matches payment or password patterns."))

    # ---------- keystroke buffer ----------
    if doc_listener_lines and BUFFER_PUSH.search(exec_code):
        for ln, line in enumerate(exec_lines, start=1):
            if BUFFER_PUSH.search(line):
                findings.append(_finding(
                    "KEYLOG_BUFFER",
                    "Keystrokes/input appear to be buffered into a collection",
                    "high", "indicator", "Data Collection", ln, _line_of(exec_lines, ln),
                    "Values are pushed into an array/object while a global listener runs — the classic "
                    "keylogger buffer pattern: collect first, send later (often in a batch, which hides "
                    "the exfiltration).",
                    "Do not accumulate raw input values. If buffering analytics events, store only "
                    "non-sensitive metadata and cap/expire the buffer."))
                break

    # ---------- clipboard ----------
    for ln, line in enumerate(exec_lines, start=1):
        if CLIPBOARD.search(line):
            findings.append(_finding(
                "CLIPBOARD_MONITOR",
                "Clipboard access / copy-paste monitoring",
                "medium", "confirmed", "Input Monitoring", ln, _line_of(exec_lines, ln),
                "Clipboard hooks can capture card numbers users paste into checkout (a common habit) and "
                "passwords pasted from password managers.",
                "Remove clipboard listeners from checkout pages unless the feature demonstrably requires "
                "them, and never log clipboard contents."))

    # ---------- network calls (executable) ----------
    net_findings = []
    for name, rx in NET_CALLS:
        for ln, line in enumerate(exec_lines, start=1):
            if rx.search(line):
                # grab a context window for taint check (this line + next 6)
                window_text = "\n".join(exec_lines[ln - 1: ln + 6])
                tainted = tainted_in(window_text) or (has_global_value_flow and bool(doc_listener_lines))
                if tainted:
                    sev, conf = "critical", "confirmed"
                    expl = (f"Executable {name} network call with collected input data flowing toward it. "
                            "Sensitive values gathered by this script can leave the browser to the call's "
                            "destination. This is the exfiltration step of a payment skimmer. NOTE: static "
                            "analysis proves the code path exists and data can flow to it; it does not by "
                            "itself prove a transmission already happened on a live site.")
                    rem = ("Remove this transmission immediately and treat the page as a potential incident: "
                           "rotate any exposed keys, review server logs for this endpoint, and follow the "
                           "incident checklist. Third-party scripts must never receive payment field values.")
                else:
                    sev, conf = "medium", "confirmed"
                    expl = (f"Executable {name} network call. Network calls alone are normal on the web; "
                            "no flow of sensitive input values into this call was proven by this analysis, "
                            "so it is flagged for review, not accused of exfiltration.")
                    rem = ("Verify the destination is first-party or an approved vendor, confirm what "
                           "payload it sends, and pin third-party endpoints in your CSP connect-src.")
                f = _finding("NETWORK_CALL", f"Network transmission via {name}", sev, conf,
                             "Network / Exfiltration", ln, _line_of(exec_lines, ln), expl, rem)
                net_findings.append(f)
                break  # one finding per mechanism
    findings.extend(net_findings)

    # ---------- commented-out network code ----------
    for c in comments:
        for name, rx in NET_CALLS:
            if rx.search(c["text"]):
                findings.append(_finding(
                    "COMMENTED_EXFIL",
                    f"Commented-out {name} transmission code (suspicious indicator)",
                    "medium", "indicator", "Suspicious Indicators", c["line"],
                    ("// " + c["text"].strip())[:300],
                    "A network send exists in the code but is commented out, so it does NOT run today. "
                    "We do not claim any transmission occurred. It is still a real indicator: skimmer "
                    "kits are often shipped with exfiltration disabled until activation, and legitimate "
                    "debuggers rarely contain a dormant send of collected data.",
                    "Delete dead transmission code — do not leave it dormant. If you keep the file, treat "
                    "the commented send as a reason to distrust and replace the whole script."))
                break

    # ---------- storage ----------
    for ln, line in enumerate(exec_lines, start=1):
        if STORAGE.search(line):
            tainted = tainted_in("\n".join(exec_lines[max(0, ln - 4): ln + 2])) or bool(doc_listener_lines)
            findings.append(_finding(
                "STORAGE_COLLECTION",
                "Data written to browser storage / cookies",
                "high" if tainted else "low", "confirmed", "Data Collection", ln, _line_of(exec_lines, ln),
                "Persisting collected input in localStorage/sessionStorage/cookies lets a skimmer stage "
                "data on the victim's browser and exfiltrate it later in one batch."
                if tainted else
                "A storage write was found. No flow of sensitive input values into it was proven, so this "
                "is low severity — review what is being stored.",
                "Never store payment or credential values in web storage. Store only opaque ids/metadata, "
                "with an expiry."))

    # ---------- console logging of values ----------
    for ln, line in enumerate(exec_lines, start=1):
        if CONSOLE_LOG.search(line) and (VALUE_READ.search(line) or tainted_in(line) or doc_listener_lines):
            findings.append(_finding(
                "CONSOLE_LOG_SENSITIVE",
                "Input values may be written to the console / logs",
                "medium", "indicator", "Data Collection", ln, _line_of(exec_lines, ln),
                "Logging field values exposes them to anyone with devtools access, log aggregation, or "
                "session-replay tools — a quiet leak path for card data.",
                "Log event names and counts only. Strip all .value content from logging in production."))

    # ---------- obfuscation ----------
    obf_lines = [ln for ln, line in enumerate(exec_lines, start=1) if OBFUSCATED_IDENT.search(line)]
    if len(obf_lines) >= 3:
        findings.append(_finding(
            "OBFUSCATED_IDENTIFIERS",
            f"Heavily obfuscated identifiers (_0x…) on {len(obf_lines)} lines",
            "high", "indicator", "Obfuscation", obf_lines[0], _line_of(exec_lines, obf_lines[0]),
            "Hex-style generated identifiers are a hallmark of packed skimmer code designed to resist "
            "review. Legitimate first-party code is almost never shipped this way.",
            "Demand readable source (and source maps) for any third-party script. Treat unexplained "
            "obfuscation on a checkout page as untrusted until the vendor explains it."))
    for ln, line in enumerate(exec_lines, start=1):
        if EVAL_USE.search(line):
            findings.append(_finding(
                "EVAL_USAGE", "Use of eval() / Function() dynamic code execution",
                "high", "confirmed", "Obfuscation", ln, _line_of(exec_lines, ln),
                "Dynamic evaluation lets a script fetch and run new code at runtime, bypassing code "
                "review and most static checks — a standard skimmer loader technique.",
                "Remove eval/Function. Block them with CSP (no 'unsafe-eval') so loaders fail closed."))
            break
    for ln, line in enumerate(exec_lines, start=1):
        if BASE64_LONG.search(line):
            findings.append(_finding(
                "ENCODED_PAYLOAD", "Base64 / long encoded string handling (possible hidden payload)",
                "medium", "indicator", "Obfuscation", ln, _line_of(exec_lines, ln),
                "Long encoded blobs and atob() decoding are used to hide exfiltration URLs and second-stage "
                "payloads from casual review.",
                "Decode and review any encoded blob before trusting the script. Pin allowed endpoints in CSP."))
            break

    # ---------- dynamic script loading ----------
    for ln, line in enumerate(exec_lines, start=1):
        if SCRIPT_LOAD.search(line):
            findings.append(_finding(
                "DYNAMIC_SCRIPT_LOAD", "Dynamic loading of external scripts",
                "medium", "confirmed", "Code Loading", ln, _line_of(exec_lines, ln),
                "Loading remote code at runtime means the reviewed file is not the whole program — the "
                "remote file can change at any time into a skimmer.",
                "Self-host and pin third-party code with Subresource Integrity (SRI) hashes. Allowlist "
                "script sources in CSP script-src."))

    # ---------- card regex / luhn ----------
    for ln, line in enumerate(exec_lines, start=1):
        if CARD_REGEX.search(line) and (SENSITIVE_IDENT.search(line) or re.search(r"\\d", line)):
            findings.append(_finding(
                "CARD_PATTERN_MATCHING", "Code pattern-matches card-number shapes",
                "high", "indicator", "Payment Data Access", ln, _line_of(exec_lines, ln),
                "Regexes for 13–19 digit sequences / Luhn checks exist to *recognize* card numbers in a "
                "stream of typed data — a skimmer needs this to pull cards out of general keystrokes. "
                "(Card validation belongs inside the payment processor's own fields.)",
                "Remove card-shape detection from page scripts. Validation should happen in the "
                "processor's hosted fields, never in a general page script."))
            break

    # ---------- unsafe globals ----------
    for ln, line in enumerate(exec_lines, start=1):
        if GLOBAL_ASSIGN.search(line) and (doc_listener_lines or SENSITIVE_IDENT.search(line)):
            findings.append(_finding(
                "UNSAFE_GLOBAL", "Collected data exposed on a global (window.*) variable",
                "medium", "indicator", "Data Collection", ln, _line_of(exec_lines, ln),
                "Data hung on window.* is readable by every other script on the page — any compromised "
                "third-party tag can lift it.",
                "Keep collected data in module scope/closures, never on window."))
            break

    # ---------- missing cleanup ----------
    if ANY_LISTENER.search(exec_code) and "removeEventListener" not in exec_code:
        findings.append(_finding(
            "NO_CLEANUP", "Event listeners are added but never removed",
            "low", "indicator", "Code Quality / Risk", 1, _line_of(exec_lines, 1),
            "No removeEventListener exists anywhere in the file. Persistent listeners survive page "
            "navigation in SPAs and keep collecting after the feature that installed them is gone. "
            "Sloppy lifecycle is also typical of injected code, which never cleans up.",
            "Store handler references and remove listeners on teardown/route change."))

    # ---------- deceptive debugger ----------
    name_claims_debug = bool(DEBUGGER_CLAIM.search(filename or "")) or bool(
        DEBUGGER_CLAIM.search("\n".join(c["text"] for c in comments[:5])))
    collects = bool(doc_listener_lines) or any(f["rule_id"] in ("FORM_HARVEST", "PAYMENT_FIELD_ACCESS") for f in findings)
    if name_claims_debug and collects:
        findings.append(_finding(
            "DECEPTIVE_DEBUGGER",
            "Script presents as a debugger/logger but monitors payment-page input",
            "critical", "indicator", "Deception", 1, (filename or "")[:120],
            "The file names or describes itself as a debugging/analytics/logging tool, yet it installs "
            "broad input monitoring and touches payment-related fields. A genuine debugger inspects code "
            "you point it at; it does not need page-wide keystroke collection or card field selectors. "
            "The mismatch between claimed purpose and actual behavior is itself a top skimmer signal.",
            "Quarantine this script: remove it from all pages, preserve a copy + hashes for forensics, "
            "and follow the incident-response checklist before redeploying anything similar."))

    # ---------- dedupe + sort ----------
    seen = set(); uniq = []
    for f in sorted(findings, key=lambda x: -SEV_ORDER[x["severity"]]):
        key = (f["rule_id"], f["line"])
        if key in seen: continue
        seen.add(key); uniq.append(f)
    findings = uniq
    for i, f in enumerate(findings):
        f["id"] = i + 1

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low", "info")}
    has_confirmed_exfil = any(f["rule_id"] == "NETWORK_CALL" and f["severity"] == "critical" for f in findings)
    has_collection = any(f["rule_id"] in ("DOC_WIDE_LISTENER", "VALUE_COLLECTION", "FORM_HARVEST", "PAYMENT_FIELD_ACCESS") for f in findings)

    if counts["critical"] >= 1 and has_collection:
        verdict, risk = "CRITICAL — Skimmer behavior likely", 90 + min(10, counts["critical"] * 2)
    elif counts["critical"] >= 1:
        verdict, risk = "HIGH RISK — Confirmed dangerous behavior", 78
    elif counts["high"] >= 2:
        verdict, risk = "HIGH RISK — Multiple serious indicators", 68
    elif counts["high"] == 1 or counts["medium"] >= 3:
        verdict, risk = "SUSPICIOUS — Review required", 48
    elif findings:
        verdict, risk = "LOW RISK — Minor issues found", 22
    else:
        verdict, risk = "CLEAN — No findings", 2

    # guardrail: never let a script with no collection + no sensitive refs be critical
    if not has_collection and not sens_lines and counts["critical"] > 0 and not has_confirmed_exfil:
        verdict, risk = "SUSPICIOUS — Review required", 50

    sha = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
    return {
        "filename": filename, "sha256": sha, "size_bytes": len(raw.encode("utf-8", "ignore")),
        "lines": len(code_lines), "verdict": verdict, "risk_score": min(100, risk),
        "counts": counts, "findings": findings,
        "tainted_vars": sorted(tainted_vars),
        "comment_count": len(comments),
        "summary": {
            "has_document_wide_monitoring": bool(doc_listener_lines),
            "has_payment_field_access": any(f["rule_id"] == "PAYMENT_FIELD_ACCESS" for f in findings),
            "has_confirmed_exfil_path": has_confirmed_exfil,
            "has_commented_exfil": any(f["rule_id"] == "COMMENTED_EXFIL" for f in findings),
            "has_collection": has_collection,
        },
    }

SAFE_DEBUGGER_REPLACEMENT = """// Safe replacement: scoped debug helper (collects NO payment data)
// - Listens only to one specific, non-payment element you pass in.
// - Never reads values from payment/password fields (explicit guard).
// - Logs event metadata only, never field contents. Cleans up after itself.
(function () {
  const BLOCKED = /(card|cc|cvv|cvc|expir|billing|password|passwd|ssn)/i;
  function isSensitive(el) {
    if (!el) return true;
    const tag = (el.tagName || '').toLowerCase();
    const type = (el.getAttribute && el.getAttribute('type') || '').toLowerCase();
    const name = ((el.getAttribute && (el.getAttribute('name') || el.getAttribute('id'))) || '');
    return type === 'password' || BLOCKED.test(name) || (tag === 'input' && BLOCKED.test(el.className || ''));
  }
  function attachDebug(el, label) {
    if (!el || isSensitive(el)) return function () {};
    const handler = function (e) {
      // metadata only — no e.target.value, ever
      console.debug('[debug]', label || el.id || el.tagName, e.type, new Date().toISOString());
    };
    el.addEventListener('change', handler);
    return function detach() { el.removeEventListener('change', handler); };
  }
  window.SafeDebug = { attach: attachDebug };
})();"""

CSP_RECOMMENDATION = ("Content-Security-Policy: default-src 'self'; "
  "script-src 'self' https://js.stripe.com; frame-src https://js.stripe.com https://hooks.stripe.com; "
  "connect-src 'self' https://api.stripe.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
  "object-src 'none'; base-uri 'self'; form-action 'self'")

INCIDENT_CHECKLIST = [
  "Remove/quarantine the flagged script from every page and CDN/tag manager; preserve a copy + SHA-256 for forensics.",
  "Identify when the script was added (git history, tag-manager versions, CMS audit logs) and who/what added it.",
  "Review server + CDN logs for requests to any endpoint named in network findings during the exposure window.",
  "Assume payment data entered while the script was live may be compromised; contact your payment processor's security team.",
  "Follow PCI DSS incident-response duties; your processor/acquirer will advise on card-brand notification and possible PFI involvement.",
  "Rotate API keys/secrets that were present on affected pages; force password resets if credential fields were monitored.",
  "Scan the rest of the site (all third-party scripts, tag-manager containers) with this tool.",
  "Re-deploy only reviewed, readable code; add CSP + SRI, and monitor for unauthorized script changes (file integrity monitoring).",
]
