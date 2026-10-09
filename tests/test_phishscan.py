import json
from pathlib import Path

from phishscan.analyzer import (addr_domain, analyze, analyze_url, attachment_info, defang, lookalike,
                                parse_auth, reg_domain, origin_ip)
from phishscan.parser import ParsedEmail, parse_eml
from phishscan.report import to_html, to_json, to_markdown

S = Path("samples")


def run(name):
    return analyze(parse_eml(S / name))


def test_sample_verdicts():
    assert run("01_credential_phish.eml").verdict == "HIGH"
    assert run("02_invoice_attachment.eml").verdict == "HIGH"
    assert run("03_legit_notification.eml").verdict == "LOW"
    assert run("04_bec_ceo_gift_cards.eml").verdict == "HIGH"


def test_legit_brand_domains_are_not_lookalikes():
    for h in ("github.com", "login.microsoftonline.com", "accounts.google.com", "www.paypal.com"):
        assert lookalike(h) is None, h


def test_lookalike_detection():
    assert lookalike("micros0ft-support.example")[0] == "microsoft"
    assert lookalike("paypa1.com")[0] == "paypal"
    assert lookalike("secure-paypal-login.example")[0] == "paypal"
    assert lookalike("microsoft.account-verify.example")[0] == "microsoft"
    assert lookalike("totally-unrelated.example") is None


def test_url_flags():
    u = analyze_url("http://203.0.113.50/verify", "https://account.microsoft.com/security")
    assert {"ip_literal", "text_mismatch", "not_https"} <= set(u.flags)
    assert "shortener" in analyze_url("https://bit.ly/abc", "").flags
    assert "at_symbol" in analyze_url("https://paypal.com@evil.example/x", "").flags
    assert analyze_url("https://github.com/notifications", "View it on GitHub").flags == []


def test_attachment_flags_and_hash_without_executing():
    a = attachment_info("Invoice.pdf.exe", "application/octet-stream", b"x")
    assert {"double_extension", "risky_extension"} <= set(a.flags)
    assert len(a.sha256) == 64
    assert "macro_enabled" in attachment_info("q3.xlsm", "x", b"").flags


def test_auth_parsing_first_result_wins():
    r = parse_auth(["mx; spf=pass; dkim=fail; dmarc=pass", "relay; spf=fail"])
    assert r == {"spf": "pass", "dkim": "fail", "dmarc": "pass"}


def test_helpers():
    assert reg_domain("a.b.example.co.uk") == "example.co.uk"
    assert addr_domain("x@Evil.Example") == "evil.example"
    assert defang("http://evil.example/a") == "hxxp://evil[.]example/a"
    assert origin_ip(["from a [192.168.1.1]", "from b [203.0.113.7]"]) == "203.0.113.7"


def test_score_is_sum_of_findings_and_bounded():
    for f in S.glob("*.eml"):
        r = analyze(parse_eml(f))
        assert 0 <= r.score <= 100
        assert r.score == max(0, min(100, sum(x.points for x in r.findings)))
        assert r.actions


def test_pass_auth_does_not_whitewash_a_lookalike():
    p = ParsedEmail(path="x", subject="hi", from_display="Microsoft Support", from_addr="a@micros0ft.example",
                    auth_headers=["spf=pass; dkim=pass; dmarc=pass"])
    r = analyze(p)
    assert all(f.points >= 0 for f in r.findings) and r.verdict in ("MEDIUM", "HIGH")


def test_reports_escape_and_defang_untrusted_content():
    p = ParsedEmail(path="x", subject="<script>alert(1)</script>", from_display="<img src=x onerror=1>",
                    from_addr="a@evil.example", html='<a href="http://evil.example/x">click</a>')
    r = analyze(p)
    html = to_html([r], "t")
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "hxxp://evil[.]example" in html and "http://evil.example/x" not in html
    assert "http://evil.example/x" not in to_markdown([r])
    assert json.loads(to_json([r]))[0]["subject"].startswith("<script>")


def test_radar_dashboard_is_safe_and_complete():
    from phishscan.dashboard import to_html as radar
    p = ParsedEmail(path="/x/evil.eml", subject="</script><script>window.PWNED=1</script>",
                    from_display='"><svg onload=1>', from_addr="a@evil.example",
                    html='<a href="http://evil.example/x">click</a>')
    page = radar([analyze(p)], "t")
    assert "</script><script>window.PWNED" not in page      # JSON payload cannot break out of its script tag
    assert "innerHTML" not in page                          # rendering uses textContent only
    assert "http://evil.example/x" not in page              # indicators are embedded defanged
    assert "hxxp://evil[.]example/x" in page
    assert "/x/evil.eml" not in page and "evil.eml" in page  # only the file name, never the local path
    full = radar([analyze(parse_eml(f)) for f in S.glob("*.eml")], "t")
    assert full.count('"verdict"') == 4
