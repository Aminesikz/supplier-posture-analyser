from posture import web_checks


def get_ids(findings):
    ids = []
    for finding in findings:
        ids.append(finding.check_id)
    return ids


# ---------- HTTPS and redirect ----------


def test_https_ok_on_bare_domain():
    assert get_ids(web_checks.check_https("example.test", "example.test")) == ["https_ok"]


def test_https_www_fallback_is_reported():
    findings = web_checks.check_https("example.test", "www.example.test")
    assert get_ids(findings) == ["https_ok", "https_www_fallback"]


def test_https_missing():
    assert get_ids(web_checks.check_https("example.test", "")) == ["https_missing"]


def test_http_redirects_to_https():
    findings = web_checks.check_http_redirect("https://example.test/")
    assert get_ids(findings) == ["http_redirect_ok"]


def test_http_does_not_redirect():
    findings = web_checks.check_http_redirect("http://example.test/")
    assert get_ids(findings) == ["http_no_redirect"]


def test_http_no_answer():
    assert get_ids(web_checks.check_http_redirect("")) == ["http_no_answer"]


# ---------- Headers ----------


def test_lowercase_headers():
    headers = web_checks.lowercase_headers({"X-Frame-Options": "DENY"})
    assert headers == {"x-frame-options": "DENY"}


def test_hsts():
    assert get_ids(web_checks.check_hsts({"strict-transport-security": "max-age=31536000"})) == ["hsts_found"]
    assert get_ids(web_checks.check_hsts({})) == ["hsts_missing"]


def test_csp():
    assert get_ids(web_checks.check_csp({"content-security-policy": "default-src 'self'"})) == ["csp_found"]
    assert get_ids(web_checks.check_csp({})) == ["csp_missing"]


def test_x_content_type_options():
    assert get_ids(web_checks.check_x_content_type_options({"x-content-type-options": "nosniff"})) == ["xcto_found"]
    assert get_ids(web_checks.check_x_content_type_options({})) == ["xcto_missing"]


def test_frame_protection_with_x_frame_options():
    findings = web_checks.check_frame_protection({"x-frame-options": "SAMEORIGIN"})
    assert get_ids(findings) == ["frame_protection_found"]


def test_frame_protection_with_csp_frame_ancestors():
    findings = web_checks.check_frame_protection({"content-security-policy": "frame-ancestors 'none'"})
    assert get_ids(findings) == ["frame_protection_found"]


def test_frame_protection_missing():
    # A CSP without frame-ancestors does not protect against framing.
    findings = web_checks.check_frame_protection({"content-security-policy": "default-src 'self'"})
    assert get_ids(findings) == ["frame_protection_missing"]


def test_referrer_policy_found():
    findings = web_checks.check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"})
    assert get_ids(findings) == ["referrer_policy_found"]
    assert findings[0].status == "pass"


def test_referrer_policy_missing():
    findings = web_checks.check_referrer_policy({})
    assert get_ids(findings) == ["referrer_policy_missing"]
    assert findings[0].status == "warn"


# ---------- security.txt ----------


def test_security_txt_found():
    findings = web_checks.check_security_txt(200, "Contact: mailto:security@example.test\n")
    assert get_ids(findings) == ["security_txt_found"]


def test_security_txt_404():
    assert get_ids(web_checks.check_security_txt(404, "Not found")) == ["security_txt_missing"]


def test_security_txt_home_page_is_not_security_txt():
    # Status 200, but it is just the normal home page.
    findings = web_checks.check_security_txt(200, "<html><body>Welcome</body></html>")
    assert get_ids(findings) == ["security_txt_missing"]
