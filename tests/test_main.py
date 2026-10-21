import dns.exception

from posture import dns_checks
from posture import main


def test_clean_domain_removes_scheme_path_and_case():
    assert main.clean_domain("  https://Example.COM/about/ ") == "example.com"


def test_clean_domain_removes_trailing_dot():
    assert main.clean_domain("example.com.") == "example.com"


def test_looks_like_domain():
    assert main.looks_like_domain("example.co.uk")
    assert not main.looks_like_domain("localhost")
    assert not main.looks_like_domain("example.com;rm -rf")


def test_dns_failure_becomes_error_finding(monkeypatch):
    def broken_email_checks(domain):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns_checks, "run_email_checks", broken_email_checks)
    findings = main.run_all_checks("example.test")
    assert len(findings) == 1
    assert findings[0].check_id == "email_checks_failed"
    assert findings[0].status == "error"
