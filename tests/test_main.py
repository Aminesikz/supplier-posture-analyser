import sys

import dns.exception
import pytest

from posture import dns_checks
from posture import main
from posture import tls_checks
from posture import web_checks


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

    def no_caa_records(domain):
        return []

    def no_homepage(domain):
        return "", None

    def no_tls_findings(host):
        return []

    # Replace every network call so this test stays offline.
    monkeypatch.setattr(dns_checks, "run_email_checks", broken_email_checks)
    monkeypatch.setattr(dns_checks, "get_caa_records", no_caa_records)
    monkeypatch.setattr(web_checks, "get_homepage", no_homepage)
    monkeypatch.setattr(tls_checks, "run_tls_checks", no_tls_findings)

    findings = main.run_all_checks("example.test")
    assert findings[0].check_id == "email_checks_failed"
    assert findings[0].status == "error"


# Amine: remove ONLY the "@pytest.mark.skip" line once --out-dir is added.
@pytest.mark.skip(reason="--out-dir not added yet")
def test_out_dir_flag(monkeypatch):
    # sys.argv is the list of words typed on the command line. We fake it here.
    monkeypatch.setattr(sys, "argv", ["posture", "example.com", "--out-dir", "my-reports"])
    args = main.parse_args()
    assert args.domain == "example.com"
    assert args.out_dir == "my-reports"


@pytest.mark.skip(reason="--out-dir not added yet")
def test_out_dir_default_is_reports(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["posture", "example.com"])
    args = main.parse_args()
    assert args.out_dir == "reports"
