import ssl

from posture import tls_checks


def get_ids(findings):
    ids = []
    for finding in findings:
        ids.append(finding.check_id)
    return ids


def test_days_until_expiry():
    # Pretend "now" is exactly 30 days before the certificate runs out.
    expiry = ssl.cert_time_to_seconds("Jun  1 12:00:00 2027 GMT")
    now = expiry - 30 * 86400
    assert tls_checks.days_until_expiry("Jun  1 12:00:00 2027 GMT", now) == 30


def test_cert_ok():
    assert get_ids(tls_checks.check_cert_expiry(90)) == ["cert_ok"]


def test_cert_expires_soon():
    findings = tls_checks.check_cert_expiry(5)
    assert get_ids(findings) == ["cert_expires_soon"]
    assert findings[0].status == "warn"


def test_tls_1_3_is_ok():
    assert get_ids(tls_checks.check_tls_version("TLSv1.3")) == ["tls_version_ok"]


def test_tls_1_0_is_flagged():
    assert get_ids(tls_checks.check_tls_version("TLSv1")) == ["tls_old_version"]


def test_tls_1_1_is_flagged():
    assert get_ids(tls_checks.check_tls_version("TLSv1.1")) == ["tls_old_version"]


def test_invalid_certificate(monkeypatch):
    def fake_bad_certificate(host):
        error = ssl.SSLCertVerificationError()
        error.verify_message = "certificate has expired"
        raise error

    monkeypatch.setattr(tls_checks, "get_certificate_and_version", fake_bad_certificate)
    findings = tls_checks.run_tls_checks("expired.example.test")
    assert get_ids(findings) == ["cert_invalid"]
    assert findings[0].evidence == "certificate has expired"


def test_connection_failure_is_error(monkeypatch):
    def fake_timeout(host):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tls_checks, "get_certificate_and_version", fake_timeout)
    findings = tls_checks.run_tls_checks("slow.example.test")
    assert get_ids(findings) == ["tls_check_failed"]
    assert findings[0].status == "error"
