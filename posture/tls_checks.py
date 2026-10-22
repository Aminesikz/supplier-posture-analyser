import socket
import ssl
import time

from posture.finding import Finding

TLS_TIMEOUT = 10  # seconds allowed to connect and finish the TLS handshake
PAUSE_SECONDS = 1  # short wait before connecting, to be polite to the server
CERT_WARNING_DAYS = 14  # warn if the certificate runs out sooner than this
OLD_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]


# ---------- Fetching ----------


def get_certificate_and_version(host):
    context = ssl.create_default_context()
    # By default Python refuses TLS 1.0 and 1.1, so we would never see them.
    # These two lines allow old versions, only so we can report them.
    # The certificate is still checked as normal.
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    context.set_ciphers("DEFAULT:@SECLEVEL=0")

    time.sleep(PAUSE_SECONDS)
    # "with" closes the connection for us when the block ends, even after an error.
    with socket.create_connection((host, 443), timeout=TLS_TIMEOUT) as connection:
        with context.wrap_socket(connection, server_hostname=host) as tls_connection:
            certificate = tls_connection.getpeercert()
            version = tls_connection.version()
    return certificate, version


# ---------- Checks ----------


def days_until_expiry(not_after, now_seconds):
    # not_after looks like "Jun  1 12:00:00 2027 GMT".
    # cert_time_to_seconds turns it into seconds since 1970, like time.time().
    expiry_seconds = ssl.cert_time_to_seconds(not_after)
    return int((expiry_seconds - now_seconds) / 86400)  # 86400 seconds in a day


def check_cert_expiry(days_left):
    if days_left < CERT_WARNING_DAYS:
        return [Finding(
            "cert_expires_soon", "warn",
            "Certificate expires in " + str(days_left) + " days",
            "The website certificate runs out in less than " + str(CERT_WARNING_DAYS)
            + " days. If it is not renewed, browsers will show a security warning.",
        )]
    return [Finding(
        "cert_ok", "pass", "Certificate is valid for " + str(days_left) + " more days",
        "The website certificate is valid and not close to running out.",
    )]


def check_tls_version(version):
    if version in OLD_TLS_VERSIONS:
        return [Finding(
            "tls_old_version", "fail", "Server uses old TLS (" + version + ")",
            "The server chose " + version + " even though my tool offered newer versions. "
            "TLS 1.0 and 1.1 are out of date and should not be used.",
        )]
    return [Finding(
        "tls_version_ok", "pass", "Server uses " + version,
        "The server chose a current version of TLS.",
    )]


# ---------- Run all TLS checks ----------


def run_tls_checks(host):
    try:
        certificate, version = get_certificate_and_version(host)
    except ssl.SSLCertVerificationError as error:
        # This must come before OSError, because it is a more specific kind of OSError.
        return [Finding(
            "cert_invalid", "fail", "Certificate is not valid",
            "Browsers will not trust this website's certificate. It may be expired, "
            "self-signed or for a different name.",
            error.verify_message,
        )]
    except OSError as error:
        # Covers timeouts, refused connections and other TLS errors.
        return [Finding(
            "tls_check_failed", "error", "TLS check could not finish",
            "I could not complete a TLS connection to " + host + " on port 443.",
            str(error),
        )]

    findings = []
    findings.extend(check_cert_expiry(days_until_expiry(certificate["notAfter"], time.time())))
    findings.extend(check_tls_version(version))
    return findings
