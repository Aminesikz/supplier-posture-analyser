import argparse
import sys

import dns.exception

from posture import dns_checks
from posture import tls_checks
from posture import web_checks
from posture.finding import Finding

ALLOWED_DOMAIN_CHARACTERS = "abcdefghijklmnopqrstuvwxyz0123456789-."


def parse_args():
    parser = argparse.ArgumentParser(
        prog="posture",
        description="Passive security checks for a supplier's domain. "
        "Only check domains you own or have permission to assess.",
    )
    parser.add_argument("domain", help="the domain to check, for example example.com")
    return parser.parse_args()


def clean_domain(text):
    # Turn input like "https://Example.com/about" into "example.com".
    domain = text.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]
    return domain.rstrip(".")


def looks_like_domain(domain):
    if "." not in domain:
        return False
    for character in domain:
        if character not in ALLOWED_DOMAIN_CHARACTERS:
            return False
    return True


def run_all_checks(domain):
    findings = []
    try:
        findings.extend(dns_checks.run_email_checks(domain))
    except dns.exception.DNSException as error:
        # A timeout or a broken DNS server. Say so, instead of reporting "missing".
        findings.append(Finding(
            "email_checks_failed", "error", "Email checks could not finish",
            "A DNS lookup failed, so the email results are not complete. Try again later.",
            str(error),
        ))

    try:
        findings.extend(dns_checks.check_caa(dns_checks.get_caa_records(domain)))
    except dns.exception.DNSException as error:
        findings.append(Finding(
            "caa_check_failed", "error", "CAA check could not finish",
            "The DNS lookup for CAA records failed. Try again later.",
            str(error),
        ))

    host, homepage = web_checks.get_homepage(domain)
    findings.extend(web_checks.run_web_checks(domain, host, homepage))

    # Check TLS on the host that answered. If none did, try the bare domain anyway,
    # because a server that only speaks old TLS fails the normal HTTPS request.
    if host == "":
        host = domain
    findings.extend(tls_checks.run_tls_checks(host))
    return findings


def print_findings(domain, findings):
    print("Results for " + domain)
    print()
    for finding in findings:
        label = finding.status.upper().ljust(5)
        print("  [" + label + "] " + finding.title)


def main():
    args = parse_args()
    domain = clean_domain(args.domain)
    if not looks_like_domain(domain):
        print("'" + args.domain + "' does not look like a domain name.", file=sys.stderr)
        return 1

    findings = run_all_checks(domain)
    print_findings(domain, findings)
    return 0


# This block only runs when the file is started with "python -m posture.main",
# not when another file (like a test) imports it.
if __name__ == "__main__":
    sys.exit(main())
