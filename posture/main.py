import argparse
import sys
from datetime import datetime, timezone

import dns.exception

from posture import dns_checks
from posture import questions
from posture import report
from posture import scoring
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
    parser.add_argument("--out-dir", default="reports", help="folder for the JSON and HTML reports (default: reports)")
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
    # Only digits and dots means an IP address, like 127.0.0.1. This tool is for domains.
    if domain.replace(".", "").isdigit():
        return False
    # DNS rules: each part between dots has 1 to 63 characters, the whole name at most 253.
    if len(domain) > 253:
        return False
    for label in domain.split("."):
        if len(label) == 0 or len(label) > 63:
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


def print_summary(domain, findings, score, band, questions):
    print("Results for " + domain)
    print()
    for finding in findings:
        label = finding.status.upper().ljust(5)
        line = "  [" + label + "] " + finding.title
        points = scoring.points_lost(finding)
        if points > 0:
            line = line + " (-" + str(points) + ")"
        print(line)

    print()
    print("Score: " + str(score) + "/100 (" + band + ")")

    error_count = scoring.count_errors(findings)
    if error_count > 0:
        print("Note: " + str(error_count) + " check(s) could not finish, so the score may be too high.")

    if len(questions) > 0:
        print()
        print("Questions to ask this supplier:")
        number = 1
        for question in questions:
            print("  " + str(number) + ". " + question)
            number += 1


def main():
    args = parse_args()
    domain = clean_domain(args.domain)
    if not looks_like_domain(domain):
        print("'" + args.domain + "' does not look like a domain name.", file=sys.stderr)
        return 1

    findings = run_all_checks(domain)
    score = scoring.calculate_score(findings)
    band = scoring.get_band(score)
    supplier_questions = questions.generate_questions(findings)
    print_summary(domain, findings, score, band, supplier_questions)

    checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    data = report.build_report_data(domain, findings, score, band, supplier_questions, checked_at)
    json_path, html_path = report.write_reports(data, args.out_dir)
    print()
    print("JSON report: " + json_path)
    print("HTML report: " + html_path)
    return 0


# This block only runs when the file is started with "python -m posture.main",
# not when another file (like a test) imports it.
if __name__ == "__main__":
    sys.exit(main())
