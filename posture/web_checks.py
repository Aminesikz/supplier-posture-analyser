import time

import requests

from posture.finding import Finding

USER_AGENT = "supplier-posture-analyser/0.1 (passive check)"
HTTP_TIMEOUT = 10  # seconds allowed for each web request
PAUSE_SECONDS = 1  # short wait before each request, to be polite to the server


# ---------- Fetching ----------


def fetch(url):
    # Returns the response, or None if the request failed
    time.sleep(PAUSE_SECONDS)
    try:
        return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
    except requests.RequestException:
        return None


def get_homepage(domain):
    # Try https://domain first. If that fails, try https://www.domain.
    hosts_to_try = [domain]
    if not domain.startswith("www."):
        hosts_to_try.append("www." + domain)

    for host in hosts_to_try:
        response = fetch("https://" + host + "/")
        if response is not None:
            return host, response
    return "", None


def lowercase_headers(headers):
    # Header names are not case sensitive ("X-Frame-Options" = "x-frame-options").
    # Making them all lower case means the checks only need one spelling.
    result = {}
    for name in headers:
        result[name.lower()] = headers[name]
    return result


# ---------- HTTPS and redirect ----------


def check_https(domain, host):
    if host == "":
        return [Finding(
            "https_missing", "fail", "Website does not answer on HTTPS",
            "I could not load https://" + domain + "/ or https://www." + domain + "/. "
            "Either there is no HTTPS website, or the connection failed.",
        )]

    findings = [Finding(
        "https_ok", "pass", "Website answers on HTTPS",
        "https://" + host + "/ loaded over an encrypted connection.",
    )]
    if host != domain:
        findings.append(Finding(
            "https_www_fallback", "info", "Checked www." + domain + " instead",
            "https://" + domain + "/ did not answer, so I ran the web checks against "
            "https://" + host + "/ instead.",
        ))
    return findings


def check_http_redirect(final_url):
    # final_url is where we ended up after loading the plain http:// address.
    # "" means the plain http:// address did not answer at all.
    if final_url == "":
        return [Finding(
            "http_no_answer", "info", "Plain HTTP does not answer",
            "The site did not answer on plain http://. That is fine for security, but "
            "people who type the address without https:// may not reach the site.",
        )]
    if final_url.startswith("https://"):
        return [Finding(
            "http_redirect_ok", "pass", "HTTP redirects to HTTPS",
            "Visitors who use plain http:// are sent to the encrypted https:// site.",
            final_url,
        )]
    return [Finding(
        "http_no_redirect", "fail", "HTTP does not redirect to HTTPS",
        "The plain http:// site loads without moving visitors to https://. Anyone on the "
        "same network could read or change that traffic.",
        final_url,
    )]


# ---------- Security headers ----------
# Each check gets the headers from lowercase_headers(), so names are lower case.


def check_hsts(headers):
    if "strict-transport-security" in headers:
        return [Finding(
            "hsts_found", "pass", "Strict-Transport-Security is set",
            "Browsers are told to always use HTTPS for this site.",
            headers["strict-transport-security"],
        )]
    return [Finding(
        "hsts_missing", "warn", "No Strict-Transport-Security header",
        "Browsers are not told to always use HTTPS, so a first visit over plain HTTP "
        "could be intercepted.",
    )]


def check_csp(headers):
    if "content-security-policy" in headers:
        return [Finding(
            "csp_found", "pass", "Content-Security-Policy is set",
            "The site tells browsers which scripts and content it may load. This makes "
            "some attacks, like cross-site scripting, harder.",
            headers["content-security-policy"],
        )]
    return [Finding(
        "csp_missing", "warn", "No Content-Security-Policy header",
        "The site does not limit which scripts and content browsers may load.",
    )]


def check_x_content_type_options(headers):
    if headers.get("x-content-type-options", "").lower() == "nosniff":
        return [Finding(
            "xcto_found", "pass", "X-Content-Type-Options is nosniff",
            "Browsers are told not to guess file types, which blocks some tricks.",
        )]
    return [Finding(
        "xcto_missing", "warn", "No X-Content-Type-Options: nosniff",
        "Browsers may guess file types. An attacker can sometimes use this to run a file "
        "as a script.",
    )]


def check_frame_protection(headers):
    # Either header can stop other sites putting this site inside a frame (clickjacking).
    csp = headers.get("content-security-policy", "").lower()
    if "x-frame-options" in headers or "frame-ancestors" in csp:
        return [Finding(
            "frame_protection_found", "pass", "Frame protection is set",
            "The site uses X-Frame-Options or CSP frame-ancestors to stop other sites "
            "showing it inside a frame.",
        )]
    return [Finding(
        "frame_protection_missing", "warn", "No frame protection",
        "Other sites could show this site inside a hidden frame and trick users into "
        "clicking on it (clickjacking).",
    )]


def check_referrer_policy(headers):
    if "referrer-policy" in headers:
        return [Finding(
            "referrer_policy_found", "pass", "Referrer-Policy is set",
            "The site controls how much of its web address is shared with other sites "
            "when users click a link.",
            headers["referrer-policy"],
        )]
    return [Finding(
        "referrer_policy_missing", "warn", "No Referrer-Policy header",
        "The site does not set a Referrer-Policy, so browsers use their own default. "
        "Older browsers may share full page addresses with other sites.",
    )]


# ---------- security.txt ----------


def check_security_txt(status_code, text):
    # Some sites return their normal home page (status 200) for any address.
    # A real security.txt must have a "Contact:" line, so we look for that too.
    if status_code == 200 and "contact:" in text.lower():
        return [Finding(
            "security_txt_found", "pass", "security.txt found",
            "The site publishes /.well-known/security.txt, so people know how to report "
            "security problems.",
        )]
    return [Finding(
        "security_txt_missing", "warn", "No security.txt",
        "There is no /.well-known/security.txt file, so it is not clear how to report a "
        "security problem to this company.",
    )]


# ---------- Run all web checks ----------


def run_web_checks(domain, host, homepage):
    findings = []
    findings.extend(check_https(domain, host))
    if homepage is None:
        # Without a working HTTPS site, there is nothing more to check.
        return findings

    http_response = fetch("http://" + host + "/")
    final_url = ""
    if http_response is not None:
        final_url = http_response.url
    findings.extend(check_http_redirect(final_url))

    headers = lowercase_headers(homepage.headers)
    findings.extend(check_hsts(headers))
    findings.extend(check_csp(headers))
    findings.extend(check_x_content_type_options(headers))
    findings.extend(check_frame_protection(headers))
    findings.extend(check_referrer_policy(headers))

    security_txt = fetch("https://" + host + "/.well-known/security.txt")
    if security_txt is None:
        findings.extend(check_security_txt(0, ""))
    else:
        findings.extend(check_security_txt(security_txt.status_code, security_txt.text))

    return findings
