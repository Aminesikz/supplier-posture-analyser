# How many points each problem costs. The score starts at 100.
# These numbers are my own judgement, not an official standard.
# My rule: problems that let someone fake email or read traffic cost the most (10 to 20).
# Missing extra protection costs a little (1 to 5).
# Anything not listed here costs 0 points. That includes every "pass", every "info"
# (like no DKIM found, which we cannot prove), and every "error" (a check that could
# not finish should not count against the supplier).
WEIGHTS = {
    # ----- Email spoofing -----
    "dmarc_missing": 20,  # nothing tells mail servers to block fake email from this domain
    "dmarc_multiple": 20,  # the standard says to ignore DMARC then, so same as missing
    "spf_plus_all": 20,  # worse than no SPF: it approves fake email from any server
    "spf_missing": 15,  # less than DMARC, because SPF alone does not protect the visible "From"
    "dmarc_policy_none": 15,  # DMARC exists but only reports, it does not block anything
    "dmarc_policy_invalid": 15,  # mail servers usually treat a bad policy like p=none
    "spf_neutral_all": 10,  # SPF says nothing about servers that are not on the list
    "spf_multiple": 10,  # mail servers treat SPF as broken
    "spf_too_many_lookups": 10,  # mail servers stop at 10 lookups and treat SPF as broken
    "dmarc_no_rua": 3,  # no reports, so the owner cannot see abuse; does not block anything itself
    # ----- Website and TLS -----
    "https_missing": 20,  # no encrypted website at all
    "cert_invalid": 20,  # browsers show a warning, and users learn to click past warnings
    "http_no_redirect": 10,  # visitors can end up on the unencrypted site
    "tls_old_version": 10,  # TLS 1.0 and 1.1 have known weaknesses and are out of date
    "cert_expires_soon": 10,  # the site will break soon if nobody renews it
    "hsts_missing": 5,  # a first visit over plain HTTP could be intercepted
    "csp_missing": 3,  # extra protection against script injection, but hard to set up
    "frame_protection_missing": 3,  # clickjacking needs a page worth tricking users on
    "xcto_missing": 2,  # small extra protection, very easy to add
    "security_txt_missing": 2,  # not a weakness, but shows how mature the security process is
    "caa_missing": 2,  # small extra protection against wrongly issued certificates
    "referrer_policy_missing": 1,  # modern browsers already have a safe default
}

GOOD_SCORE = 80  # 80 to 100 is "good"
POOR_SCORE = 50  # below 50 is "poor" and in between is "needs work"


def points_lost(finding):
    return WEIGHTS.get(finding.check_id, 0)


def calculate_score(findings):
    score = 100
    for finding in findings:
        score = score - points_lost(finding)
    if score < 0:
        score = 0  # many problems together can go below zero, so stop at 0
    return score


def get_band(score):
    if score >= GOOD_SCORE:
        return "good"
    elif score >= POOR_SCORE:
        return "needs work"
    else:
        return "poor"


def count_errors(findings):
    # Checks that could not finish cost 0 points, so the score may be too high.
    error_count = 0
    for finding in findings:
        if finding.status == "error":
            error_count += 1
    return error_count
