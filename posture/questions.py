# One question for each problem. If a finding with this check_id shows up,
# the question goes on the list for the supplier.
# The order here is the order the questions are shown, so the most important come first.
QUESTIONS = {
    # ----- Email spoofing -----
    "spf_plus_all": "Your SPF record ends with +all, which approves email from any server. "
                    "Can you change it to list only your real mail servers and end with -all or ~all?",
    "dmarc_missing": "Your domain has no DMARC record. Do you have a plan to add one, and by when?",
    "dmarc_multiple": "Your domain has more than one DMARC record, so mail servers ignore all of them. "
                      "Can you merge them into one?",
    "dmarc_policy_none": "Your DMARC policy is p=none, so fake email in your name is not blocked. "
                         "When do you plan to move to p=quarantine or p=reject?",
    "dmarc_policy_invalid": "Your DMARC record does not have a valid policy. Can you set p= to none, "
                            "quarantine or reject?",
    "spf_missing": "Your domain has no SPF record. Which servers send email for you, and can you "
                   "publish them in an SPF record?",
    "spf_multiple": "Your domain has more than one SPF record, so mail servers treat SPF as broken. "
                    "Can you merge them into one?",
    "spf_too_many_lookups": "Your SPF record needs more than 10 DNS lookups, so mail servers may treat it "
                            "as broken. Can you remove services you no longer use?",
    "spf_neutral_all": "Your SPF record ends with ?all or has no 'all' at the end. Can you end it with "
                       "-all or ~all so other servers are rejected or flagged?",
    "dmarc_no_rua": "Your DMARC record has no reporting address. Who would notice if someone started "
                    "sending fake email in your name?",
    "dkim_not_found": "I could not find a DKIM key with common names. Do you sign outgoing email with "
                      "DKIM, and which selector do you use?",
    # ----- Website and TLS -----
    "https_missing": "Your website does not answer on HTTPS. Is there a reason, and do you plan to add it?",
    "cert_invalid": "Your website certificate is not trusted by browsers. Who manages it, and when "
                    "will it be fixed?",
    "tls_old_version": "Your server uses TLS 1.0 or 1.1. When do you plan to turn these off?",
    "cert_expires_soon": "Your website certificate runs out soon. Is renewal automatic?",
    "http_no_redirect": "Your website still loads over plain HTTP. Can you redirect all visitors to HTTPS?",
    "hsts_missing": "Your website does not send Strict-Transport-Security. Can you add it?",
    "csp_missing": "Your website has no Content-Security-Policy. Is one planned?",
    "frame_protection_missing": "Your website does not stop other sites from showing it in a frame. "
                                "Can you add X-Frame-Options or CSP frame-ancestors?",
    "xcto_missing": "Your website does not send X-Content-Type-Options: nosniff. Can you add it?",
    "referrer_policy_missing": "Your website does not set a Referrer-Policy. Can you add one?",
    "caa_missing": "Your domain has no CAA record. Would you consider adding one for the certificate "
                   "authorities you use?",
    "security_txt_missing": "There is no security.txt on your website. How should someone report a "
                            "security problem to you?",
}


def generate_questions(findings):
    found_ids = []
    for finding in findings:
        found_ids.append(finding.check_id)

    # Go through QUESTIONS (not the findings), so the questions keep the order above.
    questions = []
    for check_id in QUESTIONS:
        if check_id in found_ids:
            questions.append(QUESTIONS[check_id])
    return questions
