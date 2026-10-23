import dns.resolver

from posture.finding import Finding

DNS_TIMEOUT = 5  # seconds allowed for each DNS lookup
DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1"]
MAX_SPF_LOOKUPS = 10  # the limit set by the SPF standard (RFC 7208)


# ---------- Fetching from DNS ----------
# These functions talk to the network. The check functions further down
# only read their results, so the tests can give them fake data.


def get_txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # The name does not exist, or it has no TXT records.
        return []

    records = []
    for answer in answers:
        # Long TXT records are split into chunks of up to 255 bytes. Join them back.
        text = b"".join(answer.strings).decode("utf-8", errors="replace")
        records.append(text)
    return records


def get_mx_hosts(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []

    hosts = []
    for answer in answers:
        host = str(answer.exchange).rstrip(".")
        # A "null MX" (host ".") means the domain accepts no mail, so skip it.
        if host != "":
            hosts.append(host)
    return hosts


def get_caa_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=DNS_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []

    records = []
    for answer in answers:
        # str() gives the record as text, e.g. '0 issue "letsencrypt.org"'
        records.append(str(answer))
    return records


def find_dkim_selectors(domain):
    found = []
    for selector in DKIM_SELECTORS:
        records = get_txt_records(selector + "._domainkey." + domain)
        for record in records:
            # The "p" tag holds the public key. An empty "p=" means the key was revoked,
            # which domains that never send email often publish on purpose.
            tags = parse_tags(record)
            if tags.get("p", "") != "":
                found.append(selector)
                break
    return found


# ---------- MX ----------


def check_mx(mx_hosts):
    if len(mx_hosts) > 0:
        return [Finding(
            "mx_found", "pass", "MX records found",
            "The domain has MX records, which tell other servers where to deliver its email.",
            "MX hosts: " + ", ".join(mx_hosts),
        )]
    return [Finding(
        "mx_missing", "info", "No MX records",
        "The domain has no MX records, so it may not receive email. This is not always a "
        "problem. Some domains are only used for a website.",
    )]


# ---------- SPF ----------


def find_spf_records(txt_records):
    spf_records = []
    for record in txt_records:
        text = record.lower()
        # "v=spf1" must be the whole record or be followed by a space.
        if text == "v=spf1" or text.startswith("v=spf1 "):
            spf_records.append(record)
    return spf_records


def get_spf_all_term(spf_record):
    # Returns "+all", "-all", "~all", "?all", or "" if there is no "all" term.
    for term in spf_record.lower().split():
        if term == "all" or term == "+all":
            return "+all"
        if term in ("-all", "~all", "?all"):
            return term
    return ""


def has_spf_redirect(spf_record):
    for term in spf_record.lower().split():
        if term.startswith("redirect="):
            return True
    return False


def check_spf(spf_records):
    if len(spf_records) == 0:
        return [Finding(
            "spf_missing", "fail", "No SPF record",
            "The domain has no SPF record. SPF tells mail servers which servers may send email "
            "for this domain. Without it, it is easier to send fake email that looks like it "
            "comes from this domain.",
        )]

    if len(spf_records) > 1:
        return [Finding(
            "spf_multiple", "fail", "More than one SPF record",
            "The domain has more than one SPF record. The standard says this is an error, so "
            "mail servers may ignore SPF for this domain completely.",
            " | ".join(spf_records),
        )]

    record = spf_records[0]
    all_term = get_spf_all_term(record)

    if all_term == "+all":
        return [Finding(
            "spf_plus_all", "fail", "SPF allows any server to send (+all)",
            "The SPF record ends with +all. This tells mail servers that any server in the "
            "world may send email for this domain, so SPF gives no protection.",
            record,
        )]

    if all_term == "-all" or all_term == "~all":
        return [Finding(
            "spf_all_ok", "pass", "SPF record ends with " + all_term,
            "The SPF record exists and tells mail servers to reject (-all) or mark as "
            "suspicious (~all) email from servers that are not on the list.",
            record,
        )]

    if all_term == "" and has_spf_redirect(record):
        return [Finding(
            "spf_all_via_redirect", "info", "SPF policy comes from a redirect",
            "The SPF record has no 'all' term but uses redirect= to point to another record. "
            "The final policy is in that other record. I did not check it in this version.",
            record,
        )]

    # What is left is "?all", or no "all" term at all. Both mean "neutral".
    return [Finding(
        "spf_neutral_all", "warn", "SPF does not say what to do with other servers",
        "The SPF record ends with ?all or has no 'all' term. This is 'neutral': mail servers "
        "are told nothing about email from servers that are not on the list.",
        record,
    )]


def is_spf_lookup_term(term):
    # These SPF terms each make the receiving mail server do one DNS lookup.
    # (include and redirect are handled separately because they point to more records.)
    if term in ("a", "mx", "ptr"):
        return True
    for start in ("a:", "a/", "mx:", "mx/", "ptr:", "exists:"):
        if term.startswith(start):
            return True
    return False


def count_spf_lookups(spf_record):
    # Count the DNS lookups a mail server must do to check this SPF record.
    # "include:" and "redirect=" point to other SPF records, and their lookups count too.
    # I keep a list of records still to read and work through it with a while loop.
    # Mail servers give up after 10 lookups, so I stop as soon as the count goes over 10.
    # This means a hostile record (or a loop of includes) can never make the tool do
    # more than 11 lookups here.
    count = 0
    records_to_read = [spf_record]

    while len(records_to_read) > 0 and count <= MAX_SPF_LOOKUPS:
        record = records_to_read.pop(0)

        for term in record.lower().split():
            if count > MAX_SPF_LOOKUPS:
                break

            # Remove the qualifier at the front, e.g. "~include:x" becomes "include:x".
            term = term.lstrip("+-~?")

            target = ""
            if term.startswith("include:"):
                target = term[len("include:"):]
            elif term.startswith("redirect="):
                target = term[len("redirect="):]

            if target != "":
                count += 1
                # Fetch the other domain's SPF record so we can count its lookups too.
                other_spf = find_spf_records(get_txt_records(target))
                if len(other_spf) > 0:
                    records_to_read.append(other_spf[0])
            elif is_spf_lookup_term(term):
                count += 1

    return count


def check_spf_lookups(lookup_count):
    if lookup_count > MAX_SPF_LOOKUPS:
        return [Finding(
            "spf_too_many_lookups", "fail", "SPF needs more than 10 DNS lookups",
            "The SPF record needs more than 10 DNS lookups. Mail servers stop at 10 and treat "
            "SPF as broken, so it may not protect the domain at all.",
        )]
    return [Finding(
        "spf_lookups_ok", "pass",
        "SPF needs " + str(lookup_count) + " DNS lookups (limit is 10)",
        "The SPF record stays inside the limit of 10 DNS lookups.",
    )]


# ---------- DMARC ----------


def find_dmarc_records(txt_records):
    dmarc_records = []
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            dmarc_records.append(record)
    return dmarc_records


def parse_tags(record):
    # DMARC and DKIM records are both lists of "key=value" separated by ";".
    # "v=DMARC1; p=none; rua=mailto:a@b.com"
    # becomes {"v": "DMARC1", "p": "none", "rua": "mailto:a@b.com"}
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(dmarc_records):
    if len(dmarc_records) == 0:
        return [Finding(
            "dmarc_missing", "fail", "No DMARC record",
            "The domain has no DMARC record. DMARC tells mail servers what to do with email "
            "that fails SPF and DKIM checks. Without it, fake email is often delivered.",
        )]

    if len(dmarc_records) > 1:
        return [Finding(
            "dmarc_multiple", "fail", "More than one DMARC record",
            "The domain has more than one DMARC record. The standard says mail servers must "
            "then ignore DMARC, so the domain has no DMARC protection.",
            " | ".join(dmarc_records),
        )]

    record = dmarc_records[0]
    tags = parse_tags(record)
    policy = tags.get("p", "").lower()
    findings = []

    if policy == "none":
        findings.append(Finding(
            "dmarc_policy_none", "warn", "DMARC policy is p=none (monitor only)",
            "DMARC is set to p=none. Mail servers only report on fake email. They do not "
            "block it or send it to spam.",
            record,
        ))
    elif policy == "quarantine" or policy == "reject":
        findings.append(Finding(
            "dmarc_policy_ok", "pass", "DMARC policy is p=" + policy,
            "DMARC tells mail servers to send failing email to spam (quarantine) or to "
            "refuse it (reject).",
            record,
        ))
    else:
        findings.append(Finding(
            "dmarc_policy_invalid", "fail", "DMARC policy is missing or not valid",
            "The DMARC record does not have a valid p= tag. It should be none, quarantine "
            "or reject.",
            record,
        ))

    if "rua" in tags:
        findings.append(Finding(
            "dmarc_rua_ok", "pass", "DMARC has a reporting address (rua)",
            "The domain asks mail servers to send DMARC reports, so the owner can see who "
            "is sending email in its name.",
            record,
        ))
    else:
        findings.append(Finding(
            "dmarc_no_rua", "warn", "DMARC has no reporting address (rua)",
            "The DMARC record has no rua= tag. The owner gets no reports, so they cannot see "
            "if someone is sending fake email in their name.",
            record,
        ))

    return findings


# ---------- DKIM ----------


def check_dkim(found_selectors):
    tried = ", ".join(DKIM_SELECTORS)
    if len(found_selectors) > 0:
        return [Finding(
            "dkim_found", "pass", "DKIM key found (" + ", ".join(found_selectors) + ")",
            "I found a DKIM public key for at least one common selector. DKIM lets mail "
            "servers check that email was signed by the domain.",
            "Selectors tried: " + tried,
        )]
    return [Finding(
        "dkim_not_found", "info", "No DKIM key found for common selectors",
        "I did not find a DKIM key for the common selectors I tried. This does NOT prove "
        "DKIM is missing. DKIM selectors can have any name, and there is no way to list "
        "them from DNS.",
        "Selectors tried: " + tried,
    )]


# ---------- CAA ----------


def check_caa(caa_records):
    if len(caa_records) > 0:
        return [Finding(
            "caa_found", "pass", "CAA record found",
            "The domain lists which certificate authorities may issue certificates for it. "
            "This makes it harder to get a fake certificate for the domain.",
            " | ".join(caa_records),
        )]
    return [Finding(
        "caa_missing", "warn", "No CAA record",
        "The domain does not limit which certificate authorities may issue certificates "
        "for it. Any public authority could issue one.",
    )]


# ---------- Run all email checks ----------


def run_email_checks(domain):
    findings = []

    findings.extend(check_mx(get_mx_hosts(domain)))

    spf_records = find_spf_records(get_txt_records(domain))
    findings.extend(check_spf(spf_records))
    # Only count lookups when there is exactly one SPF record to count.
    if len(spf_records) == 1:
        lookup_count = count_spf_lookups(spf_records[0])
        findings.extend(check_spf_lookups(lookup_count))

    dmarc_records = find_dmarc_records(get_txt_records("_dmarc." + domain))
    findings.extend(check_dmarc(dmarc_records))

    findings.extend(check_dkim(find_dkim_selectors(domain)))

    return findings
