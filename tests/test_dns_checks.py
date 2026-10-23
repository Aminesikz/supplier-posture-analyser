from posture import dns_checks

# A pretend DNS. Each name maps to the TXT records it would return.
# The ".test" ending is reserved for testing, so these names never exist for real.
FAKE_TXT_RECORDS = {
    # SPF include chains for the lookup counting tests
    "small.test": ["v=spf1 include:_spf.mailer.test -all"],
    "_spf.mailer.test": ["v=spf1 ip4:192.0.2.0/24 a mx -all"],
    "loop-a.test": ["v=spf1 include:loop-b.test -all"],
    "loop-b.test": ["v=spf1 include:loop-a.test -all"],
    "big.test": [
        "v=spf1 include:one.test include:two.test include:three.test "
        "include:four.test a mx -all"
    ],
    "one.test": ["v=spf1 a mx -all"],
    "two.test": ["v=spf1 a mx -all"],
    "three.test": ["v=spf1 a mx -all"],
    "four.test": ["v=spf1 a mx -all"],
    # DKIM keys
    "selector1._domainkey.dkim.test": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"],
    "google._domainkey.dkim.test": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B"],
    "default._domainkey.dkim.test": ["v=DKIM1; p="],  # empty key = revoked
}


def fake_get_txt_records(name):
    return FAKE_TXT_RECORDS.get(name, [])


def get_ids(findings):
    ids = []
    for finding in findings:
        ids.append(finding.check_id)
    return ids


# ---------- MX ----------


def test_mx_found():
    findings = dns_checks.check_mx(["mail1.example.test", "mail2.example.test"])
    assert get_ids(findings) == ["mx_found"]
    assert findings[0].status == "pass"


def test_mx_missing():
    findings = dns_checks.check_mx([])
    assert get_ids(findings) == ["mx_missing"]
    assert findings[0].status == "info"


# ---------- SPF ----------


def test_find_spf_records_ignores_other_txt():
    txt = ["google-site-verification=abc", "v=spf1 -all", "v=spf10 nonsense"]
    assert dns_checks.find_spf_records(txt) == ["v=spf1 -all"]


def test_spf_missing():
    assert get_ids(dns_checks.check_spf([])) == ["spf_missing"]


def test_spf_multiple():
    records = ["v=spf1 -all", "v=spf1 include:x.test -all"]
    assert get_ids(dns_checks.check_spf(records)) == ["spf_multiple"]


def test_spf_hard_fail_is_ok():
    findings = dns_checks.check_spf(["v=spf1 include:_spf.google.com -all"])
    assert get_ids(findings) == ["spf_all_ok"]
    assert findings[0].status == "pass"


def test_spf_soft_fail_is_ok():
    assert get_ids(dns_checks.check_spf(["v=spf1 mx ~all"])) == ["spf_all_ok"]


def test_spf_plus_all():
    assert get_ids(dns_checks.check_spf(["v=spf1 +all"])) == ["spf_plus_all"]


def test_spf_bare_all_means_plus_all():
    assert get_ids(dns_checks.check_spf(["v=spf1 mx all"])) == ["spf_plus_all"]


def test_spf_question_all():
    assert get_ids(dns_checks.check_spf(["v=spf1 mx ?all"])) == ["spf_neutral_all"]


def test_spf_no_all_term():
    assert get_ids(dns_checks.check_spf(["v=spf1 mx"])) == ["spf_neutral_all"]


def test_spf_redirect_without_all():
    findings = dns_checks.check_spf(["v=spf1 redirect=_spf.example.test"])
    assert get_ids(findings) == ["spf_all_via_redirect"]


def test_count_lookups_simple_record():
    # a, mx and include each count as one lookup. ip4 does not count.
    assert dns_checks.count_spf_lookups("v=spf1 ip4:192.0.2.1 a mx -all") == 2


def test_count_lookups_follows_includes(monkeypatch):
    monkeypatch.setattr(dns_checks, "get_txt_records", fake_get_txt_records)
    # 1 for the include, then 2 more (a, mx) inside _spf.mailer.test
    assert dns_checks.count_spf_lookups(FAKE_TXT_RECORDS["small.test"][0]) == 3


def test_count_lookups_over_limit(monkeypatch):
    monkeypatch.setattr(dns_checks, "get_txt_records", fake_get_txt_records)
    # 4 includes + a + mx = 6, then each include has a + mx = 8 more. Total 14.
    count = dns_checks.count_spf_lookups(FAKE_TXT_RECORDS["big.test"][0])
    assert count == 14
    assert get_ids(dns_checks.check_spf_lookups(count)) == ["spf_too_many_lookups"]


def test_count_lookups_stops_on_include_loop(monkeypatch):
    monkeypatch.setattr(dns_checks, "get_txt_records", fake_get_txt_records)
    # loop-a includes loop-b, which includes loop-a again. The safety limit must stop it.
    count = dns_checks.count_spf_lookups(FAKE_TXT_RECORDS["loop-a.test"][0])
    assert count == dns_checks.MAX_SPF_RECORDS_TO_READ


def test_spf_lookups_ok():
    assert get_ids(dns_checks.check_spf_lookups(10)) == ["spf_lookups_ok"]


# ---------- DMARC ----------


def test_parse_tags():
    tags = dns_checks.parse_tags("v=DMARC1; p=reject; rua=mailto:dmarc@example.test")
    assert tags == {"v": "DMARC1", "p": "reject", "rua": "mailto:dmarc@example.test"}


def test_dmarc_missing():
    assert get_ids(dns_checks.check_dmarc([])) == ["dmarc_missing"]


def test_dmarc_multiple():
    records = ["v=DMARC1; p=none", "v=DMARC1; p=reject"]
    assert get_ids(dns_checks.check_dmarc(records)) == ["dmarc_multiple"]


def test_dmarc_policy_none_without_rua():
    findings = dns_checks.check_dmarc(["v=DMARC1; p=none"])
    assert get_ids(findings) == ["dmarc_policy_none", "dmarc_no_rua"]


def test_dmarc_reject_with_rua():
    findings = dns_checks.check_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.test"])
    assert get_ids(findings) == ["dmarc_policy_ok", "dmarc_rua_ok"]


def test_dmarc_policy_is_not_case_sensitive():
    findings = dns_checks.check_dmarc(["v=DMARC1; p=Quarantine; rua=mailto:d@example.test"])
    assert get_ids(findings) == ["dmarc_policy_ok", "dmarc_rua_ok"]


def test_dmarc_invalid_policy():
    findings = dns_checks.check_dmarc(["v=DMARC1; p=block; rua=mailto:d@example.test"])
    assert get_ids(findings) == ["dmarc_policy_invalid", "dmarc_rua_ok"]


# ---------- DKIM ----------


def test_find_dkim_selectors(monkeypatch):
    monkeypatch.setattr(dns_checks, "get_txt_records", fake_get_txt_records)
    # The order follows DKIM_SELECTORS, so "google" comes first.
    # "default" has an empty (revoked) key, so it must not count as found.
    assert dns_checks.find_dkim_selectors("dkim.test") == ["google", "selector1"]


def test_dkim_found():
    findings = dns_checks.check_dkim(["selector1"])
    assert get_ids(findings) == ["dkim_found"]
    assert findings[0].status == "pass"


def test_dkim_not_found_is_info_and_says_it_is_not_proof():
    findings = dns_checks.check_dkim([])
    assert get_ids(findings) == ["dkim_not_found"]
    assert findings[0].status == "info"
    assert "does NOT prove" in findings[0].detail


# ---------- CAA ----------


def test_caa_found():
    findings = dns_checks.check_caa(['0 issue "letsencrypt.org"'])
    assert get_ids(findings) == ["caa_found"]


def test_caa_missing():
    assert get_ids(dns_checks.check_caa([])) == ["caa_missing"]
