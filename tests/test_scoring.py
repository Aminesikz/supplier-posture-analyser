import pytest

from posture import scoring
from posture.finding import Finding


def make_finding(check_id, status):
    return Finding(check_id, status, "title", "detail")


def test_no_problems_scores_100():
    findings = [make_finding("spf_all_ok", "pass"), make_finding("dmarc_policy_ok", "pass")]
    assert scoring.calculate_score(findings) == 100


def test_points_are_subtracted():
    findings = [make_finding("dmarc_policy_none", "warn"), make_finding("hsts_missing", "warn")]
    assert scoring.calculate_score(findings) == 100 - 10 - 5


def test_info_and_error_cost_nothing():
    findings = [make_finding("dkim_not_found", "info"), make_finding("email_checks_failed", "error")]
    assert scoring.calculate_score(findings) == 100


def test_score_never_goes_below_zero():
    findings = []
    for check_id in scoring.WEIGHTS:
        findings.append(make_finding(check_id, "fail"))
    assert scoring.calculate_score(findings) == 0


def test_points_lost():
    assert scoring.points_lost(make_finding("spf_missing", "fail")) == 15
    assert scoring.points_lost(make_finding("spf_all_ok", "pass")) == 0


# Amine: remove ONLY the "@pytest.mark.skip" line once get_band is written.
@pytest.mark.skip(reason="get_band not written yet")
def test_get_band():
    assert scoring.get_band(100) == "good"
    assert scoring.get_band(80) == "good"
    assert scoring.get_band(79) == "needs work"
    assert scoring.get_band(50) == "needs work"
    assert scoring.get_band(49) == "poor"
    assert scoring.get_band(0) == "poor"
