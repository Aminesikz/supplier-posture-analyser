from posture import questions
from posture import scoring
from posture.finding import Finding


def make_finding(check_id, status):
    return Finding(check_id, status, "title", "detail")


def test_no_problems_means_no_questions():
    findings = [make_finding("spf_all_ok", "pass"), make_finding("hsts_found", "pass")]
    assert questions.generate_questions(findings) == []


def test_dmarc_none_adds_a_question():
    result = questions.generate_questions([make_finding("dmarc_policy_none", "warn")])
    assert len(result) == 1
    assert "p=none" in result[0]


def test_questions_follow_the_order_in_questions_py():
    # The findings come in "wrong" order, but DMARC is more important than CAA.
    findings = [make_finding("caa_missing", "warn"), make_finding("dmarc_missing", "fail")]
    result = questions.generate_questions(findings)
    assert result[0] == questions.QUESTIONS["dmarc_missing"]
    assert result[1] == questions.QUESTIONS["caa_missing"]


def test_every_scored_problem_has_a_question():
    # Catches a typo or a forgotten question when a new weight is added.
    for check_id in scoring.WEIGHTS:
        assert check_id in questions.QUESTIONS
