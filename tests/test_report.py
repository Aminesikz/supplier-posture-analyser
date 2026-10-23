import json
import os

from posture import report
from posture.finding import Finding


def make_sample_data():
    findings = [
        Finding("dmarc_policy_none", "warn", "DMARC policy is p=none", "Detail text", "v=DMARC1; p=none"),
        Finding("hsts_found", "pass", "Strict-Transport-Security is set", "Detail text"),
    ]
    questions = ["When do you plan to move to p=quarantine or p=reject?"]
    return report.build_report_data("example.test", findings, 85, "good", questions, "2026-01-01 12:00 UTC")


def test_build_report_data():
    data = make_sample_data()
    assert data["domain"] == "example.test"
    assert data["score"] == 85
    assert data["error_count"] == 0
    assert len(data["findings"]) == 2
    assert data["findings"][0]["points_lost"] == 15
    assert data["findings"][1]["points_lost"] == 0


# tmp_path is a fresh empty folder that pytest makes for each test and cleans up later.
def test_write_reports_creates_both_files(tmp_path):
    json_path, html_path = report.write_reports(make_sample_data(), str(tmp_path))
    assert os.path.exists(json_path)
    assert os.path.exists(html_path)


def test_json_can_be_read_back(tmp_path):
    json_path, html_path = report.write_reports(make_sample_data(), str(tmp_path))
    with open(json_path, encoding="utf-8") as file:
        saved = json.load(file)
    assert saved["domain"] == "example.test"
    assert saved["findings"][0]["check_id"] == "dmarc_policy_none"


def test_html_shows_score_and_questions(tmp_path):
    json_path, html_path = report.write_reports(make_sample_data(), str(tmp_path))
    with open(html_path, encoding="utf-8") as file:
        html = file.read()
    assert "85/100 (good)" in html
    assert "When do you plan to move to p=quarantine or p=reject?" in html


def test_html_escapes_evidence_from_the_site(tmp_path):
    # A hostile site could put a script in a header. It must show as text, not run.
    findings = [Finding("csp_found", "pass", "CSP is set", "Detail", "<script>alert(1)</script>")]
    data = report.build_report_data("example.test", findings, 100, "good", [], "2026-01-01 12:00 UTC")
    json_path, html_path = report.write_reports(data, str(tmp_path))
    with open(html_path, encoding="utf-8") as file:
        html = file.read()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
