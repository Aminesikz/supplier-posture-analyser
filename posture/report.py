import json
import os

from jinja2 import Environment, FileSystemLoader

from posture import scoring

# The templates folder sits next to this file, so this works from any folder.
TEMPLATE_FOLDER = os.path.join(os.path.dirname(__file__), "templates")


def build_report_data(domain, findings, score, band, questions, checked_at):
    # Put everything into plain dictionaries and lists, so it can be saved as JSON.
    finding_list = []
    for finding in findings:
        finding_list.append({
            "check_id": finding.check_id,
            "status": finding.status,
            "title": finding.title,
            "detail": finding.detail,
            "evidence": finding.evidence,
            "points_lost": scoring.points_lost(finding),
        })

    return {
        "domain": domain,
        "checked_at": checked_at,
        "score": score,
        "band": band,
        "error_count": scoring.count_errors(findings),
        "findings": finding_list,
        "questions": questions,
    }


def write_json(data, path):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def write_html(data, path):
    # autoescape=True turns characters like < and > into safe text.
    # This matters because evidence comes from the checked site (headers, DNS records),
    # and a hostile site could put HTML or a <script> tag in there.
    environment = Environment(loader=FileSystemLoader(TEMPLATE_FOLDER), autoescape=True)
    template = environment.get_template("report.html")
    html = template.render(report=data)
    with open(path, "w", encoding="utf-8") as file:
        file.write(html)


def write_reports(data, out_dir):
    # Saves <domain>.json and <domain>.html in out_dir. A new run overwrites them.
    # Returns the two file paths.
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, data["domain"] + ".json")
    html_path = os.path.join(out_dir, data["domain"] + ".html")
    write_json(data, json_path)
    write_html(data, html_path)
    return json_path, html_path
