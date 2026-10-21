from dataclasses import dataclass


@dataclass
class Finding:
    check_id: str  # short name used by scoring and questions, e.g. "dmarc_policy_none"
    status: str  # "pass", "warn", "fail", "info" or "error"
    title: str  # one line for the terminal summary
    detail: str  # plain English explanation for the report
    evidence: str = ""  # the raw data we saw, e.g. the SPF record
