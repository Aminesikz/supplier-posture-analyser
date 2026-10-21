# CLAUDE.md

Rules for working on supplier-posture-analyser. Read these before every change.

## What this project is

- A small portfolio prototype, not a product. Owner: Amine (MSc Cyber Security, De Montfort University).
- I type a domain. The tool runs passive checks, gives a score, a plain English report, and a short list of questions to ask the supplier.
- Run with: `python -m posture.main example.com`
- Output: a short terminal summary, a JSON file and one HTML report (Jinja2).

## Scope for version 1 (do not add more checks without asking)

Email security (DNS):
- MX records exist
- SPF: exists, only one record, ends with -all or ~all (flag +all and ?all), 10 DNS lookups or fewer
- DMARC: exists, policy none / quarantine / reject, has a rua reporting address
- DKIM: try selectors google, selector1, selector2, default, k1. Not finding one does NOT prove DKIM is missing. Always say this.

Web and TLS:
- Site answers on HTTPS, and HTTP redirects to HTTPS
- Certificate days until expiry, TLS version negotiated (flag TLS 1.0 and 1.1)
- Headers: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options (or CSP frame-ancestors), Referrer-Policy
- /.well-known/security.txt exists
- CAA record exists

Not in version 1: DNSSEC, subdomain discovery, port scanning, anything active.

## Passive only (safety rules)

- Only DNS lookups and normal HTTP/HTTPS requests to the main site.
- No port scanning, no brute force, no fuzzing, no login attempts, no path guessing beyond the listed checks.
- Every network call has a timeout.
- Use a clear User-Agent that names the tool.
- Short pause between web requests.
- README must say: only check domains you own or have permission to assess.

## Tech

- Python 3.11+, argparse for the CLI.
- Allowed libraries: dnspython, requests, jinja2, pytest. Standard library ssl and socket for TLS.
- Do not add any other dependency without asking first.
- Questions-to-ask come from simple if-rules. No LLM.
- Scoring: start at 100, subtract per finding. All weights live in one dictionary in posture/scoring.py, each with a short comment on why.

## Code style

- Write like a careful junior developer. Simple functions, plain names, small files.
- No clever tricks, no design patterns, no async, no plugin systems.
- No classes, except the Finding dataclass.
- Short comments in simple English, only where something is not obvious. No long docstrings on every function.
- Amine must understand every line. If something needs a hard concept, explain it in chat first and keep the code simple.
- Tests use fake DNS answers and fake HTTP responses. Tests must never hit the real network.

## Docs style

- Plain, simple English, first person ("I built this to...").
- Short sentences. No marketing words (robust, seamless, powerful, leverage, comprehensive).
- No emojis, no badges, no big feature tables, no em dashes.
- Limitations must be honest and specific.

## How we work

- Build in small phases. Stop after each phase and wait for Amine to say "next".
- After each phase, say in a few lines what was built and which file to read first.
- Commit after each phase with a short, normal commit message.
- No CI and no Docker. Amine will add them later.
