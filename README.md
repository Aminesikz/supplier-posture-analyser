# supplier-posture-analyser

## What it is

A small command line tool. You give it a domain, and it runs a few passive security checks on the domain's email setup and website. It prints a score, writes a JSON file and an HTML report, and lists questions to ask that supplier.

It is a student prototype, not a product.

Only check domains you own or have permission to assess.

## Why I built it

Small UK businesses are often asked by customers, insurers and bigger companies to show that they and their suppliers are secure. Checking a supplier usually means a long questionnaire. Most owners also cannot tell if a supplier's domain could be used to send fake email.

I wanted a quick first look based only on public information, with questions in plain English that an owner can send to the supplier. I also wanted to practise Python and what I learned about email and web security during my MSc in Cyber Security at De Montfort University.

## How to install

You need Python 3.11 or newer. I tested it on Python 3.14.

```
git clone https://github.com/Aminesikz/supplier-posture-analyser.git
cd supplier-posture-analyser
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## How to use

```
python -m posture.main example.com
```

This prints a summary and saves `reports/example.com.json` and `reports/example.com.html`. Use `--out-dir` to save them somewhere else.

This is part of the real output for example.com:

```
  [INFO ] No MX records
  [PASS ] SPF record ends with -all
  [PASS ] DMARC policy is p=reject
  [WARN ] DMARC has no reporting address (rua) (-3)
  [INFO ] No DKIM key found for common selectors
  [FAIL ] HTTP does not redirect to HTTPS (-10)
  [WARN ] No Strict-Transport-Security header (-5)
  ...
Score: 69/100 (needs work)

Questions to ask this supplier:
  1. Your DMARC record has no reporting address. Who would notice if someone started sending fake email in your name?
  2. Your website still loads over plain HTTP. Can you redirect all visitors to HTTPS?
  ...
```

The full sample report is in `examples/`.

To run the tests:

```
python -m pytest
```

The tests use fake DNS and web data, so they do not need the internet.

## What it checks

Email (DNS):
- MX records exist
- SPF exists, there is only one SPF record, it ends with `-all` or `~all`, and it needs 10 DNS lookups or fewer
- DMARC exists, its policy (none, quarantine or reject), and if it has a reporting address (rua)
- DKIM keys for a few common selectors: google, selector1, selector2, default, k1

Website and TLS:
- The site answers on HTTPS (if the bare domain does not, I try www and say so in the report)
- Plain HTTP redirects to HTTPS
- Days until the certificate expires, and if it is valid
- The TLS version the server chooses (TLS 1.0 and 1.1 are flagged)
- Security headers: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options (or CSP frame-ancestors) and Referrer-Policy
- `/.well-known/security.txt` exists
- A CAA record exists

All checks are passive. The tool only does DNS lookups and normal web requests to the main site. Every request has a timeout, a User-Agent that names the tool, and a 1 second pause before it.

## How the score works

The score starts at 100. Each problem takes points off. The score never goes below 0.

- 80 to 100 is good
- 50 to 79 needs work
- below 50 is poor

My rule for the weights is simple. Problems that let someone send fake email in the supplier's name, or read their web traffic, cost the most (10 to 20 points). Missing extra protection costs a little (1 to 5 points). For example, no DMARC record costs 20, DMARC with `p=none` costs 15, and no Referrer-Policy costs 1.

The full list, with one line about why for each weight, is in `posture/scoring.py`.

Some results cost nothing. No DKIM found costs 0, because I cannot prove it is missing. A check that could not finish (for example a DNS timeout) also costs 0, and the report says the score may be too high.

## Limitations

- The weights are my own judgement. They are not an official standard.
- DKIM selector guessing is incomplete. Selectors can have any name, so "not found" does not mean DKIM is missing.
- Headers are only checked on the home page. Other pages can send different headers. If the home page redirects to another site, I check the headers of that site.
- The TLS check only shows the version the server chooses. A server can still allow TLS 1.0 as a fallback, and this tool will not see that.
- If an SPF record uses `redirect=` instead of ending with `all`, I do not follow the redirect to check its policy.
- SPF lookup counting does not expand SPF macros.
- CAA is only checked on the exact domain, not on its parent domain.
- security.txt only needs to exist and have a `Contact:` line. I do not check its expiry date or signature.
- A supplier may send email from other domains or services. I only check the one domain I am given.
- This is a quick outside view. It does not replace a proper assessment or a scheme like Cyber Essentials.

## What I would add next

- DNSSEC, MTA-STS and TLS-RPT checks
- Follow SPF `redirect=` and check the final policy
- Check a list of domains from a CSV file
- Compare two reports to see what changed over time
- Run the tests on Python 3.11 and newer in CI
