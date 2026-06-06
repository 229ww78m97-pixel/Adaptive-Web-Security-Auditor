# v0.2.0 Release Notes

## Summary

v0.2.0 packages bb-assistant as a passive-first, local bug bounty workspace for
authorized research. It focuses on scope validation, safe request handling,
passive observations, evidence management, human verification, Markdown reports,
and redacted audit exports.

## Features

- Default-deny Scope Guard with out-of-scope priority
- Safe HTTP Client with Safe Mode and scoped redirects
- Per-host Rate Limiter
- SQLite persistence layer with SQLAlchemy repositories
- Passive checks for security headers, cookies, TLS basics, security.txt, and robots.txt
- Passive CORS and CSP analyzers
- DBRequestLogger for persisted request metadata
- Evidence Manager with redaction and SHA256 hashing
- Finding draft workflow with explicit human verification
- Technical and management Markdown report generation
- Passive Tech Profiler based on observed headers and visible HTML
- Checklist Engine for non-executable human review tasks
- Redacted program and target audit-trail export
- Minimal Streamlit UI for the end-to-end workflow

## Safety Boundaries

- No exploit automation
- No brute force
- No credential testing
- No DoS/DDoS behavior
- No WAF bypass
- No stealth or evasion logic
- No data exfiltration
- No platform submission API
- CheckResults remain observations and are not Findings
- Only human-verified Findings are reportable

## How To Run

```bash
cd /Users/michaelbruckner/CS
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
streamlit run src/bb_assistant/interfaces/streamlit_app.py
```

## How To Test

```bash
cd /Users/michaelbruckner/CS
source .venv/bin/activate
python -m pytest
ruff check .
ruff format --check .
mypy src/bb_assistant --ignore-missing-imports
pre-commit run --all-files
```

## Known Limitations

- The UI is intentionally minimal and local-first.
- There is no platform API integration or submission workflow.
- Passive checks do not validate exploitability.
- CORS and CSP analysis is observational only and does not perform bypass testing.
- The tech profiler does not crawl, enumerate subdomains, match CVEs, or test logins.
- Schema migrations are not yet managed by Alembic.

## Next Planned v0.3 Direction

- Improve the review workflow around check results, evidence, and findings
- Add richer local export and filtering options
- Improve Streamlit ergonomics without changing the passive safety model
- Add migration tooling if schema changes continue
