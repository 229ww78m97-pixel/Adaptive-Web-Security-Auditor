# bb-assistant

Bug Bounty Analysis & Findings Assistant.

This project is being built as a legal-by-design, passive-first,
human-in-the-loop workspace for authorized bug bounty analysis. Version 0.2.0
packages the local passive workflow, persistence layer, reporting, and redacted
audit documentation.

## What It Is

bb-assistant is a local workspace for managing bug bounty program context,
scope, targets, authorizations, passive checks, check results, manually verified
findings, and Markdown reports.

It is designed around a defensive workflow:

1. Create a program.
2. Add in-scope and out-of-scope rules.
3. Add targets.
4. Confirm authorization.
5. Run passive checks through the Safe HTTP Client.
6. Review CheckResults manually.
7. Create Finding drafts only when manual review is needed.
8. Mark findings as human verified.
9. Render Markdown reports only for verified findings.

## What It Is Not

bb-assistant is not an exploit framework, aggressive scanner, credential testing
tool, crawler, or attack automation platform.

It intentionally does not include:

- Exploit automation
- Bruteforce
- Credential stuffing
- Password spraying
- DoS or DDoS behavior
- Social engineering
- WAF bypass
- Stealth or evasion logic
- Data exfiltration
- Active vulnerability exploitation

## Feature Overview

- Default-deny Scope Guard
- Out-of-scope rule priority
- Safe HTTP Client with safe mode default
- GET and HEAD only in safe mode
- Per-host rate limiter
- Passive checks for headers, CORS/CSP observations, cookie flags,
  `security.txt`, `robots.txt`, and basic HTTPS usage
- Passive technology profiler for coarse environment hints from response
  headers and visible HTML only
- Rule-based checklist engine for non-executable human review tasks
- SQLite persistence with SQLAlchemy 2.x
- Finding draft workflow with explicit human verification
- Jinja2 Markdown report generation
- Redacted Markdown/JSON audit-trail export for local documentation
- Minimal Streamlit UI for the end-to-end workflow
- Local deterministic test suite

## Architecture

Business logic lives in `src/bb_assistant/core/`.

The Streamlit interface in `src/bb_assistant/interfaces/` only orchestrates
existing core and persistence functions. Scope checks are not trusted to the UI:
the Safe HTTP Client enforces `ScopeGuard` before every request.

```text
src/bb_assistant/
  core/          Safety, checks, findings, reporting
  persistence/   SQLAlchemy models and repositories
  interfaces/    Streamlit UI orchestration
templates/       Markdown report templates
tests/           Local deterministic pytest suite
```

## Quick Start

```bash
cd /Users/michaelbruckner/CS
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On this local macOS setup, Homebrew Python may need:

```bash
DYLD_LIBRARY_PATH=/opt/homebrew/opt/expat/lib
```

Start the local Streamlit UI:

```bash
streamlit run src/bb_assistant/interfaces/streamlit_app.py
```

The UI uses a local SQLite database at `data/bb_assistant.sqlite3` and stores
generated Markdown reports in `reports/`.

## Run Tests

```bash
python -m pytest
```

Current local status:

```text
137 passed
```

## Safety Model

Safe mode is enabled by default. In safe mode, only `GET` and `HEAD` requests are
allowed. All outbound requests go through:

- `ScopeGuard`
- `RateLimiter`
- `SafeHttpClient`
- request logging hooks

Redirect targets are validated against scope before they are followed.

The v0.2 CORS and CSP analyzers are passive header observations only. They do
not perform origin reflection testing, bypass testing, payload testing, login
tests, or other active validation.

The passive technology profiler only classifies already observed headers, URLs,
status metadata, and visible HTML hints. It does not crawl, enumerate
subdomains, match CVEs, test logins, or create Findings.

The v0.2 checklist engine turns passive profile tags into human-in-the-loop
review tasks. Checklist items are never auto-executable and riskier topics are
marked as `explicit_permission_required`.

## Reporting

CheckResults are not Findings. They are observations.

Only findings with `human_verified=True` are reportable. The report generator
will block unverified findings with `ReportNotAllowedError`.

Audit-trail exports document local program context, scope, authorization,
targets, request logs, check results, findings, evidence, and reports. They are
redacted Markdown/JSON documentation only: they do not create findings, run
checks, or submit anything to a platform.

## Current Limitations

- The Streamlit UI is intentionally minimal and local-first.
- There is no bug bounty platform API integration.
- Passive checks do not prove exploitability.
- CORS and CSP analyzers do not perform bypass testing or Origin manipulation.
- The technology profiler does not crawl, enumerate subdomains, match CVEs, or
  test logins.
- Schema migrations are not yet managed with Alembic.

## Documentation

- [Changelog](CHANGELOG.md)
- [v0.2.0 release notes](docs/release-v0.2.md)
- [Screenshot placeholders](docs/screenshots.md)

## Legal Notice

Use this project only for authorized security research and bug bounty programs
where you have permission to test the target. You are responsible for following
program policy, applicable law, and rate limits.

## Roadmap v0.3

- Improve review workflows around CheckResults, Evidence, Findings, and Reports
- Add richer local filtering and export controls
- Improve Streamlit ergonomics while keeping Safe Mode as the default
- Add optional Alembic migrations if schema changes continue
- Expand passive documentation helpers without adding active testing behavior
