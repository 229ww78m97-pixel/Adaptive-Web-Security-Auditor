# bb-assistant

Bug Bounty Analysis & Findings Assistant.

This project is being built as a legal-by-design, passive-first,
human-in-the-loop workspace for authorized bug bounty analysis. Version 0.1
starts with the safety core: domain models, scope validation, and tests.

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

## Features

- Default-deny Scope Guard
- Out-of-scope rule priority
- Safe HTTP Client with safe mode default
- GET and HEAD only in safe mode
- Per-host rate limiter
- Passive checks for headers, cookie flags, `security.txt`, `robots.txt`, and
  basic HTTPS usage
- SQLite persistence with SQLAlchemy 2.x
- Finding draft workflow with explicit human verification
- Jinja2 Markdown report generation
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

## Installation

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

## Test

```bash
python -m pytest
```

Current local status:

```text
64 passed
```

## Start Streamlit UI

```bash
cd /Users/michaelbruckner/CS
source .venv/bin/activate
streamlit run src/bb_assistant/interfaces/streamlit_app.py
```

The UI uses a local SQLite database at `data/bb_assistant.sqlite3` and stores
generated Markdown reports in `reports/`.

## Safe Mode

Safe mode is enabled by default. In safe mode, only `GET` and `HEAD` requests are
allowed. All outbound requests go through:

- `ScopeGuard`
- `RateLimiter`
- `SafeHttpClient`
- request logging hooks

Redirect targets are validated against scope before they are followed.

## Reporting

CheckResults are not Findings. They are observations.

Only findings with `human_verified=True` are reportable. The report generator
will block unverified findings with `ReportNotAllowedError`.

## Legal Notice

Use this project only for authorized security research and bug bounty programs
where you have permission to test the target. You are responsible for following
program policy, applicable law, and rate limits.

## Roadmap

- DB-backed request logging in the Streamlit workflow
- Richer report export options
- Program import/export
- Better review workflow for evidence
- Optional Alembic migrations when schema changes become frequent
