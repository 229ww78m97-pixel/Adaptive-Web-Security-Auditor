# Contributing

Thanks for helping improve bb-assistant.

## Development Setup

```bash
cd /Users/michaelbruckner/CS
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pre-commit install
```

If Homebrew Python on macOS has trouble loading `pyexpat`, prefix commands with:

```bash
DYLD_LIBRARY_PATH=/opt/homebrew/opt/expat/lib
```

## Test

```bash
python -m pytest
```

## Contribution Rules

- Keep the tool passive-first and human-in-the-loop.
- Do not add exploit automation or destructive checks.
- Do not make tests call real external targets.
- Keep business logic in `src/bb_assistant/core/`.
- Keep Streamlit as orchestration only.

