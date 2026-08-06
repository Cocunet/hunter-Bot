# HunterBot

A modular, AI-assisted platform for **authorized** bug bounty and defensive
security assessments. HunterBot ingests trusted educational security
resources into a structured, versioned knowledge base and uses that
knowledge to improve vulnerability discovery — strictly against targets you
are explicitly authorized to test.

> HunterBot enforces authorization at the architecture level: every scan
> use-case must pass through `hunterbot.authorization`, which denies by
> default unless a target matches an active, non-expired `Scope` record.
> There is no bypass path.

## Status

This repository is being built incrementally, phase by phase. Implemented so far:

- `hunterbot/core/` — domain models and interfaces, no I/O dependencies
- `hunterbot/config/` — environment-based application settings
- `hunterbot/storage/` — SQLAlchemy models and repositories (SQLite by default)
- `hunterbot/authorization/` — the deny-by-default scan authorization gate
- `hunterbot/ingestion/` — Markdown/HTML/PDF connectors, text normalization, and
  an incremental ingestion pipeline (fetch → normalize → extract → dedupe → persist)
- `hunterbot/knowledge/` — a rule-based `KnowledgeExtractor` (CWE/OWASP/severity
  detection via keyword heuristics, behind an interface an LLM-backed extractor
  can later implement) and keyword/metadata search
- `hunterbot/cli/` — a Typer CLI covering scopes, sources, ingestion, and search

The learning engine (versioning/merge across re-ingestion), the scanner plugin
framework, and reporting are designed (see project history) but not yet
implemented — they land in subsequent slices.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# create the local SQLite database (./hunterbot.db by default)
hunterbot init-db

# register an authorized scan target
hunterbot scope add example.com --program "Acme Bug Bounty" --authorized-by "Alice"

# check whether a target is currently authorized (subdomains match too)
hunterbot scope check api.example.com

# register a knowledge source, then ingest a local document into it
hunterbot source add "OWASP Top 10" --type documentation --url https://owasp.org/www-project-top-ten/
hunterbot source ingest "OWASP Top 10" ./notes/owasp-top-10.md
hunterbot source list

# search the extracted knowledge base
hunterbot knowledge search --keyword injection
hunterbot knowledge search --cwe CWE-89
hunterbot knowledge search --category missing_security_headers
```

Supported ingestion file types today: `.md`/`.markdown`, `.html`/`.htm`, `.pdf`
(all read from local disk — network crawling connectors land in a later slice).

Configuration is read from environment variables prefixed `HUNTERBOT_` (or a
`.env` file), e.g. `HUNTERBOT_DATABASE_URL=postgresql://...` to move off SQLite.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## Architecture

HunterBot follows Clean Architecture: `core/` holds domain models and
interfaces and depends on nothing else in the tree; every other package
(`storage/`, `authorization/`, `cli/`, and future `ingestion/`, `knowledge/`,
`scanners/`, `reporting/`) implements or consumes those interfaces. This
keeps the storage backend, scanner plugins, and report formats swappable
without touching core logic.

## Legal and ethical use

HunterBot is built exclusively for authorized defensive security testing —
bug bounty programs, pentest engagements, and CTFs where you have explicit
permission. Do not use it against systems you are not authorized to test.
