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
  an incremental ingestion pipeline (fetch → normalize → extract → learn → persist)
- `hunterbot/knowledge/` — a rule-based `KnowledgeExtractor` (CWE/OWASP/severity
  detection via keyword heuristics, behind an interface an LLM-backed extractor
  can later implement) and keyword/metadata search
- `hunterbot/learning/` — the continuous-learning engine: `KnowledgeDiffEngine`
  classifies freshly extracted knowledge as new, an exact duplicate, or an
  update to something already known (same source + title, changed content),
  and `KnowledgeMergeService` applies that — archiving the superseded version
  as a `KnowledgeItemRevision` before overwriting, so history is never lost
- `hunterbot/scanners/` + `hunterbot/plugins/` — the scanner plugin framework
  (a `ScannerPlugin` Protocol, a registry, and a safety-constrained
  `ScannerHttpClient`) plus two built-in read-only plugins: missing security
  headers and sensitive/backup file exposure
- `hunterbot/reporting/` — a `ReportGenerator` interface with six
  implementations (Markdown, JSON, HTML, PDF, DOCX, XLSX), sorted
  most-severe-first and covering every `Finding` field
- `hunterbot/cli/` — a Typer CLI covering scopes, sources, ingestion, search,
  revision history, scans, and reports

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

# re-ingesting a revised document updates the matching item in place and
# archives the prior version -- inspect that history:
hunterbot source ingest "OWASP Top 10" ./notes/owasp-top-10-v2.md
hunterbot knowledge history 1

# scan an authorized target (refuses if the hostname has no active Scope)
hunterbot scan run https://example.com

# generate a report from stored findings, in any supported format
hunterbot report generate ./report.md --format markdown
hunterbot report generate ./report.json --format json
hunterbot report generate ./report.html --format html
hunterbot report generate ./report.pdf --format pdf
hunterbot report generate ./report.docx --format docx
hunterbot report generate ./report.xlsx --format xlsx
hunterbot report generate ./report.md --format markdown --asset https://example.com
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
(`storage/`, `authorization/`, `ingestion/`, `knowledge/`, `scanners/`,
`plugins/`, `reporting/`, `cli/`) implements or consumes those interfaces.
This keeps the storage backend, scanner plugins, and report formats
swappable without touching core logic — e.g. `RunScanUseCase` depends only
on the `ScannerPlugin`/`HttpClient` Protocols and `GenerateReportUseCase`
depends only on the `ReportGenerator` Protocol; the concrete `httpx`-based
`ScannerHttpClient` and the Markdown/JSON/HTML generators are injected by
the CLI (the composition root) instead. The same pattern applies to
`hunterbot/learning/`: `KnowledgeMergeService` depends on the
`KnowledgeRepository`/`KnowledgeRevisionRepository` Protocols, not on
SQLAlchemy directly.

Every module described above from the original architecture is now
implemented end-to-end and covered by tests, including all six report
formats named in the original brief. What's left is further depth, not
structure: a semantic/vector search layer alongside the existing keyword
search, more scanner plugins, and an optional LLM-backed
`KnowledgeExtractor` — each slots into an existing interface without
touching the rest of the system.

## Legal and ethical use

HunterBot is built exclusively for authorized defensive security testing —
bug bounty programs, pentest engagements, and CTFs where you have explicit
permission. Do not use it against systems you are not authorized to test.
