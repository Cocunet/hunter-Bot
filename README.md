# HunterBot

[![CI](https://github.com/Cocunet/hunter-Bot/actions/workflows/ci.yml/badge.svg)](https://github.com/Cocunet/hunter-Bot/actions/workflows/ci.yml)

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
- `hunterbot/knowledge/` — two `KnowledgeExtractor` implementations behind the
  same interface: `RuleBasedExtractor` (default, offline, CWE/OWASP/severity
  detection via keyword heuristics) and `LLMKnowledgeExtractor` (optional,
  uses the Claude API with a structured-output schema for higher-recall
  extraction); keyword/metadata search; and optional semantic search
  (`SemanticIndex` Protocol + a TF-IDF/cosine-similarity default backend that
  needs no model download — falls back to keyword search when its `scikit-learn`
  dependency isn't installed, per the brief's "if a vector database is available")
- `hunterbot/learning/` — the continuous-learning engine: `KnowledgeDiffEngine`
  classifies freshly extracted knowledge as new, an exact duplicate, or an
  update to something already known (same source + title, changed content),
  and `KnowledgeMergeService` applies that — archiving the superseded version
  as a `KnowledgeItemRevision` before overwriting, so history is never lost
- `hunterbot/scanners/` + `hunterbot/plugins/` — the scanner plugin framework
  (a `ScannerPlugin` Protocol, a registry, and a safety-constrained
  `ScannerHttpClient`) plus seven built-in read-only plugins: missing security
  headers, sensitive/backup file exposure, directory listing exposure,
  information disclosure (verbose `Server`/`X-Powered-By` headers and
  well-known info-leak endpoints), cookie security (missing Secure/HttpOnly/
  SameSite), CORS misconfiguration (wildcard origin + allowed credentials),
  and open redirect (unvalidated redirect-parameter probing — the one plugin
  that needs `HttpClient.get_no_redirect`, since the shared client otherwise
  follows 3xx responses itself and the scanner would never see the
  vulnerable `Location` header)
- `hunterbot/reporting/` — a `ReportGenerator` interface with six
  implementations (Markdown, JSON, HTML, PDF, DOCX, XLSX), sorted
  most-severe-first and covering every `Finding` field
- `hunterbot/knowledge/correlation.py` — `KnowledgeCorrelationService`, which
  links each scan `Finding` to the best-matching `KnowledgeItem` (same
  `VulnerabilityCategory`, most shared significant words) so scan output and
  reports show *why* a finding matters, not just that it was found; linking
  is additive and optional — a scan runs identically well without it
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

# or extract with Claude instead of the rule-based heuristics
# (requires: pip install ".[llm]" and ANTHROPIC_API_KEY set)
hunterbot source ingest "OWASP Top 10" ./notes/owasp-top-10.md --extractor llm

# search the extracted knowledge base
hunterbot knowledge search --keyword injection
hunterbot knowledge search --cwe CWE-89
hunterbot knowledge search --category missing_security_headers

# semantic search ranks by similarity to free text rather than exact match
# (requires: pip install ".[semantic]"; otherwise falls back to keyword search)
hunterbot knowledge semantic-search "database query attack"

# re-ingesting a revised document updates the matching item in place and
# archives the prior version -- inspect that history:
hunterbot source ingest "OWASP Top 10" ./notes/owasp-top-10-v2.md
hunterbot knowledge history 1

# scan an authorized target (refuses if the hostname has no active Scope)
# each finding is automatically linked to the best-matching KnowledgeItem
# from the ingested knowledge base, when one exists in the same category
hunterbot scan run https://example.com

# generate a report from stored findings, in any supported format
# (a linked finding renders its knowledge source's title, not just its id)
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

Semantic search is an optional extra: `pip install ".[semantic]"` (or
`".[dev]"`, which includes it) installs `scikit-learn`. Without it,
`knowledge semantic-search` prints a warning and transparently falls back to
keyword search over the same query text — the rest of HunterBot works
identically either way.

The LLM-backed extractor is likewise optional: `pip install ".[llm]"` installs
the `anthropic` SDK; you also need `ANTHROPIC_API_KEY` set (or another
credential source the SDK resolves — see its docs) to actually call the API.
It defaults to Claude Opus 5 — override with `HUNTERBOT_ANTHROPIC_MODEL` if a
cheaper model suits a high-volume ingestion workload better. Extraction uses
a JSON-schema-constrained structured output (`client.messages.parse`) built
directly from HunterBot's `VulnerabilityCategory`/`Severity` enums, so the
model can only return values HunterBot already understands. A safety-policy
refusal on a given chunk of text yields zero items for that chunk rather than
an error — ingestion continues.

## Running tests

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

CI (`.github/workflows/ci.yml`) runs both of the above — lint then the full
test suite — on every push and pull request, against Python 3.11 and 3.12.

## Running with Docker

```bash
docker build -t hunterbot .

# the SQLite database lives at /data/hunterbot.db inside the container;
# mount a volume so it (and generated reports) persist across runs
docker run --rm -v hunterbot-data:/data hunterbot init-db
docker run --rm -v hunterbot-data:/data hunterbot scope add example.com \
  --program "Acme Bug Bounty" --authorized-by "Alice"
docker run --rm -v hunterbot-data:/data -v "$(pwd)/reports:/reports" hunterbot \
  report generate /reports/report.md --format markdown
```

The image installs the `semantic` and `llm` extras by default; pass
`ANTHROPIC_API_KEY` via `docker run -e ANTHROPIC_API_KEY=...` to use the
LLM-backed extractor from a container.

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
formats named in the original brief, optional semantic search, an
optional LLM-backed `KnowledgeExtractor`, and knowledge-to-finding
correlation. What's left is further depth, not structure: additional
scanner plugins (e.g. authentication/authorization/API-specific checks) —
each slots into an existing interface without touching the rest of the
system.

## Legal and ethical use

HunterBot is built exclusively for authorized defensive security testing —
bug bounty programs, pentest engagements, and CTFs where you have explicit
permission. Do not use it against systems you are not authorized to test.
