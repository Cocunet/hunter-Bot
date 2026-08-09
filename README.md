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
- `knowledge_sources/owasp-risk-rating-scale.md` — a bundled, ready-to-ingest
  reference: OWASP's Risk Rating Methodology (Likelihood × Impact) applied to
  16 real-world variants across four vulnerability classes (CORS
  misconfiguration, XSS, race conditions, file upload → RCE), each carrying a
  CWE id, an OWASP Top 10 tag, and a severity from low/informational through
  critical. Written so `RuleBasedExtractor`'s keyword heuristics split it into
  one `KnowledgeItem` per variant in the right `VulnerabilityCategory` — see
  the Quick start below to ingest it. `tests/knowledge/test_owasp_risk_rating_source.py`
  ingests the real file and confirms a live `cors-misconfiguration` scan
  finding correlates to its matching entry, so an edit that breaks extraction
  fails a test instead of silently going stale
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
  `ScannerHttpClient`) plus nine built-in read-only plugins: missing security
  headers, sensitive/backup file exposure, directory listing exposure,
  information disclosure (verbose `Server`/`X-Powered-By` headers and
  well-known info-leak endpoints), cookie security (missing Secure/HttpOnly/
  SameSite), CORS misconfiguration (wildcard origin + allowed credentials),
  open redirect (unvalidated redirect-parameter probing — the one plugin
  that needs `HttpClient.get_no_redirect`, since the shared client otherwise
  follows 3xx responses itself and the scanner would never see the
  vulnerable `Location` header), HTTP method tampering (a single OPTIONS
  request — itself a safe, read-only method per RFC 7231 — flags PUT/DELETE/
  TRACE/CONNECT advertised in the `Allow` header without ever issuing one),
  and admin/debug interface exposure (Werkzeug console, Symfony profiler,
  ELMAH, Spring Boot Actuator heap dumps, Adminer/phpMyAdmin — control
  surfaces, not just information leaks, at well-known paths)
- `hunterbot/core/use_cases/run_access_control_scan.py` —
  `RunAccessControlScanUseCase`: broken access control / IDOR detection by
  replaying tester-supplied resource paths (e.g. `/api/orders/1001`) under
  two registered `AuthSession`s. HunterBot doesn't crawl, so it can't guess
  which paths are identity-scoped — the tester supplies `candidate_paths`
  explicitly. For each path it compares three read-only GETs: unauthenticated,
  the baseline session (the presumed resource owner), and a second,
  independent session. A finding fires only when the baseline session
  succeeds, the second session *also* succeeds, and the unauthenticated
  request doesn't — i.e. the endpoint checks that *someone* is logged in but
  not that they own the resource. Confidence is `confirmed` when the two
  successful bodies also look like the same record (near-identical length),
  `medium` otherwise; this is a heuristic lead for a human to verify, not
  proof. `hunterbot scan access-control` / the API's `POST
  /scans/access-control` run it; not a `ScannerPlugin` (it inherently needs
  two authenticated identities at once, not the single `http_client` that
  Protocol provides), so it isn't part of the default scanner set.
- `hunterbot/core/domain/auth_session.py` — authenticated scanning via
  `AuthSession`: HunterBot never performs a login itself (login flows vary
  too much — CSRF tokens, MFA, OAuth — to automate safely, and doing so
  would mean state-changing POST requests outside every scanner's
  read-only boundary); instead an authorized tester logs in out-of-band
  and registers the resulting header(s) (a session cookie, a bearer
  token, ...), tied to a Scope. `hunterbot scan run --session <id>` (or
  the API's `session_id`) then attaches them to every request a scan
  makes — cross-checked so a session can only be used against a target
  its own Scope actually authorizes, never a different one
- `hunterbot/reporting/` — a `ReportGenerator` interface with six
  implementations (Markdown, JSON, HTML, PDF, DOCX, XLSX), sorted
  most-severe-first and covering every `Finding` field
- `hunterbot/knowledge/correlation.py` — `KnowledgeCorrelationService`, which
  links each scan `Finding` to the best-matching `KnowledgeItem` (same
  `VulnerabilityCategory`, most shared significant words) so scan output and
  reports show *why* a finding matters, not just that it was found; linking
  is additive and optional — a scan runs identically well without it
- `hunterbot/reasoning/` — LLM-backed reasoning over what scanning already
  found, on top of the Claude API infrastructure shared with
  `LLMKnowledgeExtractor` (optional, `llm` extra, same Opus-5-default /
  graceful-unavailability pattern). Two capabilities:
  - `LLMFindingAnalyzer` — triages every stored Finding (critical / high /
    medium / low / likely-false-positive, with reasoning) and identifies
    attack chains where two or more Findings combine into a bigger risk
    than any of them read alone. Purely interpretive: read-only, changes
    nothing, and never invents a finding id it wasn't given.
  - `LLMScannerSelector` — an *opt-in* (`--adaptive`) adaptive scan mode:
    one plain recon GET, then Claude picks which of the already-registered
    `ScannerPlugin`s are worth running against this target. It can only
    narrow `RunScanUseCase`'s fixed, safety-reviewed scanner list down to a
    subset of itself — it never gets to invent a request of its own — and
    any failure (unavailable, API error, empty/hallucinated selection)
    falls back to running every scanner rather than under-testing the
    target silently.
- `hunterbot/cli/` — a Typer CLI covering scopes, sources, ingestion, search,
  auth sessions, scans (`--adaptive`, `--session`), findings analysis, and
  reports
- `hunterbot/api/` — a FastAPI REST layer (`hunterbot serve`, optional `api`
  extra) exposing the same use-cases as the CLI — scopes, sources +
  document ingestion, knowledge search, auth sessions, scans
  (`adaptive`/`session_id`), findings + analysis, and report generation —
  with interactive docs at `/docs`. Open by default (fine for local
  development); set `HUNTERBOT_API_KEY` to require `Authorization: Bearer
  <key>` on every request before exposing it any further

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

# ingest the bundled OWASP Risk Rating reference -- 16 real CORS/XSS/race-
# condition/file-upload variants scored from low to critical, ready to go
hunterbot source add "OWASP Risk Rating Scale" --type documentation \
  --url https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
hunterbot source ingest "OWASP Risk Rating Scale" ./knowledge_sources/owasp-risk-rating-scale.md

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

# adaptive mode: Claude picks which registered scanners are worth running
# based on a quick recon request, instead of always running all of them
# (requires: pip install ".[llm]" and ANTHROPIC_API_KEY set; falls back to
# running every scanner if selection is unavailable or fails)
hunterbot scan run https://example.com --adaptive

# authenticated scanning: log in out-of-band yourself (browser, curl, ...),
# then register the resulting session cookie/token against a Scope --
# HunterBot never performs the login itself (see Status above for why)
hunterbot session add 1 --name admin-user --header "Cookie: session=abc123"
hunterbot session list
hunterbot scan run https://example.com --session 1

# broken access control / IDOR: register a second session (a different
# account than admin-user above), then replay resource paths you know
# belong to admin-user's account under both -- flags any path the second
# session can also read
hunterbot session add 1 --name second-user --header "Cookie: session=def456"
hunterbot scan access-control https://example.com \
  --baseline-session 1 --test-session 2 --path /api/orders/1001

# triage stored findings and surface attack chains with Claude
# (requires the same 'llm' extra + API key; read-only, never re-scans)
hunterbot findings analyze
hunterbot findings analyze --asset https://example.com

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

## Running the API

The same use-cases the CLI drives are also exposed as a REST API — useful
for a future web UI or other integrations. Optional: requires the `api`
extra (`fastapi`, `uvicorn`, `python-multipart`).

```bash
pip install -e ".[api]"   # or ".[dev]", which includes it
hunterbot serve           # http://127.0.0.1:8000, interactive docs at /docs

# equivalent to the CLI quick start above, over HTTP
curl -X POST localhost:8000/scopes -H "Content-Type: application/json" \
  -d '{"target": "example.com", "program_name": "Acme Bug Bounty", "authorized_by": "Alice"}'
curl "localhost:8000/scopes/check?target=api.example.com"

curl -X POST localhost:8000/sources -H "Content-Type: application/json" \
  -d '{"name": "OWASP Top 10", "source_type": "documentation"}'
curl -X POST "localhost:8000/sources/OWASP%20Top%2010/ingest" -F "file=@./notes/owasp-top-10.md"

curl "localhost:8000/knowledge/search?keyword=injection"

curl -X POST localhost:8000/scans -H "Content-Type: application/json" \
  -d '{"base_url": "https://example.com"}'
# adaptive: true asks Claude to narrow down which scanners run (requires
# the 'llm' extra + ANTHROPIC_API_KEY; safely falls back to "run all" otherwise)
curl -X POST localhost:8000/scans -H "Content-Type: application/json" \
  -d '{"base_url": "https://example.com", "adaptive": true}'

# authenticated scanning: register out-of-band session material against a
# Scope (this is auth for the *scan target*, unrelated to the API's own
# HUNTERBOT_API_KEY below), then reference it by id in a scan
curl -X POST localhost:8000/sessions -H "Content-Type: application/json" \
  -d '{"scope_id": 1, "name": "admin-user", "headers": {"Cookie": "session=abc123"}}'
curl -X POST localhost:8000/scans -H "Content-Type: application/json" \
  -d '{"base_url": "https://example.com", "session_id": 1}'

# broken access control / IDOR: register a second session, then replay
# resource paths known to belong to the first session's account under both
curl -X POST localhost:8000/sessions -H "Content-Type: application/json" \
  -d '{"scope_id": 1, "name": "second-user", "headers": {"Cookie": "session=def456"}}'
curl -X POST localhost:8000/scans/access-control -H "Content-Type: application/json" \
  -d '{"base_url": "https://example.com", "baseline_session_id": 1, "test_session_id": 2, "candidate_paths": ["/api/orders/1001"]}'

curl "localhost:8000/findings"

curl -X POST localhost:8000/findings/analyze -H "Content-Type: application/json" -d '{}'

curl -X POST localhost:8000/reports -H "Content-Type: application/json" \
  -d '{"format": "markdown"}' -o report.md
```

`hunterbot serve` binds to `127.0.0.1` by default; pass `--host 0.0.0.0` to
accept connections from outside the container/host (the Docker image's
`HUNTERBOT_DATABASE_URL` still applies — point `serve` at the same database
the CLI uses to see the same scopes/sources/findings from both).

### Authentication

By default the API is **open** — anyone who can reach it can register scan
scopes and run scans. That's fine on localhost during development; before
exposing it any further, set `HUNTERBOT_API_KEY` and every request must then
carry it as `Authorization: Bearer <key>` (`/docs` and `/openapi.json` are
also disabled once a key is set, not just the data routes). `hunterbot serve`
prints a warning on startup if no key is configured. This is authentication
only — *can this caller use the API at all* — not authorization over which
targets it may scan; the existing Scope/`ScopeAuthorizationService` system
still separately governs that, unchanged.

```bash
export HUNTERBOT_API_KEY="$(openssl rand -hex 32)"
hunterbot serve --host 0.0.0.0

curl localhost:8000/scopes                                          # 401
curl localhost:8000/scopes -H "Authorization: Bearer $HUNTERBOT_API_KEY"  # 200
```

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

# or run the REST API instead of a one-off CLI command -- set
# HUNTERBOT_API_KEY since --host 0.0.0.0 means it's no longer localhost-only
docker run --rm -p 8000:8000 -v hunterbot-data:/data \
  -e HUNTERBOT_API_KEY="$(openssl rand -hex 32)" hunterbot serve --host 0.0.0.0
```

The image installs the `semantic`, `llm`, and `api` extras by default; pass
`ANTHROPIC_API_KEY` via `docker run -e ANTHROPIC_API_KEY=...` to use the
LLM-backed extractor from a container.

## Architecture

HunterBot follows Clean Architecture: `core/` holds domain models and
interfaces and depends on nothing else in the tree; every other package
(`storage/`, `authorization/`, `ingestion/`, `knowledge/`, `scanners/`,
`plugins/`, `reporting/`, `cli/`, `api/`) implements or consumes those
interfaces. This keeps the storage backend, scanner plugins, and report
formats swappable without touching core logic — e.g. `RunScanUseCase`
depends only on the `ScannerPlugin`/`HttpClient` Protocols and
`GenerateReportUseCase` depends only on the `ReportGenerator` Protocol; the
concrete `httpx`-based `ScannerHttpClient` and the Markdown/JSON/HTML
generators are injected by whichever composition root is running —
`hunterbot/cli/` or `hunterbot/api/` — instead. The same pattern applies to
`hunterbot/learning/`: `KnowledgeMergeService` depends on the
`KnowledgeRepository`/`KnowledgeRevisionRepository` Protocols, not on
SQLAlchemy directly. `hunterbot/api/` is a second, independent composition
root next to the CLI — same use-cases, same repositories, a different
entry point — not a wrapper around the CLI.

Every module described above from the original architecture is now
implemented end-to-end and covered by tests, including all six report
formats named in the original brief, optional semantic search, an
optional LLM-backed `KnowledgeExtractor`, knowledge-to-finding correlation,
and a REST API alongside the CLI. `hunterbot/reasoning/` follows the exact
same optional/graceful-degradation shape as `LLMKnowledgeExtractor`, but
where extraction turns unstructured text into `KnowledgeItem`s,
`LLMFindingAnalyzer`/`LLMScannerSelector` reason about the platform's own
Findings and ScannerPlugin registry — one interprets results after a scan
(triage, attack chains), the other narrows *which* already-vetted scanners
run before one (adaptive selection); neither can act outside HunterBot's
existing scanner list or authorization gate. What's left is further depth,
not structure: nine scanner plugins now cover headers, file/directory
exposure, cookies, CORS, open redirects, HTTP method tampering, and
admin-interface exposure, and every one of them can now run authenticated
via `AuthSession` (`--session`/`session_id`) against a target a tester has
already logged into out-of-band. A web UI on top of the existing REST API
is the largest remaining piece, and slots into an existing interface
without touching the rest of the system.

## Legal and ethical use

HunterBot is built exclusively for authorized defensive security testing —
bug bounty programs, pentest engagements, and CTFs where you have explicit
permission. Do not use it against systems you are not authorized to test.
