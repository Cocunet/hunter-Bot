from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import typer

from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.config import get_config
from hunterbot.core.domain import SourceType, target_matches
from hunterbot.core.use_cases.analyze_findings import AnalyzeFindingsUseCase
from hunterbot.core.use_cases.generate_report import GenerateReportUseCase
from hunterbot.core.use_cases.run_scan import RunScanUseCase
from hunterbot.core.use_cases.scope_management import ListScopesUseCase, RegisterScopeUseCase
from hunterbot.core.use_cases.session_management import ListAuthSessionsUseCase, RegisterAuthSessionUseCase
from hunterbot.core.use_cases.source_management import ListSourcesUseCase, RegisterSourceUseCase
from hunterbot.ingestion.connectors import connector_for_path
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.knowledge.extraction import LLMExtractionError, LLMKnowledgeExtractor, RuleBasedExtractor
from hunterbot.knowledge.search import KnowledgeSearchService, SemanticKnowledgeSearchService, TfidfSemanticIndex
from hunterbot.plugins import default_scanners
from hunterbot.reasoning import LLMAnalysisError, LLMFindingAnalyzer, LLMScannerSelector, ScannerSelectionError
from hunterbot.reporting import get_generator
from hunterbot.scanners import ScannerHttpClient
from hunterbot.storage import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyKnowledgeRevisionRepository,
    SqlAlchemyScopeRepository,
    SqlAlchemySourceRepository,
    get_session_factory,
    init_db,
)
from hunterbot.storage.database import create_engine_from_url

app = typer.Typer(help="HunterBot: authorized security assessment platform.")
scope_app = typer.Typer(help="Manage authorized scan scopes.")
source_app = typer.Typer(help="Manage registered knowledge sources.")
knowledge_app = typer.Typer(help="Search the structured knowledge base.")
session_app = typer.Typer(help="Manage authentication sessions for authenticated scanning.")
scan_app = typer.Typer(help="Run authorized vulnerability scans.")
findings_app = typer.Typer(help="Inspect and analyze stored findings.")
report_app = typer.Typer(help="Generate vulnerability reports from stored findings.")
app.add_typer(scope_app, name="scope")
app.add_typer(source_app, name="source")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(session_app, name="session")
app.add_typer(scan_app, name="scan")
app.add_typer(findings_app, name="findings")
app.add_typer(report_app, name="report")


def _session_factory():
    config = get_config()
    engine = create_engine_from_url(config.database_url)
    init_db(engine)
    return get_session_factory(engine)


@app.command("init-db")
def init_db_command() -> None:
    """Create database tables if they don't already exist."""
    config = get_config()
    engine = create_engine_from_url(config.database_url)
    init_db(engine)
    typer.echo(f"Database ready at {config.database_url}")


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (development only)."),
) -> None:
    """Run the HunterBot REST API (requires the 'api' extra)."""
    if get_config().api_key is None:
        typer.secho(
            "No HUNTERBOT_API_KEY configured — this API is open to anyone who can reach it "
            "(it can register scan scopes and run scans). Set HUNTERBOT_API_KEY before exposing "
            "it beyond localhost.",
            fg=typer.colors.YELLOW,
        )
    try:
        import uvicorn
    except ImportError:
        typer.secho(
            "The API server needs the 'api' extra: pip install \"hunterbot[api]\"",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1) from None
    uvicorn.run("hunterbot.api.app:app", host=host, port=port, reload=reload)


@scope_app.command("add")
def scope_add(
    target: str = typer.Argument(..., help="Hostname, domain, or IP/CIDR to authorize."),
    program_name: str = typer.Option(..., "--program", help="Bug bounty program or engagement name."),
    authorized_by: str = typer.Option(..., "--authorized-by", help="Who granted this authorization."),
    notes: str = typer.Option(None, "--notes"),
    expires_at: datetime = typer.Option(None, "--expires-at", formats=["%Y-%m-%d"]),
) -> None:
    """Register a new authorized scan target."""
    session_factory = _session_factory()
    with session_factory() as session:
        use_case = RegisterScopeUseCase(SqlAlchemyScopeRepository(session))
        scope = use_case.execute(
            target=target,
            program_name=program_name,
            authorized_by=authorized_by,
            notes=notes,
            expires_at=expires_at,
        )
    typer.echo(f"Registered scope #{scope.id}: {scope.target} ({scope.program_name})")


@scope_app.command("list")
def scope_list() -> None:
    """List all registered scopes."""
    session_factory = _session_factory()
    with session_factory() as session:
        scopes = ListScopesUseCase(SqlAlchemyScopeRepository(session)).execute()
    for scope in scopes:
        active = "active" if scope.is_currently_active() else "inactive"
        typer.echo(f"[{scope.id}] {scope.target} — {scope.program_name} ({scope.status.value}, {active})")


@scope_app.command("check")
def scope_check(target: str) -> None:
    """Check whether a target is currently authorized."""
    session_factory = _session_factory()
    with session_factory() as session:
        service = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        try:
            scope = service.authorize(target)
        except NotAuthorizedError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        typer.secho(f"Authorized under scope #{scope.id} ({scope.program_name})", fg=typer.colors.GREEN)


@session_app.command("add")
def session_add(
    scope_id: int = typer.Argument(..., help="id of the Scope this session authenticates against."),
    name: str = typer.Option(..., "--name", help="Human label for this session, e.g. 'admin-user'."),
    header: list[str] = typer.Option(
        ...,
        "--header",
        help="An HTTP header to attach to every scan request, as 'Name: value'. Repeatable.",
    ),
    notes: str = typer.Option(None, "--notes"),
    expires_at: datetime = typer.Option(None, "--expires-at", formats=["%Y-%m-%d"]),
) -> None:
    """Register externally-obtained session material for authenticated scanning.

    HunterBot never logs in on your behalf -- login flows vary too much
    (CSRF tokens, MFA, OAuth) to automate safely, and doing so would mean
    issuing state-changing requests outside every scanner's read-only
    boundary. Authenticate out-of-band (your browser, curl, your own
    tooling) and paste the resulting header(s) here instead, e.g.:

        hunterbot session add 1 --name admin-user --header "Cookie: session=abc123"

    Use the registered session with `hunterbot scan run --session <id>`.
    """
    headers: dict[str, str] = {}
    for entry in header:
        if ":" not in entry:
            typer.secho(f"Invalid --header {entry!r} (expected 'Name: value').", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        key, _, value = entry.partition(":")
        headers[key.strip()] = value.strip()

    session_factory = _session_factory()
    with session_factory() as session:
        use_case = RegisterAuthSessionUseCase(
            auth_session_repository=SqlAlchemyAuthSessionRepository(session),
            scope_repository=SqlAlchemyScopeRepository(session),
        )
        try:
            auth_session = use_case.execute(
                scope_id=scope_id, name=name, headers=headers, notes=notes, expires_at=expires_at
            )
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
    typer.echo(f"Registered session #{auth_session.id}: {auth_session.name} (scope #{auth_session.scope_id})")


@session_app.command("list")
def session_list(
    scope: int = typer.Option(None, "--scope", help="Limit to sessions registered for one scope id."),
) -> None:
    """List registered authentication sessions. Header values are never shown here."""
    session_factory = _session_factory()
    with session_factory() as session:
        auth_sessions = ListAuthSessionsUseCase(SqlAlchemyAuthSessionRepository(session)).execute(scope_id=scope)

    if not auth_sessions:
        typer.echo("No sessions registered.")
        return
    for auth_session in auth_sessions:
        active = "active" if auth_session.is_currently_active() else "expired"
        header_names = ", ".join(sorted(auth_session.headers))
        typer.echo(
            f"[{auth_session.id}] {auth_session.name} (scope #{auth_session.scope_id}, {active}) "
            f"headers=[{header_names}]"
        )


@source_app.command("add")
def source_add(
    name: str = typer.Argument(...),
    source_type: SourceType = typer.Option(..., "--type"),
    url: str = typer.Option(None, "--url"),
) -> None:
    """Register a new educational knowledge source."""
    session_factory = _session_factory()
    with session_factory() as session:
        use_case = RegisterSourceUseCase(SqlAlchemySourceRepository(session))
        source = use_case.execute(name=name, source_type=source_type, url=url)
    typer.echo(f"Registered source #{source.id}: {source.name} ({source.source_type.value})")


@source_app.command("list")
def source_list() -> None:
    """List all registered knowledge sources."""
    session_factory = _session_factory()
    with session_factory() as session:
        sources = ListSourcesUseCase(SqlAlchemySourceRepository(session)).execute()
    for source in sources:
        typer.echo(f"[{source.id}] {source.name} ({source.source_type.value}) — {source.url or 'no url'}")


@source_app.command("ingest")
def source_ingest(
    name: str = typer.Argument(..., help="Name of a previously registered source."),
    path: str = typer.Argument(..., help="Local .md/.html/.pdf file to ingest for this source."),
    extractor: str = typer.Option(
        "rule-based",
        "--extractor",
        help="'rule-based' (default, offline) or 'llm' (Claude API; requires the 'llm' extra and an API key).",
    ),
) -> None:
    """Ingest a local document into the knowledge base for a registered source."""
    if extractor == "rule-based":
        extractor_instance = RuleBasedExtractor()
    elif extractor == "llm":
        try:
            extractor_instance = LLMKnowledgeExtractor()
        except LLMExtractionError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
    else:
        typer.secho(f"Unknown extractor {extractor!r} (expected 'rule-based' or 'llm').", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    session_factory = _session_factory()
    with session_factory() as session:
        source_repo = SqlAlchemySourceRepository(session)
        source = source_repo.get_by_name(name)
        if source is None:
            typer.secho(
                f"No source named {name!r}. Register it first with `hunterbot source add`.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        connector = connector_for_path(path)
        pipeline = IngestionPipeline(
            source_repository=source_repo,
            knowledge_repository=SqlAlchemyKnowledgeRepository(session),
            knowledge_revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
            extractor=extractor_instance,
        )
        try:
            result = pipeline.ingest(source=source, connector=connector)
        except LLMExtractionError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc

    typer.echo(
        f"Ingested {path}: {result.items_extracted} extracted, "
        f"{result.items_added} added, {result.items_updated} updated, "
        f"{result.items_unchanged} unchanged"
    )


@knowledge_app.command("search")
def knowledge_search(
    keyword: str = typer.Option(None, "--keyword", help="Match against title/summary text."),
    category: str = typer.Option(None, "--category", help="VulnerabilityCategory value, e.g. input_validation."),
    cwe: str = typer.Option(None, "--cwe", help="Exact CWE id, e.g. CWE-79."),
    owasp: str = typer.Option(None, "--owasp", help="OWASP category name or code."),
    severity: str = typer.Option(None, "--severity", help="Severity value, e.g. high."),
    tag: str = typer.Option(None, "--tag"),
) -> None:
    """Search the structured knowledge base."""
    session_factory = _session_factory()
    with session_factory() as session:
        service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))
        results = service.search(
            keyword=keyword,
            category=category,
            cwe=cwe,
            owasp_category=owasp,
            severity=severity,
            tag=tag,
        )

    if not results:
        typer.echo("No matching knowledge items.")
        return
    for item in results:
        severity_label = item.severity_hint.value if item.severity_hint else "-"
        typer.echo(
            f"[{item.id}] ({item.category.value}) {item.title} "
            f"cwe={item.cwe or '-'} owasp={item.owasp_category or '-'} severity={severity_label}"
        )


@knowledge_app.command("semantic-search")
def knowledge_semantic_search(
    query: str = typer.Argument(..., help="Free-text query to rank the knowledge base against."),
    top_k: int = typer.Option(10, "--top-k", help="Maximum number of results."),
) -> None:
    """Rank the knowledge base by similarity to a free-text query.

    Optional: requires the 'semantic' extra (scikit-learn). Falls back to
    plain keyword search over the same query text if that isn't installed.
    """
    session_factory = _session_factory()
    with session_factory() as session:
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        semantic_service = SemanticKnowledgeSearchService(
            knowledge_repository=knowledge_repo, semantic_index=TfidfSemanticIndex()
        )

        if not semantic_service.is_available():
            typer.secho(
                "Semantic search backend not installed (pip install \"hunterbot[semantic]\"); "
                "falling back to keyword search.",
                fg=typer.colors.YELLOW,
            )
            results = KnowledgeSearchService(knowledge_repo).search(keyword=query)
            if not results:
                typer.echo("No matching knowledge items.")
                return
            for item in results[:top_k]:
                typer.echo(f"[{item.id}] ({item.category.value}) {item.title}")
            return

        matches = semantic_service.search(query=query, top_k=top_k)

    if not matches:
        typer.echo("No matching knowledge items.")
        return
    for match in matches:
        typer.echo(f"[{match.item.id}] (score={match.score:.3f}) {match.item.title}")


@knowledge_app.command("history")
def knowledge_history(item_id: int) -> None:
    """Show the revision history of a knowledge item (oldest first)."""
    session_factory = _session_factory()
    with session_factory() as session:
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        current = knowledge_repo.get(item_id)
        if current is None:
            typer.secho(f"No knowledge item with id {item_id}.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        revisions = SqlAlchemyKnowledgeRevisionRepository(session).list_by_knowledge_item(item_id)

    if not revisions:
        typer.echo(f"[{item_id}] {current.title} is at version {current.version}; no prior revisions.")
        return

    for revision in revisions:
        typer.echo(
            f"v{revision.version} (superseded {revision.superseded_at.isoformat()}): {revision.title}"
        )
    typer.echo(f"v{current.version} (current): {current.title}")


@scan_app.command("run")
def scan_run(
    base_url: str = typer.Argument(..., help="Full base URL to scan, e.g. https://example.com"),
    adaptive: bool = typer.Option(
        False,
        "--adaptive",
        help=(
            "Use Claude to pick which registered scanners are worth running, based on a "
            "quick recon request, instead of always running all of them (requires the 'llm' extra)."
        ),
    ),
    session_id: int = typer.Option(
        None,
        "--session",
        help="id of a registered auth session (see `hunterbot session add`) to authenticate scan requests with.",
    ),
) -> None:
    """Run registered scanner plugins against an authorized target.

    Refuses to scan unless ``base_url``'s hostname matches an active,
    non-expired Scope — register one first with `hunterbot scope add`.
    """
    scanner_selector = None
    if adaptive:
        try:
            scanner_selector = LLMScannerSelector()
        except ScannerSelectionError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc

    session_factory = _session_factory()
    with session_factory() as session:
        http_client_factory = ScannerHttpClient
        if session_id is not None:
            auth_session = SqlAlchemyAuthSessionRepository(session).get(session_id)
            if auth_session is None:
                typer.secho(f"No session with id {session_id}.", fg=typer.colors.RED)
                raise typer.Exit(code=1)
            if not auth_session.is_currently_active():
                typer.secho(f"Session #{session_id} has expired.", fg=typer.colors.RED)
                raise typer.Exit(code=1)
            owning_scope = SqlAlchemyScopeRepository(session).get(auth_session.scope_id)
            hostname = urlparse(base_url).hostname or ""
            if owning_scope is None or not target_matches(owning_scope.target, hostname):
                typer.secho(
                    f"Session #{session_id} belongs to a scope that does not authorize "
                    f"{hostname!r}; refusing to use it here.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)
            extra_headers = auth_session.headers

            def http_client_factory(url: str) -> ScannerHttpClient:
                return ScannerHttpClient(url, extra_headers=extra_headers)

        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=default_scanners(),
            http_client_factory=http_client_factory,
            knowledge_correlator=KnowledgeCorrelationService(SqlAlchemyKnowledgeRepository(session)),
            scanner_selector=scanner_selector,
        )
        try:
            findings = use_case.execute(base_url=base_url)
        except NotAuthorizedError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc

    if not findings:
        typer.echo("No findings.")
        return
    for finding in findings:
        knowledge_note = (
            f", knowledge #{finding.knowledge_source_id}" if finding.knowledge_source_id is not None else ""
        )
        typer.echo(
            f"[{finding.id}] {finding.severity.value.upper()} — {finding.title} "
            f"({finding.scanner_name}{knowledge_note})"
        )


@findings_app.command("analyze")
def findings_analyze(
    asset: str = typer.Option(None, "--asset", help="Limit analysis to one affected_asset value."),
) -> None:
    """Use Claude to triage stored findings and surface attack chains (requires the 'llm' extra).

    Read-only: this reasons about findings that already exist and never
    triggers new scanning.
    """
    try:
        analyzer = LLMFindingAnalyzer()
    except LLMAnalysisError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    session_factory = _session_factory()
    with session_factory() as session:
        use_case = AnalyzeFindingsUseCase(
            finding_repository=SqlAlchemyFindingRepository(session),
            analyzer=analyzer,
            knowledge_repository=SqlAlchemyKnowledgeRepository(session),
        )
        try:
            analysis = use_case.execute(affected_asset=asset)
        except LLMAnalysisError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc

    typer.echo(analysis.summary)

    if analysis.triage:
        typer.echo("\nTriage:")
        for item in analysis.triage:
            typer.echo(f"  [{item.finding_id}] {item.priority.value.upper()} — {item.reasoning}")

    if analysis.attack_chains:
        typer.echo("\nAttack chains:")
        for chain in analysis.attack_chains:
            finding_ids = ", ".join(str(fid) for fid in chain.finding_ids)
            typer.echo(f"  [{chain.severity.value.upper()}] {chain.title} (findings {finding_ids})")
            typer.echo(f"    {chain.narrative}")


@report_app.command("generate")
def report_generate(
    output: Path = typer.Argument(..., help="File path to write the report to."),
    format: str = typer.Option("markdown", "--format", help="markdown, json, html, pdf, docx, or xlsx."),
    asset: str = typer.Option(None, "--asset", help="Limit the report to one affected_asset value."),
) -> None:
    """Generate a vulnerability report from stored findings."""
    session_factory = _session_factory()
    with session_factory() as session:
        try:
            generator = get_generator(format)
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc

        use_case = GenerateReportUseCase(
            finding_repository=SqlAlchemyFindingRepository(session),
            report_generator=generator,
            knowledge_repository=SqlAlchemyKnowledgeRepository(session),
        )
        result_path = use_case.execute(output_path=output, affected_asset=asset)

    typer.echo(f"Report written to {result_path}")


if __name__ == "__main__":
    app()
