from datetime import datetime

import typer

from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.config import get_config
from hunterbot.core.domain import SourceType
from hunterbot.core.use_cases.run_scan import RunScanUseCase
from hunterbot.core.use_cases.scope_management import ListScopesUseCase, RegisterScopeUseCase
from hunterbot.core.use_cases.source_management import ListSourcesUseCase, RegisterSourceUseCase
from hunterbot.ingestion.connectors import connector_for_path
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.extraction import RuleBasedExtractor
from hunterbot.knowledge.search import KnowledgeSearchService
from hunterbot.plugins import default_scanners
from hunterbot.scanners import ScannerHttpClient
from hunterbot.storage import (
    SqlAlchemyFindingRepository,
    SqlAlchemyKnowledgeRepository,
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
scan_app = typer.Typer(help="Run authorized vulnerability scans.")
app.add_typer(scope_app, name="scope")
app.add_typer(source_app, name="source")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(scan_app, name="scan")


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
) -> None:
    """Ingest a local document into the knowledge base for a registered source."""
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
            extractor=RuleBasedExtractor(),
        )
        result = pipeline.ingest(source=source, connector=connector)

    typer.echo(
        f"Ingested {path}: {result.items_extracted} extracted, "
        f"{result.items_added} added, {result.items_deduplicated} already known"
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


@scan_app.command("run")
def scan_run(
    base_url: str = typer.Argument(..., help="Full base URL to scan, e.g. https://example.com"),
) -> None:
    """Run all registered scanner plugins against an authorized target.

    Refuses to scan unless ``base_url``'s hostname matches an active,
    non-expired Scope — register one first with `hunterbot scope add`.
    """
    session_factory = _session_factory()
    with session_factory() as session:
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=default_scanners(),
            http_client_factory=ScannerHttpClient,
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
        typer.echo(
            f"[{finding.id}] {finding.severity.value.upper()} — {finding.title} ({finding.scanner_name})"
        )


if __name__ == "__main__":
    app()
