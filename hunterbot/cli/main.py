from datetime import datetime

import typer

from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.config import get_config
from hunterbot.core.domain import SourceType
from hunterbot.core.use_cases.scope_management import ListScopesUseCase, RegisterScopeUseCase
from hunterbot.core.use_cases.source_management import ListSourcesUseCase, RegisterSourceUseCase
from hunterbot.storage import (
    SqlAlchemyScopeRepository,
    SqlAlchemySourceRepository,
    get_session_factory,
    init_db,
)
from hunterbot.storage.database import create_engine_from_url

app = typer.Typer(help="HunterBot: authorized security assessment platform.")
scope_app = typer.Typer(help="Manage authorized scan scopes.")
source_app = typer.Typer(help="Manage registered knowledge sources.")
app.add_typer(scope_app, name="scope")
app.add_typer(source_app, name="source")


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


if __name__ == "__main__":
    app()
