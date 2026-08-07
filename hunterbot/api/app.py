from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from hunterbot.api.dependencies import require_api_key
from hunterbot.api.routers import findings, knowledge, reports, scans, scopes, sources
from hunterbot.config import get_config


def create_app() -> FastAPI:
    # FastAPI's docs/openapi/redoc routes are registered directly on the
    # Starlette app rather than through include_router, so the
    # `dependencies=` list below (which does cover every real route) never
    # reaches them. When an API key is configured, disabling these instead
    # is simpler and more honest than trying to bolt auth onto routes
    # FastAPI owns internally -- "locked" should mean the whole surface,
    # not everything except the one place that describes it.
    docs_enabled = get_config().api_key is None

    app = FastAPI(
        title="HunterBot API",
        description=(
            "REST API for HunterBot: a modular, AI-assisted platform for authorized "
            "bug bounty and defensive security assessments."
        ),
        version="0.1.0",
        dependencies=[Depends(require_api_key)],
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    @app.exception_handler(ValidationError)
    async def _handle_domain_validation_error(request: Request, exc: ValidationError) -> JSONResponse:
        # Raised by domain models' own validators (e.g. Scope's expires_at
        # must be after authorized_at) — request-shape errors are already
        # handled by FastAPI's own RequestValidationError -> 422 path.
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    app.include_router(scopes.router)
    app.include_router(sources.router)
    app.include_router(knowledge.router)
    app.include_router(scans.router)
    app.include_router(reports.router)
    app.include_router(findings.router)

    return app


app = create_app()
