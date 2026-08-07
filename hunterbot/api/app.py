from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from hunterbot.api.routers import findings, knowledge, reports, scans, scopes, sources


def create_app() -> FastAPI:
    app = FastAPI(
        title="HunterBot API",
        description=(
            "REST API for HunterBot: a modular, AI-assisted platform for authorized "
            "bug bounty and defensive security assessments."
        ),
        version="0.1.0",
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
