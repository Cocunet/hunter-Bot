from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import ScanRequest
from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.core.domain import Finding, target_matches
from hunterbot.core.use_cases.run_scan import RunScanUseCase
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.plugins import default_scanners
from hunterbot.reasoning import LLMScannerSelector, ScannerSelectionError
from hunterbot.scanners import ScannerHttpClient
from hunterbot.storage import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyScopeRepository,
)

router = APIRouter(prefix="/scans", tags=["scans"])


def _http_client_factory_for(payload: ScanRequest, session: Session):
    if payload.session_id is None:
        return ScannerHttpClient

    auth_session = SqlAlchemyAuthSessionRepository(session).get(payload.session_id)
    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No session with id {payload.session_id}."
        )
    if not auth_session.is_currently_active():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Session #{payload.session_id} has expired."
        )
    owning_scope = SqlAlchemyScopeRepository(session).get(auth_session.scope_id)
    hostname = urlparse(payload.base_url).hostname or ""
    if owning_scope is None or not target_matches(owning_scope.target, hostname):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Session #{payload.session_id} belongs to a scope that does not authorize {hostname!r}.",
        )

    extra_headers = auth_session.headers

    def factory(url: str) -> ScannerHttpClient:
        return ScannerHttpClient(url, extra_headers=extra_headers)

    return factory


@router.post("", response_model=list[Finding])
def run_scan(payload: ScanRequest, session: Session = Depends(get_session)) -> list[Finding]:
    """Run registered scanner plugins against an authorized target.

    Refuses to scan (403) unless ``base_url``'s hostname matches an active,
    non-expired Scope — register one first via POST /scopes. Pass
    ``adaptive: true`` to let Claude narrow down which scanners run based
    on a quick recon request (requires the 'llm' extra); omitted or false
    runs every registered scanner, as before. Pass ``session_id`` to
    authenticate scan requests using a previously registered AuthSession
    (see POST /sessions) -- its owning Scope must authorize the same
    target being scanned here.
    """
    scanner_selector = None
    if payload.adaptive:
        try:
            scanner_selector = LLMScannerSelector()
        except ScannerSelectionError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    http_client_factory = _http_client_factory_for(payload, session)

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
        return use_case.execute(base_url=payload.base_url)
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
