from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import ScanRequest
from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.core.domain import Finding
from hunterbot.core.use_cases.run_scan import RunScanUseCase
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.plugins import default_scanners
from hunterbot.reasoning import LLMScannerSelector, ScannerSelectionError
from hunterbot.scanners import ScannerHttpClient
from hunterbot.storage import SqlAlchemyFindingRepository, SqlAlchemyKnowledgeRepository, SqlAlchemyScopeRepository

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=list[Finding])
def run_scan(payload: ScanRequest, session: Session = Depends(get_session)) -> list[Finding]:
    """Run registered scanner plugins against an authorized target.

    Refuses to scan (403) unless ``base_url``'s hostname matches an active,
    non-expired Scope — register one first via POST /scopes. Pass
    ``adaptive: true`` to let Claude narrow down which scanners run based
    on a quick recon request (requires the 'llm' extra); omitted or false
    runs every registered scanner, as before.
    """
    scanner_selector = None
    if payload.adaptive:
        try:
            scanner_selector = LLMScannerSelector()
        except ScannerSelectionError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    use_case = RunScanUseCase(
        authorization_checker=authorization,
        finding_repository=SqlAlchemyFindingRepository(session),
        scanners=default_scanners(),
        http_client_factory=ScannerHttpClient,
        knowledge_correlator=KnowledgeCorrelationService(SqlAlchemyKnowledgeRepository(session)),
        scanner_selector=scanner_selector,
    )
    try:
        return use_case.execute(base_url=payload.base_url)
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
