from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import (
    AccessControlScanRequest,
    FileUploadRceScanRequest,
    MassAssignmentScanRequest,
    RaceConditionScanRequest,
    ScanRequest,
    XxeScanRequest,
)
from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.core.domain import Finding, target_matches
from hunterbot.core.use_cases.run_access_control_scan import RunAccessControlScanUseCase
from hunterbot.core.use_cases.run_file_upload_rce_scan import RunFileUploadRceScanUseCase
from hunterbot.core.use_cases.run_mass_assignment_scan import RunMassAssignmentScanUseCase
from hunterbot.core.use_cases.run_race_condition_scan import RunRaceConditionScanUseCase
from hunterbot.core.use_cases.run_scan import RunScanUseCase
from hunterbot.core.use_cases.run_xxe_scan import RunXxeScanUseCase
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.plugins import default_scanners
from hunterbot.reasoning import LLMScannerSelector, ScannerSelectionError
from hunterbot.scanners import ActiveScannerHttpClient, ScannerHttpClient
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


@router.post("/access-control", response_model=list[Finding])
def run_access_control_scan(
    payload: AccessControlScanRequest, session: Session = Depends(get_session)
) -> list[Finding]:
    """Flag broken access control / IDOR by replaying candidate_paths under two sessions.

    For each path in ``candidate_paths``, compares an unauthenticated
    request, one made with ``baseline_session_id``, and one made with
    ``test_session_id``. Flags any path where the second session also gets
    a successful response, even though it should be scoped to whichever
    account ``baseline_session_id`` belongs to. Both sessions' owning
    scopes must authorize ``base_url``'s hostname (403 otherwise).
    """
    authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    use_case = RunAccessControlScanUseCase(
        authorization_checker=authorization,
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        http_client_factory=lambda url, headers: ScannerHttpClient(url, extra_headers=headers),
    )
    try:
        return use_case.execute(
            base_url=payload.base_url,
            baseline_session_id=payload.baseline_session_id,
            test_session_id=payload.test_session_id,
            candidate_paths=payload.candidate_paths,
        )
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/race-condition", response_model=list[Finding])
def run_race_condition_scan(
    payload: RaceConditionScanRequest, session: Session = Depends(get_session)
) -> list[Finding]:
    """ACTIVE SCAN -- fires real concurrent POST requests at ``path``.

    Unlike every other scan endpoint, this one issues state-changing
    requests: it performs the target action ``concurrency`` times, for
    real, to see whether more than ``expected_max_successes`` of them
    succeed. Only point this at an endpoint whose repeated real execution
    is an accepted consequence of testing it, in scope authorized for that.
    """
    authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    use_case = RunRaceConditionScanUseCase(
        authorization_checker=authorization,
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: ActiveScannerHttpClient(url, extra_headers=headers),
    )
    try:
        return use_case.execute(
            base_url=payload.base_url,
            path=payload.path,
            body=payload.body,
            content_type=payload.content_type,
            concurrency=payload.concurrency,
            expected_max_successes=payload.expected_max_successes,
            session_id=payload.session_id,
        )
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/file-upload-rce", response_model=list[Finding])
def run_file_upload_rce_scan(
    payload: FileUploadRceScanRequest, session: Session = Depends(get_session)
) -> list[Finding]:
    """ACTIVE SCAN -- uploads a real (harmless) canary file to confirm upload-to-RCE.

    Unlike every other scan endpoint, this one writes to the target: it
    uploads a file whose only content is a harmless unique token, then
    requests it back to check whether the token was executed and echoed
    rather than served as inert source. A confirmed finding means a real
    file was left on the target -- its evidence records exactly where.
    """
    authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    use_case = RunFileUploadRceScanUseCase(
        authorization_checker=authorization,
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: ActiveScannerHttpClient(url, extra_headers=headers),
    )
    try:
        return use_case.execute(
            base_url=payload.base_url,
            upload_path=payload.upload_path,
            field_name=payload.field_name,
            payload_type=payload.payload_type,
            extra_fields=payload.extra_fields,
            fetch_path_template=payload.fetch_path_template,
            session_id=payload.session_id,
        )
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/xxe", response_model=list[Finding])
def run_xxe_scan(payload: XxeScanRequest, session: Session = Depends(get_session)) -> list[Finding]:
    """ACTIVE SCAN -- posts a real XML body with an external entity to confirm XXE.

    Unlike every read-only scan endpoint, this one writes to the target: it
    POSTs a DOCTYPE declaring an external entity pointing at /etc/passwd
    and compares the response against a DOCTYPE-free baseline body posted
    to the same endpoint.
    """
    authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    use_case = RunXxeScanUseCase(
        authorization_checker=authorization,
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: ActiveScannerHttpClient(url, extra_headers=headers),
    )
    try:
        return use_case.execute(
            base_url=payload.base_url,
            target_path=payload.target_path,
            session_id=payload.session_id,
        )
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/mass-assignment", response_model=list[Finding])
def run_mass_assignment_scan(
    payload: MassAssignmentScanRequest, session: Session = Depends(get_session)
) -> list[Finding]:
    """ACTIVE SCAN -- submits a real write with an extra, undocumented field to confirm mass assignment.

    Unlike every read-only scan endpoint, this one writes to the target: it
    sends ``injected_field``/``injected_value`` alongside ``base_fields``
    and checks whether the server actually applied the extra field, either
    in the write response itself or a follow-up GET to ``verify_path``.
    """
    authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    use_case = RunMassAssignmentScanUseCase(
        authorization_checker=authorization,
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: ActiveScannerHttpClient(url, extra_headers=headers),
    )
    try:
        return use_case.execute(
            base_url=payload.base_url,
            target_path=payload.target_path,
            injected_field=payload.injected_field,
            injected_value=payload.injected_value,
            base_fields=payload.base_fields,
            method=payload.method,
            verify_path=payload.verify_path,
            session_id=payload.session_id,
        )
    except NotAuthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
