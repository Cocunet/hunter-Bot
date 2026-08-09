from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import AuthSessionCreateRequest, AuthSessionResponse
from hunterbot.core.use_cases.session_management import ListAuthSessionsUseCase, RegisterAuthSessionUseCase
from hunterbot.storage import SqlAlchemyAuthSessionRepository, SqlAlchemyScopeRepository

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.post("", response_model=AuthSessionResponse, status_code=status.HTTP_201_CREATED)
def create_session(payload: AuthSessionCreateRequest, session: Session = Depends(get_session)) -> AuthSessionResponse:
    """Register externally-obtained session material for authenticated scanning.

    HunterBot never logs in on your behalf -- authenticate out-of-band and
    pass the resulting header(s) (a session cookie, a bearer token, ...)
    here. Use the returned id with POST /scans's ``session_id``.
    """
    use_case = RegisterAuthSessionUseCase(
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
    )
    try:
        auth_session = use_case.execute(
            scope_id=payload.scope_id,
            name=payload.name,
            headers=payload.headers,
            notes=payload.notes,
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return AuthSessionResponse.from_domain(auth_session)


@router.get("", response_model=list[AuthSessionResponse])
def list_sessions(scope_id: int | None = None, session: Session = Depends(get_session)) -> list[AuthSessionResponse]:
    """List registered authentication sessions. Header values are never returned."""
    auth_sessions = ListAuthSessionsUseCase(SqlAlchemyAuthSessionRepository(session)).execute(scope_id=scope_id)
    return [AuthSessionResponse.from_domain(auth_session) for auth_session in auth_sessions]
