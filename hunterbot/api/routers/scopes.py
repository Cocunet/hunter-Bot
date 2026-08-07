from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import ScopeCheckResponse, ScopeCreateRequest
from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.core.domain import Scope
from hunterbot.core.use_cases.scope_management import ListScopesUseCase, RegisterScopeUseCase
from hunterbot.storage import SqlAlchemyScopeRepository

router = APIRouter(prefix="/scopes", tags=["scopes"])


@router.post("", response_model=Scope, status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScopeCreateRequest, session: Session = Depends(get_session)) -> Scope:
    """Register a new authorized scan target."""
    use_case = RegisterScopeUseCase(SqlAlchemyScopeRepository(session))
    return use_case.execute(
        target=payload.target,
        program_name=payload.program_name,
        authorized_by=payload.authorized_by,
        notes=payload.notes,
        expires_at=payload.expires_at,
    )


@router.get("", response_model=list[Scope])
def list_scopes(session: Session = Depends(get_session)) -> list[Scope]:
    """List all registered scopes."""
    return ListScopesUseCase(SqlAlchemyScopeRepository(session)).execute()


@router.get("/check", response_model=ScopeCheckResponse)
def check_scope(target: str, session: Session = Depends(get_session)) -> ScopeCheckResponse:
    """Check whether a target is currently authorized, without scanning it."""
    service = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
    try:
        scope = service.authorize(target)
    except NotAuthorizedError:
        return ScopeCheckResponse(authorized=False, scope=None)
    return ScopeCheckResponse(authorized=True, scope=scope)
