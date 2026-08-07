from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.core.domain import Finding
from hunterbot.storage import SqlAlchemyFindingRepository

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[Finding])
def list_findings(asset: str | None = None, session: Session = Depends(get_session)) -> list[Finding]:
    """List stored findings, optionally filtered to one affected_asset."""
    repo = SqlAlchemyFindingRepository(session)
    return repo.list_by_asset(asset) if asset is not None else repo.list_all()
