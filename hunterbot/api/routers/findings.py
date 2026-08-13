from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import AnalyzeRequest
from hunterbot.core.domain import Finding, ScanAnalysis
from hunterbot.core.use_cases.analyze_findings import AnalyzeFindingsUseCase
from hunterbot.reasoning import LLMAnalysisError, LLMFindingAnalyzer
from hunterbot.storage import SqlAlchemyFindingRepository, SqlAlchemyKnowledgeRepository

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[Finding])
def list_findings(asset: str | None = None, session: Session = Depends(get_session)) -> list[Finding]:
    """List stored findings, optionally filtered to one affected_asset."""
    repo = SqlAlchemyFindingRepository(session)
    return repo.list_by_asset(asset) if asset is not None else repo.list_all()


@router.post("/analyze", response_model=ScanAnalysis)
def analyze_findings(payload: AnalyzeRequest, session: Session = Depends(get_session)) -> ScanAnalysis:
    """Use Claude to triage stored findings and surface attack chains (requires the 'llm' extra).

    Read-only: this reasons about findings that already exist and never
    triggers new scanning.
    """
    try:
        analyzer = LLMFindingAnalyzer()
    except LLMAnalysisError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    use_case = AnalyzeFindingsUseCase(
        finding_repository=SqlAlchemyFindingRepository(session),
        analyzer=analyzer,
        knowledge_repository=SqlAlchemyKnowledgeRepository(session),
    )
    try:
        return use_case.execute(affected_asset=payload.asset)
    except LLMAnalysisError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
