import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import IngestResponse, SourceCreateRequest
from hunterbot.core.domain import Source
from hunterbot.core.use_cases.source_management import ListSourcesUseCase, RegisterSourceUseCase
from hunterbot.ingestion.connectors import connector_for_path
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.extraction import LLMExtractionError, LLMKnowledgeExtractor, RuleBasedExtractor
from hunterbot.storage import (
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyKnowledgeRevisionRepository,
    SqlAlchemySourceRepository,
)

router = APIRouter(prefix="/sources", tags=["sources"])


@router.post("", response_model=Source, status_code=status.HTTP_201_CREATED)
def create_source(payload: SourceCreateRequest, session: Session = Depends(get_session)) -> Source:
    """Register a new educational knowledge source."""
    use_case = RegisterSourceUseCase(SqlAlchemySourceRepository(session))
    try:
        return use_case.execute(
            name=payload.name,
            source_type=payload.source_type,
            url=payload.url,
            license_note=payload.license_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get("", response_model=list[Source])
def list_sources(enabled_only: bool = False, session: Session = Depends(get_session)) -> list[Source]:
    """List all registered knowledge sources."""
    return ListSourcesUseCase(SqlAlchemySourceRepository(session)).execute(enabled_only=enabled_only)


@router.post("/{name}/ingest", response_model=IngestResponse)
def ingest_source(
    name: str,
    file: UploadFile = File(..., description="A .md/.html/.pdf document to ingest."),
    extractor: str = Form("rule-based", description="'rule-based' (default, offline) or 'llm'."),
    session: Session = Depends(get_session),
) -> IngestResponse:
    """Ingest an uploaded document into the knowledge base for a registered source."""
    if extractor == "rule-based":
        extractor_instance = RuleBasedExtractor()
    elif extractor == "llm":
        try:
            extractor_instance = LLMKnowledgeExtractor()
        except LLMExtractionError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown extractor {extractor!r} (expected 'rule-based' or 'llm').",
        )

    source_repo = SqlAlchemySourceRepository(session)
    source = source_repo.get_by_name(name)
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No source named {name!r}. Register it first via POST /sources.",
        )

    # connector_for_path picks a connector by file extension, so the temp
    # copy needs the uploaded file's own suffix, not a generic one.
    suffix = Path(file.filename or "").suffix
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        tmp.write(file.file.read())
        tmp.flush()

        try:
            connector = connector_for_path(tmp.name)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        pipeline = IngestionPipeline(
            source_repository=source_repo,
            knowledge_repository=SqlAlchemyKnowledgeRepository(session),
            knowledge_revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
            extractor=extractor_instance,
        )
        try:
            result = pipeline.ingest(source=source, connector=connector)
        except LLMExtractionError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return IngestResponse(
        source_id=result.source.id,
        items_extracted=result.items_extracted,
        items_added=result.items_added,
        items_updated=result.items_updated,
        items_unchanged=result.items_unchanged,
    )
