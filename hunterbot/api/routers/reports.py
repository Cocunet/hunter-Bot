import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import ReportRequest
from hunterbot.core.use_cases.generate_report import GenerateReportUseCase
from hunterbot.reporting import get_generator
from hunterbot.storage import SqlAlchemyFindingRepository, SqlAlchemyKnowledgeRepository

router = APIRouter(prefix="/reports", tags=["reports"])

_MEDIA_TYPES = {
    "markdown": "text/markdown",
    "json": "application/json",
    "html": "text/html",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
_EXTENSIONS = {"markdown": "md", "json": "json", "html": "html", "pdf": "pdf", "docx": "docx", "xlsx": "xlsx"}


@router.post("")
def generate_report(payload: ReportRequest, session: Session = Depends(get_session)) -> FileResponse:
    """Generate a vulnerability report from stored findings and return it as a download."""
    try:
        generator = get_generator(payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    use_case = GenerateReportUseCase(
        finding_repository=SqlAlchemyFindingRepository(session),
        report_generator=generator,
        knowledge_repository=SqlAlchemyKnowledgeRepository(session),
    )

    # get_generator already validated payload.format against the same key
    # set as _EXTENSIONS/_MEDIA_TYPES, so both lookups below are safe.
    extension = _EXTENSIONS[payload.format]
    tmp_dir = Path(tempfile.mkdtemp(prefix="hunterbot-report-"))
    output_path = tmp_dir / f"report.{extension}"
    result_path = use_case.execute(output_path=output_path, affected_asset=payload.asset)

    return FileResponse(
        path=result_path,
        media_type=_MEDIA_TYPES[payload.format],
        filename=f"hunterbot-report.{extension}",
        background=BackgroundTask(shutil.rmtree, tmp_dir, ignore_errors=True),
    )
