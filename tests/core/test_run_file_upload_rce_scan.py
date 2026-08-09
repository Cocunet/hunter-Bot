import json

import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import ScopeAuthorizationService
from hunterbot.core.domain import AuthSession, Confidence, Scope, Severity
from hunterbot.core.interfaces import ScannerResponse
from hunterbot.core.use_cases.run_file_upload_rce_scan import RunFileUploadRceScanUseCase
from hunterbot.storage.repositories import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyScopeRepository,
)

_BASE_URL = "https://example.com"
_UPLOAD_PATH = "/api/upload"


class _StubActiveClient:
    """Simulates an upload endpoint whose behavior depends on the *actual*
    (randomly generated, per-scan) filename and payload the use-case sends,
    since neither is known ahead of time by a fixed fixture.

    ``get_mode`` controls what a later GET to the discovered file returns:
    "executed" (the token comes back alone -- RCE), "unexecuted" (the raw
    payload source comes back -- upload accepted, not executed), "not_found"
    (a 404, token never reappears), or None (GET is never expected to be
    called, e.g. when the response gives us nothing to follow up on).
    """

    def __init__(
        self, *, upload_status: int = 201, include_url_in_response: bool = True, get_mode: str | None = None
    ) -> None:
        self.upload_status = upload_status
        self.include_url_in_response = include_url_in_response
        self.get_mode = get_mode
        self.last_multipart_call: dict | None = None
        self.get_calls: list[str] = []
        self.closed = False

    def post_multipart(self, path: str, *, files, data=None) -> ScannerResponse | None:
        self.last_multipart_call = {"path": path, "files": files, "data": data}
        _field, (filename, _content, _content_type) = next(iter(files.items()))
        text = json.dumps({"url": f"/uploads/{filename}"}) if self.include_url_in_response else "upload successful"
        return ScannerResponse(status_code=self.upload_status, headers={}, text=text, url=_BASE_URL + path)

    def get(self, path: str) -> ScannerResponse | None:
        self.get_calls.append(path)
        if self.get_mode is None:
            return None
        _field, (_filename, content, _content_type) = next(iter(self.last_multipart_call["files"].items()))
        payload_text = content.decode()
        if self.get_mode == "executed":
            token = payload_text.split('"')[1]
            return ScannerResponse(status_code=200, headers={}, text=token, url=_BASE_URL + path)
        if self.get_mode == "unexecuted":
            return ScannerResponse(status_code=200, headers={}, text=payload_text, url=_BASE_URL + path)
        if self.get_mode == "not_found":
            return ScannerResponse(status_code=404, headers={}, text="not found", url=_BASE_URL + path)
        raise AssertionError(f"unexpected get_mode {self.get_mode!r}")

    def post(self, path, *, body=None, content_type=None) -> ScannerResponse | None:
        return None

    def close(self) -> None:
        self.closed = True


def _build_use_case(session: Session, client) -> RunFileUploadRceScanUseCase:
    return RunFileUploadRceScanUseCase(
        authorization_checker=ScopeAuthorizationService(SqlAlchemyScopeRepository(session)),
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: client,
    )


def _authorize(session: Session) -> None:
    SqlAlchemyScopeRepository(session).add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))


class TestRunFileUploadRceScanUseCase:
    def test_raises_when_target_not_authorized(self, session: Session) -> None:
        client = _StubActiveClient(upload_status=415)
        use_case = _build_use_case(session, client)

        with pytest.raises(Exception):
            use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH)

    def test_rejects_unknown_payload_type(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(upload_status=415)
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="unknown payload_type"):
            use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH, payload_type="perl")

    def test_no_finding_when_upload_rejected(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(upload_status=415)
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH)

        assert findings == []
        assert client.closed

    def test_confirms_rce_when_token_executes(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(get_mode="executed")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.CONFIRMED
        assert "Remote code execution confirmed" in finding.title
        assert client.closed

    def test_confirms_unrestricted_upload_when_source_served_unexecuted(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(get_mode="unexecuted")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.CONFIRMED
        assert "Unrestricted file upload" in finding.title

    def test_medium_finding_when_upload_accepted_but_location_undiscoverable(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(include_url_in_response=False, get_mode=None)
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.confidence == Confidence.MEDIUM
        assert "undetermined" in finding.title
        assert client.get_calls == []

    def test_no_finding_when_token_never_reappears(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(get_mode="not_found")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH)

        assert findings == []

    def test_uses_fetch_path_template_when_response_has_no_location(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(include_url_in_response=False, get_mode="executed")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(
            base_url=_BASE_URL,
            upload_path=_UPLOAD_PATH,
            fetch_path_template="/uploads/{filename}",
        )

        assert len(findings) == 1
        assert any(call.startswith("/uploads/hunterbot-") for call in client.get_calls)

    def test_extra_fields_and_field_name_are_forwarded(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(upload_status=415)
        use_case = _build_use_case(session, client)

        use_case.execute(
            base_url=_BASE_URL,
            upload_path=_UPLOAD_PATH,
            field_name="upload",
            extra_fields={"csrf": "abc123"},
        )

        assert "upload" in client.last_multipart_call["files"]
        assert client.last_multipart_call["data"] == {"csrf": "abc123"}

    def test_unknown_session_id_raises(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(upload_status=415)
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="no session with id"):
            use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH, session_id=999)

    def test_session_scoped_to_different_target_raises(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        other_scope = scope_repo.add(Scope(target="other.com", program_name="Other", authorized_by="Alice"))
        auth_session = SqlAlchemyAuthSessionRepository(session).add(
            AuthSession(scope_id=other_scope.id, name="alice", headers={"Cookie": "session=abc"})
        )
        client = _StubActiveClient(upload_status=415)
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="does not authorize"):
            use_case.execute(base_url=_BASE_URL, upload_path=_UPLOAD_PATH, session_id=auth_session.id)
