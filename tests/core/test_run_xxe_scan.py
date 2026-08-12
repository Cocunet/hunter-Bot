import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import ScopeAuthorizationService
from hunterbot.core.domain import AuthSession, Confidence, Scope, Severity
from hunterbot.core.interfaces import ScannerResponse
from hunterbot.core.use_cases.run_xxe_scan import RunXxeScanUseCase
from hunterbot.storage.repositories import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyScopeRepository,
)

_BASE_URL = "https://example.com"
_TARGET_PATH = "/api/import"


class _StubActiveClient:
    def __init__(self, *, baseline_text: str = "ok", payload_text: str, status_code: int = 200) -> None:
        self.baseline_text = baseline_text
        self.payload_text = payload_text
        self.status_code = status_code
        self.post_calls: list[dict] = []
        self.closed = False

    def get(self, path: str) -> ScannerResponse | None:
        return None

    def post(self, path: str, *, body=None, content_type=None) -> ScannerResponse | None:
        self.post_calls.append({"path": path, "body": body, "content_type": content_type})
        text = self.baseline_text if len(self.post_calls) == 1 else self.payload_text
        return ScannerResponse(status_code=self.status_code, headers={}, text=text, url=_BASE_URL + path)

    def post_multipart(self, path, *, files, data=None):
        return None

    def close(self) -> None:
        self.closed = True


def _build_use_case(session: Session, client) -> RunXxeScanUseCase:
    return RunXxeScanUseCase(
        authorization_checker=ScopeAuthorizationService(SqlAlchemyScopeRepository(session)),
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: client,
    )


def _authorize(session: Session) -> None:
    SqlAlchemyScopeRepository(session).add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))


class TestRunXxeScanUseCase:
    def test_raises_when_target_not_authorized(self, session: Session) -> None:
        client = _StubActiveClient(payload_text="ok")
        use_case = _build_use_case(session, client)

        with pytest.raises(Exception):
            use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH)

    def test_confirms_file_read(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(
            payload_text="uid=0 root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"
        )
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.CONFIRMED
        assert "file read" in finding.title
        assert client.closed
        assert len(client.post_calls) == 2

    def test_confirms_parser_error_when_file_not_read(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(payload_text="Error: failed to load external entity \"file:///etc/passwd\"")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.confidence == Confidence.MEDIUM
        assert "accepts external entity" in finding.title

    def test_no_finding_when_neither_signature_present(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(payload_text="<r>hunterbot-baseline</r>")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH)

        assert findings == []

    def test_signature_present_in_baseline_too_is_not_flagged(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(
            baseline_text="root:x:0:0: this app always says this",
            payload_text="root:x:0:0: this app always says this",
        )
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH)

        assert findings == []

    def test_no_response_yields_no_findings(self, session: Session) -> None:
        _authorize(session)

        class _UnreachableClient(_StubActiveClient):
            def post(self, path, *, body=None, content_type=None):
                self.post_calls.append({"path": path})
                return None

        client = _UnreachableClient(payload_text="")
        use_case = _build_use_case(session, client)

        findings = use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH)

        assert findings == []

    def test_unknown_session_id_raises(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(payload_text="ok")
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="no session with id"):
            use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH, session_id=999)

    def test_session_scoped_to_different_target_raises(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        other_scope = scope_repo.add(Scope(target="other.com", program_name="Other", authorized_by="Alice"))
        auth_session = SqlAlchemyAuthSessionRepository(session).add(
            AuthSession(scope_id=other_scope.id, name="alice", headers={"Cookie": "session=abc"})
        )
        client = _StubActiveClient(payload_text="ok")
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="does not authorize"):
            use_case.execute(base_url=_BASE_URL, target_path=_TARGET_PATH, session_id=auth_session.id)
