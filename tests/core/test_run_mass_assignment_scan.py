import json

import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import ScopeAuthorizationService
from hunterbot.core.domain import AuthSession, Confidence, Scope, Severity
from hunterbot.core.interfaces import ScannerResponse
from hunterbot.core.use_cases.run_mass_assignment_scan import RunMassAssignmentScanUseCase
from hunterbot.storage.repositories import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyScopeRepository,
)

_BASE_URL = "https://example.com"
_TARGET_PATH = "/api/users"
_VERIFY_PATH = "/api/users/me"


class _StubActiveClient:
    def __init__(
        self,
        *,
        post_response: ScannerResponse | None,
        get_response: ScannerResponse | None = None,
    ) -> None:
        self.post_response = post_response
        self.get_response = get_response
        self.post_calls: list[dict] = []
        self.get_calls: list[str] = []
        self.closed = False

    def get(self, path: str) -> ScannerResponse | None:
        self.get_calls.append(path)
        return self.get_response

    def post(self, path: str, *, body=None, content_type=None) -> ScannerResponse | None:
        self.post_calls.append({"path": path, "body": body, "content_type": content_type})
        return self.post_response

    def post_multipart(self, path, *, files, data=None):
        return None

    def close(self) -> None:
        self.closed = True


def _build_use_case(session: Session, client) -> RunMassAssignmentScanUseCase:
    return RunMassAssignmentScanUseCase(
        authorization_checker=ScopeAuthorizationService(SqlAlchemyScopeRepository(session)),
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=lambda url, headers: client,
    )


def _authorize(session: Session) -> None:
    SqlAlchemyScopeRepository(session).add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))


class TestRunMassAssignmentScanUseCase:
    def test_raises_when_target_not_authorized(self, session: Session) -> None:
        client = _StubActiveClient(post_response=None)
        use_case = _build_use_case(session, client)

        with pytest.raises(Exception):
            use_case.execute(
                base_url=_BASE_URL, target_path=_TARGET_PATH, injected_field="role", injected_value="admin"
            )

    def test_rejects_unsupported_method(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(post_response=None)
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="unsupported method"):
            use_case.execute(
                base_url=_BASE_URL,
                target_path=_TARGET_PATH,
                injected_field="role",
                injected_value="admin",
                method="DELETE",
            )

    def test_no_finding_when_request_rejected(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(
            post_response=ScannerResponse(status_code=422, headers={}, text="rejected", url=_BASE_URL)
        )
        use_case = _build_use_case(session, client)

        findings = use_case.execute(
            base_url=_BASE_URL, target_path=_TARGET_PATH, injected_field="role", injected_value="admin"
        )

        assert findings == []
        assert client.closed

    def test_confirms_via_write_response_reflecting_field(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(
            post_response=ScannerResponse(
                status_code=201,
                headers={},
                text=json.dumps({"id": 42, "name": "bob", "role": "admin"}),
                url=_BASE_URL + _TARGET_PATH,
            )
        )
        use_case = _build_use_case(session, client)

        findings = use_case.execute(
            base_url=_BASE_URL,
            target_path=_TARGET_PATH,
            injected_field="role",
            injected_value="admin",
            base_fields={"name": "bob"},
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.CONFIRMED
        assert "'role' field" in finding.title
        assert client.get_calls == []  # confirmed from the write response alone, no verify GET needed

        sent_body = json.loads(client.post_calls[0]["body"])
        assert sent_body == {"name": "bob", "role": "admin"}

    def test_confirms_via_verify_path_when_write_response_silent(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(
            post_response=ScannerResponse(status_code=201, headers={}, text='{"id": 42}', url=_BASE_URL),
            get_response=ScannerResponse(
                status_code=200,
                headers={},
                text=json.dumps({"id": 42, "role": "admin"}),
                url=_BASE_URL + _VERIFY_PATH,
            ),
        )
        use_case = _build_use_case(session, client)

        findings = use_case.execute(
            base_url=_BASE_URL,
            target_path=_TARGET_PATH,
            injected_field="role",
            injected_value="admin",
            verify_path=_VERIFY_PATH,
        )

        assert len(findings) == 1
        assert "a follow-up GET to /api/users/me" in findings[0].evidence
        assert client.get_calls == [_VERIFY_PATH]

    def test_no_finding_when_field_never_confirmed(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(
            post_response=ScannerResponse(status_code=201, headers={}, text='{"id": 42}', url=_BASE_URL),
            get_response=ScannerResponse(status_code=200, headers={}, text='{"id": 42}', url=_BASE_URL),
        )
        use_case = _build_use_case(session, client)

        findings = use_case.execute(
            base_url=_BASE_URL,
            target_path=_TARGET_PATH,
            injected_field="role",
            injected_value="admin",
            verify_path=_VERIFY_PATH,
        )

        assert findings == []

    def test_unknown_session_id_raises(self, session: Session) -> None:
        _authorize(session)
        client = _StubActiveClient(post_response=None)
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="no session with id"):
            use_case.execute(
                base_url=_BASE_URL,
                target_path=_TARGET_PATH,
                injected_field="role",
                injected_value="admin",
                session_id=999,
            )

    def test_session_scoped_to_different_target_raises(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        other_scope = scope_repo.add(Scope(target="other.com", program_name="Other", authorized_by="Alice"))
        auth_session = SqlAlchemyAuthSessionRepository(session).add(
            AuthSession(scope_id=other_scope.id, name="alice", headers={"Cookie": "session=abc"})
        )
        client = _StubActiveClient(post_response=None)
        use_case = _build_use_case(session, client)

        with pytest.raises(ValueError, match="does not authorize"):
            use_case.execute(
                base_url=_BASE_URL,
                target_path=_TARGET_PATH,
                injected_field="role",
                injected_value="admin",
                session_id=auth_session.id,
            )
