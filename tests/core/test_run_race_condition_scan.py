import threading

import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import ScopeAuthorizationService
from hunterbot.core.domain import AuthSession, Confidence, Scope
from hunterbot.core.interfaces import ScannerResponse
from hunterbot.core.use_cases.run_race_condition_scan import (
    MAX_CONCURRENCY,
    MIN_CONCURRENCY,
    RunRaceConditionScanUseCase,
)
from hunterbot.storage.repositories import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyScopeRepository,
)

_BASE_URL = "https://example.com"
_PATH = "/api/coupons/redeem"


class _GuardedFakeClient:
    """Simulates a properly-locked single-use endpoint: only the first
    ``max_successes`` requests to arrive succeed; the rest get a 409."""

    def __init__(self, max_successes: int = 1) -> None:
        self._lock = threading.Lock()
        self._successes = 0
        self._max_successes = max_successes
        self.post_count = 0
        self.closed = False

    def get(self, path: str) -> ScannerResponse | None:
        return None

    def post(self, path: str, *, body: str | None = None, content_type: str | None = None) -> ScannerResponse | None:
        with self._lock:
            self.post_count += 1
            if self._successes < self._max_successes:
                self._successes += 1
                return ScannerResponse(status_code=200, headers={}, text="ok", url=_BASE_URL + path)
            return ScannerResponse(status_code=409, headers={}, text="already redeemed", url=_BASE_URL + path)

    def post_multipart(self, path, *, files, data=None):
        return None

    def close(self) -> None:
        self.closed = True


class _UnguardedFakeClient:
    """Simulates a racy endpoint with no concurrency guard: every request succeeds."""

    def __init__(self) -> None:
        self.post_count = 0
        self.closed = False

    def get(self, path: str) -> ScannerResponse | None:
        return None

    def post(self, path: str, *, body: str | None = None, content_type: str | None = None) -> ScannerResponse | None:
        self.post_count += 1
        return ScannerResponse(status_code=200, headers={}, text="ok", url=_BASE_URL + path)

    def post_multipart(self, path, *, files, data=None):
        return None

    def close(self) -> None:
        self.closed = True


def _build_use_case(session: Session, http_client_factory) -> RunRaceConditionScanUseCase:
    return RunRaceConditionScanUseCase(
        authorization_checker=ScopeAuthorizationService(SqlAlchemyScopeRepository(session)),
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        active_http_client_factory=http_client_factory,
    )


def _authorize(session: Session) -> None:
    SqlAlchemyScopeRepository(session).add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))


class TestRunRaceConditionScanUseCase:
    def test_raises_when_target_not_authorized(self, session: Session) -> None:
        use_case = _build_use_case(session, lambda url, headers: _UnguardedFakeClient())

        with pytest.raises(Exception):
            use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=5)

    def test_rejects_concurrency_below_minimum(self, session: Session) -> None:
        _authorize(session)
        use_case = _build_use_case(session, lambda url, headers: _UnguardedFakeClient())

        with pytest.raises(ValueError, match="concurrency must be between"):
            use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=MIN_CONCURRENCY - 1)

    def test_rejects_concurrency_above_maximum(self, session: Session) -> None:
        _authorize(session)
        use_case = _build_use_case(session, lambda url, headers: _UnguardedFakeClient())

        with pytest.raises(ValueError, match="concurrency must be between"):
            use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=MAX_CONCURRENCY + 1)

    def test_rejects_expected_max_successes_below_one(self, session: Session) -> None:
        _authorize(session)
        use_case = _build_use_case(session, lambda url, headers: _UnguardedFakeClient())

        with pytest.raises(ValueError, match="expected_max_successes"):
            use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=5, expected_max_successes=0)

    def test_no_finding_when_endpoint_is_properly_guarded(self, session: Session) -> None:
        _authorize(session)
        client = _GuardedFakeClient(max_successes=1)
        use_case = _build_use_case(session, lambda url, headers: client)

        findings = use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=20)

        assert findings == []
        assert client.post_count == 20
        assert client.closed

    def test_flags_race_when_endpoint_allows_multiple_successes(self, session: Session) -> None:
        _authorize(session)
        client = _UnguardedFakeClient()
        use_case = _build_use_case(session, lambda url, headers: client)

        findings = use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=20)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id is not None
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.severity.value == "high"
        assert finding.scanner_name == "race-condition"
        assert _PATH in finding.title
        assert "20/20" in finding.evidence

    def test_respects_expected_max_successes_override(self, session: Session) -> None:
        _authorize(session)
        client = _GuardedFakeClient(max_successes=3)
        use_case = _build_use_case(session, lambda url, headers: client)

        no_findings = use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=10, expected_max_successes=3)
        assert no_findings == []

        client2 = _GuardedFakeClient(max_successes=3)
        use_case2 = _build_use_case(session, lambda url, headers: client2)
        findings = use_case2.execute(base_url=_BASE_URL, path=_PATH, concurrency=10, expected_max_successes=1)
        assert len(findings) == 1

    def test_unknown_session_id_raises(self, session: Session) -> None:
        _authorize(session)
        use_case = _build_use_case(session, lambda url, headers: _UnguardedFakeClient())

        with pytest.raises(ValueError, match="no session with id"):
            use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=5, session_id=999)

    def test_session_scoped_to_different_target_raises(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        other_scope = scope_repo.add(Scope(target="other.com", program_name="Other", authorized_by="Alice"))
        session_repo = SqlAlchemyAuthSessionRepository(session)
        auth_session = session_repo.add(
            AuthSession(scope_id=other_scope.id, name="alice", headers={"Cookie": "session=abc"})
        )
        use_case = _build_use_case(session, lambda url, headers: _UnguardedFakeClient())

        with pytest.raises(ValueError, match="does not authorize"):
            use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=5, session_id=auth_session.id)

    def test_session_headers_are_passed_to_factory(self, session: Session) -> None:
        _authorize(session)
        session_repo = SqlAlchemyAuthSessionRepository(session)
        scope = SqlAlchemyScopeRepository(session).list()[0]
        auth_session = session_repo.add(
            AuthSession(scope_id=scope.id, name="alice", headers={"Cookie": "session=abc"})
        )
        received_headers = {}

        def factory(url, headers):
            received_headers.update(headers or {})
            return _UnguardedFakeClient()

        use_case = _build_use_case(session, factory)
        use_case.execute(base_url=_BASE_URL, path=_PATH, concurrency=5, session_id=auth_session.id)

        assert received_headers == {"Cookie": "session=abc"}
