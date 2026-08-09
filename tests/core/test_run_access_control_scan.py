import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import ScopeAuthorizationService
from hunterbot.core.domain import AuthSession, Confidence, Scope
from hunterbot.core.interfaces import ScannerResponse
from hunterbot.core.use_cases.run_access_control_scan import RunAccessControlScanUseCase
from hunterbot.storage.repositories import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyScopeRepository,
)

_BASE_URL = "https://example.com"
_BASELINE_HEADERS = {"Cookie": "session=alice"}
_TEST_HEADERS = {"Cookie": "session=bob"}


class _KeyedHttpClient:
    def __init__(self, responses: dict[str, ScannerResponse]) -> None:
        self._responses = responses
        self.requested_paths: list[str] = []
        self.closed = False

    def get(self, path: str) -> ScannerResponse | None:
        self.requested_paths.append(path)
        return self._responses.get(path)

    def get_no_redirect(self, path: str) -> ScannerResponse | None:
        return self.get(path)

    def options(self, path: str) -> ScannerResponse | None:
        return self.get(path)

    def close(self) -> None:
        self.closed = True


def _response(status_code: int = 200, text: str = "body") -> ScannerResponse:
    return ScannerResponse(status_code=status_code, headers={}, text=text, url=f"{_BASE_URL}/x")


def _make_factory(
    *,
    anon: dict[str, ScannerResponse] | None = None,
    baseline: dict[str, ScannerResponse] | None = None,
    test: dict[str, ScannerResponse] | None = None,
):
    clients: dict[str, _KeyedHttpClient] = {}

    def factory(base_url: str, headers: dict[str, str] | None):
        assert base_url == _BASE_URL
        if headers is None:
            client = _KeyedHttpClient(anon or {})
            clients["anon"] = client
        elif headers == _BASELINE_HEADERS:
            client = _KeyedHttpClient(baseline or {})
            clients["baseline"] = client
        elif headers == _TEST_HEADERS:
            client = _KeyedHttpClient(test or {})
            clients["test"] = client
        else:
            raise AssertionError(f"unexpected headers: {headers}")
        return client

    factory.clients = clients
    return factory


def _register_scope_and_sessions(session: Session) -> tuple[Scope, AuthSession, AuthSession]:
    scope_repo = SqlAlchemyScopeRepository(session)
    scope = scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
    session_repo = SqlAlchemyAuthSessionRepository(session)
    baseline_session = session_repo.add(
        AuthSession(scope_id=scope.id, name="alice", headers=_BASELINE_HEADERS)
    )
    test_session = session_repo.add(AuthSession(scope_id=scope.id, name="bob", headers=_TEST_HEADERS))
    return scope, baseline_session, test_session


def _build_use_case(session: Session, http_client_factory) -> RunAccessControlScanUseCase:
    return RunAccessControlScanUseCase(
        authorization_checker=ScopeAuthorizationService(SqlAlchemyScopeRepository(session)),
        auth_session_repository=SqlAlchemyAuthSessionRepository(session),
        scope_repository=SqlAlchemyScopeRepository(session),
        finding_repository=SqlAlchemyFindingRepository(session),
        http_client_factory=http_client_factory,
    )


class TestRunAccessControlScanUseCase:
    def test_raises_when_target_not_authorized(self, session: Session) -> None:
        # No Scope registered for not-authorized.com at all -- the general
        # authorization gate must reject it before any session is resolved.
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        use_case = _build_use_case(session, _make_factory())

        with pytest.raises(Exception):
            use_case.execute(
                base_url="https://not-authorized.com",
                baseline_session_id=baseline_session.id,
                test_session_id=test_session.id,
                candidate_paths=["/api/orders/1"],
            )

    def test_rejects_same_session_for_both_roles(self, session: Session) -> None:
        _, baseline_session, _ = _register_scope_and_sessions(session)
        use_case = _build_use_case(session, _make_factory())

        with pytest.raises(ValueError, match="two different sessions"):
            use_case.execute(
                base_url=_BASE_URL,
                baseline_session_id=baseline_session.id,
                test_session_id=baseline_session.id,
                candidate_paths=["/api/orders/1"],
            )

    def test_rejects_empty_candidate_paths(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        use_case = _build_use_case(session, _make_factory())

        with pytest.raises(ValueError, match="at least one candidate path"):
            use_case.execute(
                base_url=_BASE_URL,
                baseline_session_id=baseline_session.id,
                test_session_id=test_session.id,
                candidate_paths=[],
            )

    def test_rejects_unknown_session_id(self, session: Session) -> None:
        _, baseline_session, _ = _register_scope_and_sessions(session)
        use_case = _build_use_case(session, _make_factory())

        with pytest.raises(ValueError, match="no session with id"):
            use_case.execute(
                base_url=_BASE_URL,
                baseline_session_id=baseline_session.id,
                test_session_id=999,
                candidate_paths=["/api/orders/1"],
            )

    def test_rejects_session_whose_scope_does_not_authorize_target(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        session_repo = SqlAlchemyAuthSessionRepository(session)
        scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        other_scope = scope_repo.add(Scope(target="other.com", program_name="Other", authorized_by="Alice"))
        baseline_session = session_repo.add(
            AuthSession(scope_id=other_scope.id, name="alice", headers=_BASELINE_HEADERS)
        )
        test_session = session_repo.add(
            AuthSession(scope_id=other_scope.id, name="bob", headers=_TEST_HEADERS)
        )
        use_case = _build_use_case(session, _make_factory())

        with pytest.raises(ValueError, match="does not authorize"):
            use_case.execute(
                base_url=_BASE_URL,
                baseline_session_id=baseline_session.id,
                test_session_id=test_session.id,
                candidate_paths=["/api/orders/1"],
            )

    def test_skips_path_when_baseline_session_cannot_access_it(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            baseline={"/api/orders/1": _response(status_code=404)},
            test={"/api/orders/1": _response(status_code=200)},
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert findings == []

    def test_skips_path_when_second_session_is_denied(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            baseline={"/api/orders/1": _response(status_code=200)},
            test={"/api/orders/1": _response(status_code=403)},
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert findings == []

    def test_skips_path_reachable_without_any_session(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            anon={"/api/orders/1": _response(status_code=200)},
            baseline={"/api/orders/1": _response(status_code=200)},
            test={"/api/orders/1": _response(status_code=200)},
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert findings == []

    def test_flags_confirmed_when_both_sessions_get_matching_bodies(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            anon={"/api/orders/1": _response(status_code=403, text="denied")},
            baseline={"/api/orders/1": _response(status_code=200, text="order #1 data")},
            test={"/api/orders/1": _response(status_code=200, text="order #1 data")},
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id is not None
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.scanner_name == "access-control-idor"
        assert "/api/orders/1" in finding.title

    def test_flags_medium_confidence_when_bodies_differ(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            anon={"/api/orders/1": _response(status_code=401, text="")},
            baseline={"/api/orders/1": _response(status_code=200, text="a" * 500)},
            test={"/api/orders/1": _response(status_code=200, text="b" * 10)},
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert len(findings) == 1
        assert findings[0].confidence == Confidence.MEDIUM

    def test_treats_no_anon_response_as_denied(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            anon={},
            baseline={"/api/orders/1": _response(status_code=200, text="data")},
            test={"/api/orders/1": _response(status_code=200, text="data")},
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert len(findings) == 1

    def test_checks_every_candidate_path(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            anon={},
            baseline={
                "/api/orders/1": _response(status_code=200, text="one"),
                "/api/orders/2": _response(status_code=404),
            },
            test={
                "/api/orders/1": _response(status_code=200, text="one"),
                "/api/orders/2": _response(status_code=403),
            },
        )
        use_case = _build_use_case(session, factory)

        findings = use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1", "/api/orders/2"],
        )

        assert len(findings) == 1
        assert "/api/orders/1" in findings[0].title

    def test_closes_all_three_clients(self, session: Session) -> None:
        _, baseline_session, test_session = _register_scope_and_sessions(session)
        factory = _make_factory(
            anon={},
            baseline={"/api/orders/1": _response(status_code=200)},
            test={"/api/orders/1": _response(status_code=200)},
        )
        use_case = _build_use_case(session, factory)

        use_case.execute(
            base_url=_BASE_URL,
            baseline_session_id=baseline_session.id,
            test_session_id=test_session.id,
            candidate_paths=["/api/orders/1"],
        )

        assert all(client.closed for client in factory.clients.values())
