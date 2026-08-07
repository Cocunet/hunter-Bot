import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import ScopeAuthorizationService
from hunterbot.core.domain import Confidence, Finding, Scope, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient
from hunterbot.core.use_cases.run_scan import RunScanUseCase
from hunterbot.storage.repositories import SqlAlchemyFindingRepository, SqlAlchemyScopeRepository
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class _StubScanner:
    name = "stub-scanner"

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings
        self.received_base_url: str | None = None

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        self.received_base_url = base_url
        return self._findings


def _finding(title: str = "Test finding") -> Finding:
    return Finding(
        title=title,
        category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="A test finding.",
        affected_asset=_BASE_URL,
        location=_BASE_URL + "/",
        scanner_name="stub-scanner",
    )


class TestRunScanUseCase:
    def test_raises_when_target_not_authorized(self, session: Session) -> None:
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[_StubScanner([])],
            http_client_factory=lambda base_url: FakeHttpClient(),
        )

        with pytest.raises(Exception):
            use_case.execute(base_url=_BASE_URL)

    def test_runs_scanners_and_persists_findings_for_authorized_target(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        scanner = _StubScanner([_finding()])
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[scanner],
            http_client_factory=lambda base_url: FakeHttpClient(),
        )

        findings = use_case.execute(base_url=_BASE_URL)

        assert len(findings) == 1
        assert findings[0].id is not None
        assert scanner.received_base_url == _BASE_URL

    def test_closes_http_client_even_if_scanner_raises(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))

        class _RaisingScanner:
            name = "raising-scanner"

            def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
                raise RuntimeError("boom")

        created_clients: list[FakeHttpClient] = []

        def factory(base_url: str) -> FakeHttpClient:
            client = FakeHttpClient()
            created_clients.append(client)
            return client

        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[_RaisingScanner()],
            http_client_factory=factory,
        )

        with pytest.raises(RuntimeError):
            use_case.execute(base_url=_BASE_URL)

        assert created_clients[0].closed is True

    def test_correlator_sets_knowledge_source_id_when_supplied(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        scanner = _StubScanner([_finding()])

        class _StubCorrelator:
            def __init__(self) -> None:
                self.received: Finding | None = None

            def correlate(self, finding: Finding) -> int | None:
                self.received = finding
                return 42

        correlator = _StubCorrelator()
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[scanner],
            http_client_factory=lambda base_url: FakeHttpClient(),
            knowledge_correlator=correlator,
        )

        findings = use_case.execute(base_url=_BASE_URL)

        assert findings[0].knowledge_source_id == 42
        assert correlator.received is not None

    def test_no_correlator_leaves_knowledge_source_id_none(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[_StubScanner([_finding()])],
            http_client_factory=lambda base_url: FakeHttpClient(),
        )

        findings = use_case.execute(base_url=_BASE_URL)

        assert findings[0].knowledge_source_id is None

    def test_adaptive_selector_narrows_which_scanners_run(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        wanted_scanner = _StubScanner([_finding(title="Wanted")])
        wanted_scanner.name = "wanted-scanner"
        skipped_scanner = _StubScanner([_finding(title="Skipped")])
        skipped_scanner.name = "skipped-scanner"

        class _StubSelector:
            def __init__(self) -> None:
                self.received_available_names: list[str] | None = None

            def select(self, *, base_url, recon_signal, available_scanners):
                self.received_available_names = [s.name for s in available_scanners]
                return ["wanted-scanner"]

        selector = _StubSelector()
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[wanted_scanner, skipped_scanner],
            http_client_factory=lambda base_url: FakeHttpClient(),
            scanner_selector=selector,
        )

        findings = use_case.execute(base_url=_BASE_URL)

        assert [f.title for f in findings] == ["Wanted"]
        assert set(selector.received_available_names) == {"wanted-scanner", "skipped-scanner"}

    def test_adaptive_selector_failure_falls_back_to_running_everything(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        scanner = _StubScanner([_finding()])

        class _RaisingSelector:
            def select(self, *, base_url, recon_signal, available_scanners):
                raise RuntimeError("selection boom")

        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[scanner],
            http_client_factory=lambda base_url: FakeHttpClient(),
            scanner_selector=_RaisingSelector(),
        )

        findings = use_case.execute(base_url=_BASE_URL)

        assert len(findings) == 1

    def test_adaptive_selector_result_with_no_valid_names_falls_back_to_running_everything(
        self, session: Session
    ) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        scanner = _StubScanner([_finding()])

        class _UselessSelector:
            def select(self, *, base_url, recon_signal, available_scanners):
                return ["nonexistent-scanner"]

        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[scanner],
            http_client_factory=lambda base_url: FakeHttpClient(),
            scanner_selector=_UselessSelector(),
        )

        findings = use_case.execute(base_url=_BASE_URL)

        assert len(findings) == 1

    def test_subdomain_target_is_authorized_by_parent_domain_scope(self, session: Session) -> None:
        SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        authorization = ScopeAuthorizationService(SqlAlchemyScopeRepository(session))
        use_case = RunScanUseCase(
            authorization_checker=authorization,
            finding_repository=SqlAlchemyFindingRepository(session),
            scanners=[_StubScanner([])],
            http_client_factory=lambda base_url: FakeHttpClient(),
        )

        findings = use_case.execute(base_url="https://api.example.com")

        assert findings == []
