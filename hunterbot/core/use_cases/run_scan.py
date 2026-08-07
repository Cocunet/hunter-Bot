from typing import Callable
from urllib.parse import urlparse

from hunterbot.core.domain import Finding
from hunterbot.core.interfaces import (
    AuthorizationChecker,
    FindingRepository,
    HttpClient,
    KnowledgeCorrelator,
    ScannerPlugin,
)


class RunScanUseCase:
    """Runs every registered scanner plugin against an authorized target.

    Authorization is checked exactly once, before any scanner touches the
    network, using the hostname parsed out of ``base_url``. There is no
    per-plugin bypass: if ``authorization_checker.authorize`` raises
    NotAuthorizedError, it propagates straight to the caller and no scanner
    runs.

    ``http_client_factory`` is required rather than defaulted so this
    use-case has no dependency on any concrete HTTP implementation — the
    caller (composition root, e.g. hunterbot.cli) supplies
    ``hunterbot.scanners.ScannerHttpClient`` or a test double.

    ``knowledge_correlator`` is optional: when supplied, each Finding is
    linked to the best-matching KnowledgeItem (see
    hunterbot.knowledge.correlation.KnowledgeCorrelationService) before
    being persisted. A scan runs identically well without one — correlation
    is additive, never required, and never blocks or fails a scan.
    """

    def __init__(
        self,
        *,
        authorization_checker: AuthorizationChecker,
        finding_repository: FindingRepository,
        scanners: list[ScannerPlugin],
        http_client_factory: Callable[[str], HttpClient],
        knowledge_correlator: KnowledgeCorrelator | None = None,
    ) -> None:
        self._authorization = authorization_checker
        self._findings = finding_repository
        self._scanners = scanners
        self._http_client_factory = http_client_factory
        self._knowledge_correlator = knowledge_correlator

    def execute(self, *, base_url: str) -> list[Finding]:
        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")

        self._authorization.authorize(hostname)

        http_client = self._http_client_factory(base_url)
        try:
            persisted_findings: list[Finding] = []
            for scanner in self._scanners:
                for finding in scanner.scan(base_url=base_url, http_client=http_client):
                    if self._knowledge_correlator is not None:
                        knowledge_source_id = self._knowledge_correlator.correlate(finding)
                        finding = finding.model_copy(update={"knowledge_source_id": knowledge_source_id})
                    persisted_findings.append(self._findings.add(finding))
            return persisted_findings
        finally:
            http_client.close()
