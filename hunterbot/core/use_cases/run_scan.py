import logging
from typing import Callable
from urllib.parse import urlparse

from hunterbot.core.domain import Finding
from hunterbot.core.interfaces import (
    AuthorizationChecker,
    FindingRepository,
    HttpClient,
    KnowledgeCorrelator,
    ScannerPlugin,
    ScannerSelector,
)

logger = logging.getLogger(__name__)

_RECON_BODY_SNIPPET_LENGTH = 300


def _build_recon_signal(http_client: HttpClient) -> str:
    response = http_client.get("/")
    if response is None:
        return "GET / did not return a response (target unreachable or refused the connection)."
    body_snippet = response.text[:_RECON_BODY_SNIPPET_LENGTH]
    return f"status={response.status_code}\nheaders={response.headers}\nbody_snippet={body_snippet!r}"


class RunScanUseCase:
    """Runs registered scanner plugins against an authorized target.

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

    ``scanner_selector`` is optional and opt-in (unlike the correlator, it
    changes what gets tested, so a caller must ask for it explicitly — see
    hunterbot.cli's ``--adaptive`` flag). When supplied, one plain GET is
    made first to build a short recon signal, then the selector narrows
    ``scanners`` down to whichever subset it picks — see
    hunterbot.core.interfaces.ScannerSelector for why it can only narrow,
    never add to or otherwise change, that fixed set. Any failure during
    selection (the selector errors, or returns nothing usable) falls back
    to running every registered scanner rather than failing the scan or
    silently under-testing the target — the safe direction to fail in for a
    security tool is "tested more than planned," not "tested less."
    """

    def __init__(
        self,
        *,
        authorization_checker: AuthorizationChecker,
        finding_repository: FindingRepository,
        scanners: list[ScannerPlugin],
        http_client_factory: Callable[[str], HttpClient],
        knowledge_correlator: KnowledgeCorrelator | None = None,
        scanner_selector: ScannerSelector | None = None,
    ) -> None:
        self._authorization = authorization_checker
        self._findings = finding_repository
        self._scanners = scanners
        self._http_client_factory = http_client_factory
        self._knowledge_correlator = knowledge_correlator
        self._scanner_selector = scanner_selector

    def execute(self, *, base_url: str) -> list[Finding]:
        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")

        self._authorization.authorize(hostname)

        http_client = self._http_client_factory(base_url)
        try:
            scanners_to_run = self._select_scanners(base_url=base_url, http_client=http_client)

            persisted_findings: list[Finding] = []
            for scanner in scanners_to_run:
                for finding in scanner.scan(base_url=base_url, http_client=http_client):
                    if self._knowledge_correlator is not None:
                        finding = self._correlate(finding)
                    persisted_findings.append(self._findings.add(finding))
            return persisted_findings
        finally:
            http_client.close()

    def _correlate(self, finding: Finding) -> Finding:
        try:
            knowledge_source_id = self._knowledge_correlator.correlate(finding)
        except Exception as exc:
            # Same contract as _select_scanners below: correlation is
            # documented as additive and never required, so a failure here
            # (e.g. a knowledge-repository error) must degrade to "no link"
            # rather than aborting the scan and silently dropping every
            # finding not yet processed in the loop above.
            logger.warning("knowledge correlation failed for finding %r (%s); leaving it unlinked", finding.title, exc)
            logger.debug("knowledge correlation failure detail", exc_info=True)
            return finding
        return finding.model_copy(update={"knowledge_source_id": knowledge_source_id})

    def _select_scanners(self, *, base_url: str, http_client: HttpClient) -> list[ScannerPlugin]:
        if self._scanner_selector is None:
            return self._scanners

        try:
            recon_signal = _build_recon_signal(http_client)
            selected_names = self._scanner_selector.select(
                base_url=base_url, recon_signal=recon_signal, available_scanners=self._scanners
            )
            selected = [scanner for scanner in self._scanners if scanner.name in set(selected_names)]
        except Exception as exc:
            # Expected/handled, not a crash: log the summary at WARNING (so
            # it's visible without extra config) and the full traceback only
            # at DEBUG -- exc_info=True on the WARNING itself would print a
            # scary-looking stack trace to stderr for what a caller should
            # read as "adaptive scanning declined, scan continued normally".
            logger.warning("adaptive scanner selection failed (%s); running all registered scanners", exc)
            logger.debug("adaptive scanner selection failure detail", exc_info=True)
            return self._scanners

        return selected or self._scanners
