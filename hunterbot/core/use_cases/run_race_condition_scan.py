import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from urllib.parse import urlparse

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory, target_matches
from hunterbot.core.interfaces import (
    ActiveHttpClient,
    AuthorizationChecker,
    AuthSessionRepository,
    FindingRepository,
    ScopeRepository,
)

logger = logging.getLogger(__name__)

SCANNER_NAME = "race-condition"

MIN_CONCURRENCY = 2
MAX_CONCURRENCY = 50
DEFAULT_CONCURRENCY = 20


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


class RunRaceConditionScanUseCase:
    """Confirms a race condition by firing real concurrent requests at a
    tester-specified state-changing endpoint and counting how many "win".

    HunterBot cannot discover which endpoint to race on its own -- that
    would mean guessing at state-changing actions on a live target, exactly
    the blind write every read-only scanner refuses to make. Here the
    tester supplies the endpoint and payload deliberately. This is one of
    only two use-cases in HunterBot that issues state-changing requests at
    all (the other is RunFileUploadRceScanUseCase) -- see
    hunterbot.core.interfaces.ActiveHttpClient for why that capability is
    kept structurally separate from every read-only ScannerPlugin.

    Running this has real side effects: it actually performs the racy POST
    ``concurrency`` times. If the race succeeds, the underlying action (a
    coupon redemption, a withdrawal, whatever the endpoint does) really
    happens more than once on the target. Only race an action whose
    repeated real execution is an accepted consequence of testing it,
    against a target and account the tester controls.

    Concurrency mechanics: every request is queued behind a
    threading.Barrier so all ``concurrency`` requests release together
    rather than trickling out one at a time -- the closest approximation to
    a true "single-packet" race a synchronous HTTP client can offer. A
    finding fires only when more requests than ``expected_max_successes``
    (default 1: "this should be usable exactly once") come back with a 2xx
    status. A correctly-guarded single-use action should reject every
    attempt after the first with a 4xx/409/etc; if two or more instead
    reported success, the endpoint isn't serializing the state change and
    the race actually won -- this is a live, confirmed result, not a
    heuristic guess, hence Confidence.CONFIRMED.
    """

    def __init__(
        self,
        *,
        authorization_checker: AuthorizationChecker,
        auth_session_repository: AuthSessionRepository,
        scope_repository: ScopeRepository,
        finding_repository: FindingRepository,
        active_http_client_factory: Callable[[str, dict[str, str] | None], ActiveHttpClient],
    ) -> None:
        self._authorization = authorization_checker
        self._auth_sessions = auth_session_repository
        self._scopes = scope_repository
        self._findings = finding_repository
        self._http_client_factory = active_http_client_factory

    def execute(
        self,
        *,
        base_url: str,
        path: str,
        body: str | None = None,
        content_type: str | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        expected_max_successes: int = 1,
        session_id: int | None = None,
    ) -> list[Finding]:
        if not (MIN_CONCURRENCY <= concurrency <= MAX_CONCURRENCY):
            raise ValueError(f"concurrency must be between {MIN_CONCURRENCY} and {MAX_CONCURRENCY}")
        if expected_max_successes < 1:
            raise ValueError("expected_max_successes must be at least 1")

        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")
        self._authorization.authorize(hostname)

        headers = None
        if session_id is not None:
            headers = self._resolve_session_headers(session_id, hostname)

        http_client = self._http_client_factory(base_url, headers)
        try:
            responses = self._fire_concurrently(
                http_client, path=path, body=body, content_type=content_type, concurrency=concurrency
            )
        finally:
            http_client.close()

        successes = [response for response in responses if response is not None and _is_success(response.status_code)]
        if len(successes) <= expected_max_successes:
            return []

        status_summary = ", ".join(
            str(response.status_code) if response is not None else "no-response" for response in responses
        )
        finding = Finding(
            title=f"Race condition confirmed on POST {path}",
            category=VulnerabilityCategory.AUTHORIZATION_ISSUE,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                f"{len(responses)} concurrent POST requests were sent to {path}; {len(successes)} "
                f"returned a successful (2xx) response, exceeding the expected maximum of "
                f"{expected_max_successes}. This endpoint does not correctly serialize the state "
                "change it performs under concurrent load -- a time-of-check-to-time-of-use race "
                "allowed the action to be applied more than once."
            ),
            affected_asset=base_url,
            location=f"{base_url}{path}",
            evidence=f"{len(successes)}/{len(responses)} requests succeeded (statuses: {status_summary})",
            reproduction_steps=(
                f"Send {concurrency} concurrent POST requests to {path} "
                f"{'using the same session' if session_id is not None else 'unauthenticated'} and count "
                "how many return a successful response; more than one confirms the race."
            ),
            remediation=(
                "Serialize the state change with a database-level constraint, row lock, or atomic "
                "compare-and-swap so concurrent requests cannot both observe the pre-change state."
            ),
            scanner_name=SCANNER_NAME,
        )
        return [self._findings.add(finding)]

    def _resolve_session_headers(self, session_id: int, hostname: str) -> dict[str, str]:
        auth_session = self._auth_sessions.get(session_id)
        if auth_session is None:
            raise ValueError(f"no session with id {session_id}")
        if not auth_session.is_currently_active():
            raise ValueError(f"session #{session_id} has expired")
        owning_scope = self._scopes.get(auth_session.scope_id)
        if owning_scope is None or not target_matches(owning_scope.target, hostname):
            raise ValueError(f"session #{session_id} belongs to a scope that does not authorize {hostname!r}")
        return auth_session.headers

    def _fire_concurrently(
        self,
        http_client: ActiveHttpClient,
        *,
        path: str,
        body: str | None,
        content_type: str | None,
        concurrency: int,
    ) -> list:
        barrier = threading.Barrier(concurrency)
        responses: list = [None] * concurrency

        def worker(index: int) -> None:
            barrier.wait()
            responses[index] = http_client.post(path, body=body, content_type=content_type)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            list(executor.map(worker, range(concurrency)))

        return responses
