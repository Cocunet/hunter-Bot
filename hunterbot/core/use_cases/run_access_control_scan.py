import logging
from typing import Callable
from urllib.parse import urlparse

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory, target_matches
from hunterbot.core.interfaces import (
    AuthorizationChecker,
    AuthSessionRepository,
    FindingRepository,
    HttpClient,
    ScopeRepository,
)

logger = logging.getLogger(__name__)

SCANNER_NAME = "access-control-idor"

# Response bodies within this fraction of each other's length are treated as
# "plausibly the same underlying record" -- a coarse but dependency-free
# stand-in for a real diff, good enough to separate "both sessions got back
# the same private resource" from "both sessions got a 200 for unrelated
# reasons" without pulling in a text-similarity library for one comparison.
_SIMILAR_LENGTH_TOLERANCE = 0.05


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


def _bodies_look_like_the_same_resource(baseline_body: str, test_body: str) -> bool:
    if not baseline_body or not test_body:
        return baseline_body == test_body
    longer = max(len(baseline_body), len(test_body))
    difference = abs(len(baseline_body) - len(test_body))
    return difference / longer <= _SIMILAR_LENGTH_TOLERANCE


class RunAccessControlScanUseCase:
    """Flags broken access control / IDOR by replaying candidate paths under two identities.

    HunterBot doesn't crawl and can't infer which paths are identity-scoped,
    so the tester supplies ``candidate_paths`` explicitly -- endpoints they
    already know reference a specific resource (e.g. ``/api/orders/1001``)
    that should belong only to whichever account ``baseline_session_id``
    authenticates as.

    For each candidate path, three read-only GETs are compared: one with no
    credentials, one with the baseline session's, and one with a second,
    independent session's (``test_session_id``). A finding is raised only
    when the baseline session succeeds (otherwise there's nothing valid to
    compare against), the second session *also* succeeds, and the
    unauthenticated request does not -- i.e. the endpoint clearly requires
    *some* identity, but not specifically the one that owns the resource.
    This mirrors how tools like Autorize perform differential authorization
    testing, adapted to HunterBot's registered-AuthSession model instead of
    live traffic interception.

    This is a heuristic, not proof: two accounts can legitimately share
    access to the same resource. Confidence is CONFIRMED only when the two
    successful response bodies also look like the same underlying record
    (see ``_bodies_look_like_the_same_resource``); otherwise it's MEDIUM and
    the finding description says to verify by hand.
    """

    def __init__(
        self,
        *,
        authorization_checker: AuthorizationChecker,
        auth_session_repository: AuthSessionRepository,
        scope_repository: ScopeRepository,
        finding_repository: FindingRepository,
        http_client_factory: Callable[[str, dict[str, str] | None], HttpClient],
    ) -> None:
        self._authorization = authorization_checker
        self._auth_sessions = auth_session_repository
        self._scopes = scope_repository
        self._findings = finding_repository
        self._http_client_factory = http_client_factory

    def execute(
        self,
        *,
        base_url: str,
        baseline_session_id: int,
        test_session_id: int,
        candidate_paths: list[str],
    ) -> list[Finding]:
        if baseline_session_id == test_session_id:
            raise ValueError("baseline_session_id and test_session_id must be two different sessions")
        if not candidate_paths:
            raise ValueError("at least one candidate path is required")

        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")
        self._authorization.authorize(hostname)

        baseline_headers = self._resolve_session_headers(baseline_session_id, hostname)
        test_headers = self._resolve_session_headers(test_session_id, hostname)

        anon_client = self._http_client_factory(base_url, None)
        baseline_client = self._http_client_factory(base_url, baseline_headers)
        test_client = self._http_client_factory(base_url, test_headers)
        try:
            persisted_findings: list[Finding] = []
            for path in candidate_paths:
                finding = self._check_path(
                    base_url=base_url,
                    path=path,
                    anon_client=anon_client,
                    baseline_client=baseline_client,
                    test_client=test_client,
                )
                if finding is not None:
                    persisted_findings.append(self._findings.add(finding))
            return persisted_findings
        finally:
            anon_client.close()
            baseline_client.close()
            test_client.close()

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

    def _check_path(
        self,
        *,
        base_url: str,
        path: str,
        anon_client: HttpClient,
        baseline_client: HttpClient,
        test_client: HttpClient,
    ) -> Finding | None:
        baseline_response = baseline_client.get(path)
        if baseline_response is None or not _is_success(baseline_response.status_code):
            logger.debug("skipping %s: baseline session could not access it either", path)
            return None

        test_response = test_client.get(path)
        if test_response is None or not _is_success(test_response.status_code):
            return None

        anon_response = anon_client.get(path)
        if anon_response is not None and _is_success(anon_response.status_code):
            logger.debug("skipping %s: reachable without any session, not identity-scoped", path)
            return None

        confidence = (
            Confidence.CONFIRMED
            if _bodies_look_like_the_same_resource(baseline_response.text, test_response.text)
            else Confidence.MEDIUM
        )
        anon_note = (
            "an unauthenticated request was not attempted for comparison"
            if anon_response is None
            else f"an unauthenticated request returned HTTP {anon_response.status_code}"
        )

        return Finding(
            title=f"Second session can access {path}, which appears scoped to another account",
            category=VulnerabilityCategory.AUTHORIZATION_ISSUE,
            severity=Severity.HIGH,
            confidence=confidence,
            description=(
                f"{path} returned a successful response for both the baseline session and an independent "
                f"second session, while {anon_note}. This suggests the endpoint checks that a caller is "
                "authenticated but not that the caller owns the specific resource at this path -- broken "
                "access control (IDOR). Confirm by hand that the two sessions represent different, "
                "unrelated accounts before treating this as more than a lead."
            ),
            affected_asset=base_url,
            location=baseline_response.url,
            evidence=(
                f"baseline session: HTTP {baseline_response.status_code}, {len(baseline_response.text)} bytes "
                f"| second session: HTTP {test_response.status_code}, {len(test_response.text)} bytes"
                + ("" if anon_response is None else f" | unauthenticated: HTTP {anon_response.status_code}")
            ),
            reproduction_steps=(
                f"Request {path} using the second session's credentials and confirm the response contains "
                "data that should belong only to the account behind the baseline session."
            ),
            remediation=(
                "Enforce an object-level ownership check on this endpoint -- verify the authenticated "
                "caller is permitted to access the specific resource requested, not just that they are "
                "logged in as someone."
            ),
            scanner_name=SCANNER_NAME,
        )
