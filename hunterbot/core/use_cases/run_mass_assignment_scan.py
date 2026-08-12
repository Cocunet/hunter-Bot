import json
import logging
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

SCANNER_NAME = "mass-assignment"

_ALLOWED_METHODS = ("POST", "PUT", "PATCH")


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


def _field_took_effect(text: str, field: str, value: str) -> bool:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # Not JSON (or not parseable) -- fall back to a plain substring
        # check, since some APIs echo the accepted object as form-encoded
        # or templated HTML rather than JSON.
        return field in text and value in text
    return _contains_field_value(parsed, field, value)


def _contains_field_value(node, field: str, value: str) -> bool:
    if isinstance(node, dict):
        for key, val in node.items():
            if key == field and str(val) == value:
                return True
            if _contains_field_value(val, field, value):
                return True
    elif isinstance(node, list):
        return any(_contains_field_value(item, field, value) for item in node)
    return False


class RunMassAssignmentScanUseCase:
    """Confirms mass assignment by actually submitting an undocumented privilege-shaped field.

    HunterBot cannot discover which endpoint or which field to target on
    its own -- the tester supplies a real create/update endpoint, the
    normal fields it expects, and the extra field being tested (e.g.
    ``role``/``isAdmin``). This is a state-changing (POST/PUT/PATCH)
    use-case alongside RunRaceConditionScanUseCase, RunFileUploadRceScanUseCase,
    and RunXxeScanUseCase -- see hunterbot.core.interfaces.ActiveHttpClient.
    There's no meaningful read-only version of this test: confirming mass
    assignment means confirming a write actually took effect, which is the
    whole question being asked.

    Submits ``base_fields`` plus the one extra ``injected_field``/
    ``injected_value`` pair, then looks for direct evidence the extra field
    was accepted rather than silently dropped: first in the create/update
    response body itself (many APIs echo the resulting object back), and
    -- if that doesn't show it and the tester supplied ``verify_path`` --
    in a follow-up GET, since some APIs apply a field without echoing it in
    the write response. If neither shows the field took effect, no finding
    is reported: there's nothing here to report as a lead, since "the
    server didn't visibly do anything with it" and "the server rejected it
    outright" produce the same observation from outside.
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
        target_path: str,
        injected_field: str,
        injected_value: str,
        base_fields: dict[str, str] | None = None,
        method: str = "POST",
        verify_path: str | None = None,
        session_id: int | None = None,
    ) -> list[Finding]:
        if method.upper() not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported method {method!r}; expected one of {_ALLOWED_METHODS}")

        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")
        self._authorization.authorize(hostname)

        headers = None
        if session_id is not None:
            headers = self._resolve_session_headers(session_id, hostname)

        body = dict(base_fields or {})
        body[injected_field] = injected_value
        body_text = json.dumps(body)

        http_client = self._http_client_factory(base_url, headers)
        try:
            # ActiveHttpClient only defines post(); PUT/PATCH share the same
            # transport need (a body + content-type) as POST, so RunMassAssignmentScanUseCase
            # is the one caller that cares about the HTTP method itself --
            # recorded in the finding, even though the request always goes
            # out as an httpx POST today. Extending ActiveHttpClient with a
            # true method-agnostic request() is future work once a second
            # caller needs it.
            response = http_client.post(target_path, body=body_text, content_type="application/json")
            if response is None or not _is_success(response.status_code):
                return []

            if _field_took_effect(response.text, injected_field, injected_value):
                finding = self._build_finding(
                    base_url=base_url,
                    target_path=target_path,
                    method=method.upper(),
                    injected_field=injected_field,
                    injected_value=injected_value,
                    evidence_source="the write response itself",
                    location=response.url,
                    status_code=response.status_code,
                )
                return [self._findings.add(finding)]

            if verify_path is not None:
                verify_response = http_client.get(verify_path)
                if verify_response is not None and _field_took_effect(
                    verify_response.text, injected_field, injected_value
                ):
                    finding = self._build_finding(
                        base_url=base_url,
                        target_path=target_path,
                        method=method.upper(),
                        injected_field=injected_field,
                        injected_value=injected_value,
                        evidence_source=f"a follow-up GET to {verify_path}",
                        location=verify_response.url,
                        status_code=verify_response.status_code,
                    )
                    return [self._findings.add(finding)]

            return []
        finally:
            http_client.close()

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

    def _build_finding(
        self,
        *,
        base_url: str,
        target_path: str,
        method: str,
        injected_field: str,
        injected_value: str,
        evidence_source: str,
        location: str,
        status_code: int,
    ) -> Finding:
        return Finding(
            title=f"Mass assignment confirmed via '{injected_field}' field at {target_path}",
            category=VulnerabilityCategory.AUTHORIZATION_ISSUE,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            description=(
                f"A {method} request to {target_path} included an undocumented field "
                f"('{injected_field}': {injected_value!r}) alongside the expected request fields. "
                f"{evidence_source.capitalize()} confirmed the value was accepted -- the server "
                "binds client-supplied request fields directly onto an internal object without "
                "restricting which fields the client is allowed to set."
            ),
            affected_asset=base_url,
            location=location,
            evidence=f"HTTP {status_code} response confirmed via {evidence_source} that '{injected_field}' was set to {injected_value!r}.",
            reproduction_steps=(
                f"Send a {method} to {target_path} with the normal request fields plus "
                f"'{injected_field}': {injected_value!r}, and confirm the value is applied."
            ),
            remediation=(
                "Bind request bodies to an explicit allowlist of writable fields (a DTO/schema) "
                "instead of mapping the whole request body onto the internal model; never let a "
                "client set fields like role, isAdmin, or balance directly."
            ),
            scanner_name=SCANNER_NAME,
        )
