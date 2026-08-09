import json
import logging
import re
import secrets
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

SCANNER_NAME = "file-upload-rce"

# payload type -> (extension, template with {token}, the tag that marks
# unexecuted raw source -- if this literal substring is what comes back
# instead of the rendered token, the file was served, not run).
PAYLOAD_TYPES: dict[str, tuple[str, str, str]] = {
    "php": (".php", '<?php echo "HUNTERBOT_RCE_{token}"; ?>', "<?php"),
    "jsp": (".jsp", '<% out.println("HUNTERBOT_RCE_{token}"); %>', "<%"),
    "aspx": (".aspx", '<%@ Page Language="C#" %><% Response.Write("HUNTERBOT_RCE_{token}"); %>', "<%@"),
}

_TOKEN_PREFIX = "HUNTERBOT_RCE_"


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


def _find_candidate_paths(response, filename: str) -> list[str]:
    """Best-effort guess at where an upload endpoint put the file.

    Tries, in order of reliability: JSON response fields, a Location
    header, and a plain-text scan for the filename inside an href/src or a
    path-shaped substring. Every source is something the server itself told
    us -- nothing here is guessed independent of the response.
    """
    candidates: list[str] = []

    try:
        parsed = json.loads(response.text)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if parsed is not None:
        candidates.extend(_strings_containing(parsed, filename))

    location = response.headers.get("location") or response.headers.get("Location")
    if location and filename in location:
        candidates.append(location)

    for match in re.finditer(r'["\']([^"\']*' + re.escape(filename) + r'[^"\']*)["\']', response.text):
        candidates.append(match.group(1))

    bare_match = re.search(r"(/[\w\-./]*" + re.escape(filename) + r")", response.text)
    if bare_match:
        candidates.append(bare_match.group(1))

    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _strings_containing(value, needle: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if needle in value:
            found.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_strings_containing(item, needle))
    elif isinstance(value, list):
        for item in value:
            found.extend(_strings_containing(item, needle))
    return found


class RunFileUploadRceScanUseCase:
    """Confirms file-upload-to-RCE by actually uploading a canary and requesting it back.

    HunterBot cannot discover an upload endpoint on its own -- crawling and
    guessing form fields is out of scope, and blindly uploading to a
    guessed path is exactly the kind of unauthorized write HunterBot's
    read-only scanners refuse to make. The tester supplies the endpoint and
    field name deliberately. This is one of only two use-cases in HunterBot
    that issues state-changing requests at all (the other is
    RunRaceConditionScanUseCase) -- see
    hunterbot.core.interfaces.ActiveHttpClient.

    The uploaded payload is deliberately inert: for every supported
    language (see PAYLOAD_TYPES) it does nothing but echo a unique,
    per-scan random token -- no shell, no command execution, no
    filesystem/network access, no persistence. If the target executes it,
    the only observable effect is that token appearing in a later response;
    that's the entire proof. Running this leaves a real file on the target
    if the upload succeeds -- the resulting Finding's evidence records
    exactly where, precisely so it can be removed afterward.

    Three distinguishable outcomes:
      - the token comes back on its own (no raw source markers) -> the
        payload was executed: CONFIRMED remote code execution, CRITICAL.
      - the token comes back wrapped in its own source markers (e.g. the
        literal ``<?php`` tag) -> the dangerous extension was accepted and
        served, but not executed: CONFIRMED unrestricted upload, HIGH.
      - the upload succeeded (2xx) but no resulting file could be located
        from the response -> MEDIUM, flagged for manual follow-up rather
        than silently dropped, since the upload did observably do
        something.
      - anything else (upload rejected, file unreachable, token never
        reappears) -> no finding.
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
        upload_path: str,
        field_name: str = "file",
        payload_type: str = "php",
        extra_fields: dict[str, str] | None = None,
        fetch_path_template: str | None = None,
        session_id: int | None = None,
    ) -> list[Finding]:
        if payload_type not in PAYLOAD_TYPES:
            raise ValueError(f"unknown payload_type {payload_type!r}; expected one of {sorted(PAYLOAD_TYPES)}")

        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError(f"could not determine a hostname from {base_url!r}")
        self._authorization.authorize(hostname)

        headers = None
        if session_id is not None:
            headers = self._resolve_session_headers(session_id, hostname)

        extension, template, source_marker = PAYLOAD_TYPES[payload_type]
        token = secrets.token_hex(8)
        marker = f"{_TOKEN_PREFIX}{token}"
        payload_text = template.format(token=token)
        filename = f"hunterbot-{token}{extension}"

        http_client = self._http_client_factory(base_url, headers)
        try:
            upload_response = http_client.post_multipart(
                upload_path,
                files={field_name: (filename, payload_text.encode(), "application/octet-stream")},
                data=extra_fields or None,
            )
            if upload_response is None or not _is_success(upload_response.status_code):
                logger.debug("upload to %s was not accepted (no finding)", upload_path)
                return []

            candidate_paths = _find_candidate_paths(upload_response, filename)
            if fetch_path_template:
                candidate_paths.append(fetch_path_template.format(filename=filename))

            if not candidate_paths:
                finding = self._build_finding(
                    base_url=base_url,
                    upload_path=upload_path,
                    filename=filename,
                    fetch_url=None,
                    outcome="undetermined",
                    marker=marker,
                    upload_status=upload_response.status_code,
                )
                return [self._findings.add(finding)]

            for candidate in candidate_paths:
                fetch_response = http_client.get(candidate)
                if fetch_response is None or marker not in fetch_response.text:
                    continue

                executed = source_marker not in fetch_response.text
                finding = self._build_finding(
                    base_url=base_url,
                    upload_path=upload_path,
                    filename=filename,
                    fetch_url=fetch_response.url,
                    outcome="executed" if executed else "served-unexecuted",
                    marker=marker,
                    upload_status=upload_response.status_code,
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
        upload_path: str,
        filename: str,
        fetch_url: str | None,
        outcome: str,
        marker: str,
        upload_status: int,
    ) -> Finding:
        if outcome == "executed":
            return Finding(
                title=f"Remote code execution confirmed via file upload at {upload_path}",
                category=VulnerabilityCategory.INPUT_VALIDATION,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"A canary file ({filename}) uploaded to {upload_path} was executed by the "
                    f"server: requesting it back returned the unique token {marker!r} on its own, "
                    "with no trace of the source that produced it, proving arbitrary code ran on "
                    "the target."
                ),
                affected_asset=base_url,
                location=fetch_url or f"{base_url}{upload_path}",
                evidence=f"Uploaded {filename} (HTTP {upload_status}); fetching it back returned {marker!r} as executed output.",
                reproduction_steps=f"Upload {filename} to {upload_path}, then request the resulting file and observe the token in the response.",
                remediation=(
                    "Never execute uploaded files. Validate content by allowlist (extension + MIME + "
                    "magic bytes), store uploads outside the webroot, and serve them from a "
                    "non-executing path via signed URL. A real file was left on the target at "
                    f"{fetch_url or filename} -- remove it."
                ),
                scanner_name=SCANNER_NAME,
            )
        if outcome == "served-unexecuted":
            return Finding(
                title=f"Unrestricted file upload accepts server-side script extensions at {upload_path}",
                category=VulnerabilityCategory.INPUT_VALIDATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"A canary file ({filename}) with a server-side script extension uploaded to "
                    f"{upload_path} was accepted and is retrievable, but was served as raw source "
                    "rather than executed -- the extension/type validation gap is confirmed even "
                    "though execution wasn't. A server or path misconfiguration elsewhere could "
                    "still make this extension executable."
                ),
                affected_asset=base_url,
                location=fetch_url or f"{base_url}{upload_path}",
                evidence=f"Uploaded {filename} (HTTP {upload_status}); fetching it back returned the raw source, not executed output.",
                reproduction_steps=f"Upload {filename} to {upload_path} and request the resulting file back.",
                remediation=(
                    "Reject uploads by an extension/MIME allowlist rather than a blacklist, and store "
                    "uploads outside the webroot regardless. A real file was left on the target at "
                    f"{fetch_url or filename} -- remove it."
                ),
                scanner_name=SCANNER_NAME,
            )
        return Finding(
            title=f"Upload to {upload_path} accepted but resulting file location is undetermined",
            category=VulnerabilityCategory.INPUT_VALIDATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(
                f"A canary file ({filename}) uploaded to {upload_path} returned HTTP {upload_status} "
                "(accepted), but no resulting file URL could be found in the response body, headers, "
                "or (if provided) --fetch-path-template. Locate it manually to confirm whether it "
                "executes."
            ),
            affected_asset=base_url,
            location=f"{base_url}{upload_path}",
            evidence=f"Uploaded {filename} (HTTP {upload_status}); no candidate file location found to follow up on.",
            reproduction_steps=f"Upload {filename} to {upload_path}, find where it landed, and request it back.",
            remediation="Not yet confirmed -- locate the uploaded file and re-test with --fetch-path-template.",
            scanner_name=SCANNER_NAME,
        )
