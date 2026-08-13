from urllib.parse import urlparse

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# An RFC 2606 reserved TLD: guaranteed to never resolve, so a redirect that
# reflects it back verbatim proves the target is unvalidated rather than
# happening to point somewhere real.
_PROBE_TARGET = "https://hunterbot-redirect-probe.invalid/"
_PROBE_NETLOC = urlparse(_PROBE_TARGET).netloc

_REDIRECT_PARAMS = ("url", "redirect", "next", "return_url", "continue")
_CANDIDATE_PATHS = ("/", "/redirect", "/out")


class OpenRedirectScanner:
    """Probes common redirect-parameter names for unvalidated external redirects.

    For each (path, parameter name) pair in a small, well-known set, sends
    one read-only GET with the parameter pointing at ``_PROBE_TARGET`` and
    checks whether the server's 3xx response reflects that exact address
    back in ``Location`` -- i.e. would send a real browser there unmodified.
    Nothing is submitted or changed on the target; every request is a GET.

    Uses ``get_no_redirect`` rather than ``get``: the probe target is a
    non-resolving ``.invalid`` domain by design (no live network dependency,
    no third party ever actually receives a request), but the shared
    HttpClient's default ``get`` follows redirects itself -- it would chase
    the 3xx straight into a connection failure and this scanner would never
    see the ``Location`` header that proves the vulnerability.
    """

    name = "open-redirect"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for path in _CANDIDATE_PATHS:
            for param in _REDIRECT_PARAMS:
                probe_path = f"{path}?{param}={_PROBE_TARGET}"
                response = http_client.get_no_redirect(probe_path)
                if response is None or not (300 <= response.status_code < 400):
                    continue

                headers = {key.lower(): value for key, value in response.headers.items()}
                location = headers.get("location")
                if not location or urlparse(location).netloc != _PROBE_NETLOC:
                    continue

                findings.append(
                    Finding(
                        title=f"Open redirect via '{param}' parameter on {path}",
                        category=VulnerabilityCategory.INPUT_VALIDATION,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            f"A GET request to {probe_path} returned an HTTP {response.status_code} "
                            f"redirect to an attacker-controlled address supplied verbatim in the "
                            f"'{param}' parameter, without validating it against an allowlist."
                        ),
                        affected_asset=base_url,
                        location=response.url,
                        evidence=f"HTTP {response.status_code}, Location: {location}",
                        remediation=(
                            "Validate redirect targets against an allowlist of known-safe paths or "
                            "domains, or use indirection (e.g. lookup keys) instead of raw URLs."
                        ),
                        scanner_name=self.name,
                    )
                )
        return findings
