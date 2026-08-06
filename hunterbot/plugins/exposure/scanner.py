from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# A small, well-known set of paths that should never be served by a web
# root. Deliberately narrow and read-only (GET only, no fuzzing/brute force)
# — this is a targeted check, not a directory-busting tool.
_CANDIDATE_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/database.sql",
    "/.DS_Store",
)


class SensitiveFileExposureScanner:
    """Checks a fixed set of commonly-sensitive paths for accidental exposure."""

    name = "sensitive-file-exposure"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for path in _CANDIDATE_PATHS:
            response = http_client.get(path)
            if response is None or response.status_code != 200 or not response.text.strip():
                continue
            findings.append(
                Finding(
                    title=f"Potentially exposed sensitive file at {path}",
                    category=VulnerabilityCategory.SENSITIVE_FILE_EXPOSURE,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"A GET request to {path} returned HTTP 200 with non-empty content. "
                        "This path commonly contains sensitive configuration or credentials."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"HTTP {response.status_code}, {len(response.text)} bytes returned",
                    remediation="Remove this file from the web root or restrict access to it at the server/proxy level.",
                    scanner_name=self.name,
                )
            )
        return findings
