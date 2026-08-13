from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# A small, well-known set of paths commonly left with directory listing
# enabled by accident. Deliberately narrow and read-only (GET only, no
# fuzzing/brute force) — this is a targeted check, not a directory-busting
# tool.
_CANDIDATE_PATHS: tuple[str, ...] = (
    "/images/",
    "/uploads/",
    "/backup/",
    "/files/",
    "/assets/",
    "/logs/",
)

# Passive fingerprints of common directory-listing renderers (Apache's
# autoindex, Python's http.server, nginx's autoindex). Case-insensitive.
_LISTING_MARKERS: tuple[str, ...] = (
    "index of /",
    "directory listing for",
    "parent directory</a>",
    "[to parent directory]",
)


class DirectoryListingExposureScanner:
    """Checks a fixed set of commonly-sensitive directories for exposed listings."""

    name = "directory-listing-exposure"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for path in _CANDIDATE_PATHS:
            response = http_client.get(path)
            if response is None or response.status_code != 200:
                continue
            lowered_body = response.text.lower()
            if not any(marker in lowered_body for marker in _LISTING_MARKERS):
                continue
            findings.append(
                Finding(
                    title=f"Directory listing exposed at {path}",
                    category=VulnerabilityCategory.DIRECTORY_EXPOSURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"A GET request to {path} returned HTTP 200 with a response body that matches "
                        "known directory-listing output, suggesting the web server is enumerating this "
                        "directory's contents instead of returning an index page or 403/404."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"HTTP {response.status_code}, matched a directory-listing fingerprint",
                    remediation=(
                        "Disable directory listing/autoindex for this path at the web server level, "
                        "or place an index file in the directory."
                    ),
                    scanner_name=self.name,
                )
            )
        return findings
