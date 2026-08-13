import re

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

_VERSION_PATTERN = re.compile(r"\d+\.\d+")

# path -> (severity, human-readable description of what typically leaks there)
_CANDIDATE_PATHS: dict[str, tuple[Severity, str]] = {
    "/phpinfo.php": (Severity.HIGH, "a phpinfo() page, which discloses server configuration, paths, and environment variables"),
    "/server-status": (Severity.MEDIUM, "the Apache mod_status page, which discloses active requests and client IPs"),
    "/server-info": (Severity.MEDIUM, "the Apache mod_info page, which discloses server module configuration"),
    "/actuator/env": (Severity.HIGH, "a Spring Boot Actuator environment endpoint, which can disclose configuration and secrets"),
    "/debug/pprof/": (Severity.MEDIUM, "a Go net/http/pprof debug endpoint, which discloses runtime profiling data"),
}


class InformationDisclosureScanner:
    """Flags verbose server headers and a small set of well-known info-leak paths."""

    name = "information-disclosure"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_headers(base_url, http_client))
        findings.extend(self._check_candidate_paths(base_url, http_client))
        return findings

    def _check_headers(self, base_url: str, http_client: HttpClient) -> list[Finding]:
        response = http_client.get("/")
        if response is None:
            return []

        headers = {key.lower(): value for key, value in response.headers.items()}
        findings: list[Finding] = []

        server_header = headers.get("server")
        if server_header and _VERSION_PATTERN.search(server_header):
            findings.append(
                Finding(
                    title="Server header discloses detailed version information",
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The Server response header ({server_header!r}) includes a specific version "
                        "number, which helps an attacker identify known vulnerabilities for that exact "
                        "software version."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Server: {server_header}",
                    remediation="Configure the web server to omit or generalize the Server header.",
                    scanner_name=self.name,
                )
            )

        if "x-powered-by" in headers:
            findings.append(
                Finding(
                    title="X-Powered-By header discloses backend technology",
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The X-Powered-By response header ({headers['x-powered-by']!r}) discloses the "
                        "backend framework/language in use."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"X-Powered-By: {headers['x-powered-by']}",
                    remediation="Disable the X-Powered-By header at the framework or server level.",
                    scanner_name=self.name,
                )
            )

        return findings

    def _check_candidate_paths(self, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for path, (severity, leak_description) in _CANDIDATE_PATHS.items():
            response = http_client.get(path)
            if response is None or response.status_code != 200 or not response.text.strip():
                continue
            findings.append(
                Finding(
                    title=f"Information disclosure endpoint exposed at {path}",
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    description=f"A GET request to {path} returned HTTP 200; this is typically {leak_description}.",
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"HTTP {response.status_code}, {len(response.text)} bytes returned",
                    remediation="Remove or restrict access to this endpoint in production environments.",
                    scanner_name=self.name,
                )
            )
        return findings
