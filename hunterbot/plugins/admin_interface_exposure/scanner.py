from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# path -> (severity, what typically sits there and why it matters exposed)
_CANDIDATE_PATHS: dict[str, tuple[Severity, str]] = {
    "/console": (
        Severity.CRITICAL,
        "the Werkzeug/Flask interactive debugger console, which allows arbitrary code "
        "execution on the server if reachable without its PIN",
    ),
    "/_profiler": (
        Severity.MEDIUM,
        "the Symfony web profiler toolbar, which discloses request internals, "
        "configuration, and often session/database details",
    ),
    "/elmah.axd": (
        Severity.HIGH,
        "the ELMAH .NET error log viewer, which discloses unhandled exception details "
        "including stack traces and often connection strings",
    ),
    "/actuator/heapdump": (
        Severity.CRITICAL,
        "a Spring Boot Actuator heap dump, which can contain in-memory secrets such as "
        "session tokens, passwords, or API keys",
    ),
    "/actuator/beans": (
        Severity.MEDIUM,
        "a Spring Boot Actuator endpoint listing internal application beans and "
        "configuration wiring",
    ),
    "/adminer.php": (
        Severity.HIGH,
        "the Adminer database administration tool, a direct path to the database if "
        "left reachable with default or no credentials",
    ),
    "/phpmyadmin/": (
        Severity.HIGH,
        "the phpMyAdmin database administration interface, a direct path to the "
        "database if left reachable with default or no credentials",
    ),
}


class AdminInterfaceExposureScanner:
    """Flags exposed administrative or debugging interfaces at well-known paths.

    Distinct from InformationDisclosureScanner: that one covers passive
    metadata leaks (verbose headers, status/monitoring endpoints); this one
    covers interactive tooling that, left reachable, is itself a control
    surface -- a debugger console or DB admin panel is a much larger risk
    than a page merely disclosing information.
    """

    name = "admin-interface-exposure"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for path, (severity, leak_description) in _CANDIDATE_PATHS.items():
            response = http_client.get(path)
            if response is None or response.status_code != 200 or not response.text.strip():
                continue
            findings.append(
                Finding(
                    title=f"Administrative interface exposed at {path}",
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    description=f"A GET request to {path} returned HTTP 200; this is typically {leak_description}.",
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"HTTP {response.status_code}, {len(response.text)} bytes returned",
                    remediation="Remove or restrict access to this interface in production environments.",
                    scanner_name=self.name,
                )
            )
        return findings
