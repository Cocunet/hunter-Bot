from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# header (lowercase) -> (severity if missing, remediation guidance)
_REQUIRED_HEADERS: dict[str, tuple[Severity, str]] = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Define a Content-Security-Policy to restrict which script/style/resource origins the browser will load.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Set X-Frame-Options (or a CSP frame-ancestors directive) to prevent clickjacking via iframe embedding.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Set Strict-Transport-Security to force browsers to use HTTPS for this origin.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Set X-Content-Type-Options: nosniff to stop browsers from MIME-sniffing responses.",
    ),
}


class MissingSecurityHeadersScanner:
    """Flags security-relevant HTTP response headers that are absent.

    A single GET against the target's root path is enough to evaluate every
    header this scanner checks, so it never makes more than one request.
    """

    name = "missing-security-headers"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        response = http_client.get("/")
        if response is None:
            return []

        present_headers = {key.lower() for key in response.headers}

        findings: list[Finding] = []
        for header, (severity, remediation) in _REQUIRED_HEADERS.items():
            if header in present_headers:
                continue
            findings.append(
                Finding(
                    title=f"Missing {header} header",
                    category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    description=f"The response from {response.url} does not set the {header} header.",
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Observed response headers: {sorted(present_headers)}",
                    remediation=remediation,
                    scanner_name=self.name,
                )
            )
        return findings
