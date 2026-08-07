from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# method -> (severity, why it's worth flagging when routable at all)
_DANGEROUS_METHODS: dict[str, tuple[Severity, str]] = {
    "PUT": (
        Severity.MEDIUM,
        "PUT can allow creating or overwriting resources if the route isn't properly authenticated.",
    ),
    "DELETE": (
        Severity.MEDIUM,
        "DELETE can allow removing resources if the route isn't properly authenticated.",
    ),
    "TRACE": (
        Severity.MEDIUM,
        "TRACE enables Cross-Site Tracing (XST), which can be used to read headers "
        "(e.g. cookies) that client-side script would otherwise be blocked from seeing.",
    ),
    "CONNECT": (
        Severity.LOW,
        "CONNECT is meant for proxying; a web application origin server rarely has a "
        "legitimate reason to advertise it.",
    ),
}


class HttpMethodTamperingScanner:
    """Flags dangerous HTTP methods advertised as routable via the Allow header.

    A single OPTIONS request against the root path is enough: OPTIONS is a
    safe, read-only method per RFC 7231 (it asks what's supported, it
    doesn't act), so this never actually issues a PUT/DELETE/TRACE itself
    -- it only checks whether the server says it would route them.
    """

    name = "http-method-tampering"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        response = http_client.options("/")
        if response is None:
            return []

        headers = {key.lower(): value for key, value in response.headers.items()}
        allow_header = headers.get("allow")
        if not allow_header:
            return []

        advertised = {method.strip().upper() for method in allow_header.split(",") if method.strip()}
        dangerous = advertised & _DANGEROUS_METHODS.keys()
        if not dangerous:
            return []

        findings: list[Finding] = []
        for method in sorted(dangerous):
            severity, remediation = _DANGEROUS_METHODS[method]
            findings.append(
                Finding(
                    title=f"HTTP {method} method advertised as routable",
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"An OPTIONS request to {response.url} lists {method} in its Allow "
                        f"header ({allow_header!r}), meaning the server will route that method "
                        "to this endpoint. Whether it's actually exploitable depends on whether "
                        "the handler enforces authentication/authorization -- this check only "
                        "confirms the method is routable, not that it's unprotected."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Allow: {allow_header}",
                    remediation=remediation,
                    scanner_name=self.name,
                )
            )
        return findings
