from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient


class CorsMisconfigurationScanner:
    """Flags a CORS policy that pairs a wildcard origin with allowed credentials.

    ``Access-Control-Allow-Origin: *`` together with
    ``Access-Control-Allow-Credentials: true`` is invalid per the Fetch
    spec -- a compliant browser refuses to honor the wildcard once
    credentials are allowed -- but plenty of real servers still emit it,
    and any client that doesn't enforce that rule will not stop the
    request. This is a static response property, so it's detectable from
    a single default GET; it doesn't require sending a custom Origin
    header, which the shared HttpClient doesn't support.
    """

    name = "cors-misconfiguration"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        response = http_client.get("/")
        if response is None:
            return []

        headers = {key.lower(): value for key, value in response.headers.items()}
        allow_origin = headers.get("access-control-allow-origin", "").strip()
        allow_credentials = headers.get("access-control-allow-credentials", "").strip().lower()

        if allow_origin != "*" or allow_credentials != "true":
            return []

        return [
            Finding(
                title="CORS policy combines wildcard origin with allowed credentials",
                category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=(
                    f"{response.url} responds with Access-Control-Allow-Origin: * and "
                    "Access-Control-Allow-Credentials: true at the same time. This combination is "
                    "invalid per the Fetch spec, but a client that doesn't enforce that rule can be "
                    "made to expose authenticated responses to any origin."
                ),
                affected_asset=base_url,
                location=response.url,
                evidence=f"Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: {allow_credentials}",
                remediation=(
                    "Return a specific, validated Origin (never '*') whenever "
                    "Access-Control-Allow-Credentials is true."
                ),
                scanner_name=self.name,
            )
        ]
