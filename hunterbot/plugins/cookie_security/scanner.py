from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient


def _parse_set_cookie(cookie_header: str) -> tuple[str, set[str]]:
    """Split one Set-Cookie header value into (cookie name, lowercase attribute names)."""
    parts = [part.strip() for part in cookie_header.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"
    attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
    return name, attributes


class CookieSecurityScanner:
    """Flags a cookie set on the root response that is missing Secure/HttpOnly/SameSite.

    Only the root path is requested. If the server sets more than one
    cookie, only the last Set-Cookie value survives ScannerResponse's
    dict-based headers (a limitation of the shared HttpClient, not this
    scanner) -- so this checks whichever cookie that leaves visible.
    """

    name = "cookie-security"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        response = http_client.get("/")
        if response is None:
            return []

        headers = {key.lower(): value for key, value in response.headers.items()}
        cookie_header = headers.get("set-cookie")
        if not cookie_header:
            return []

        cookie_name, attributes = _parse_set_cookie(cookie_header)
        is_https = response.url.startswith("https://")

        findings: list[Finding] = []
        if is_https and "secure" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie_name}' missing Secure attribute",
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The '{cookie_name}' cookie set by {response.url} is missing the Secure "
                        "attribute, so a client may send it over an unencrypted HTTP connection."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation="Add the Secure attribute so this cookie is only ever sent over HTTPS.",
                    scanner_name=self.name,
                )
            )
        if "httponly" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie_name}' missing HttpOnly attribute",
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The '{cookie_name}' cookie set by {response.url} is missing the HttpOnly "
                        "attribute, so client-side JavaScript can read it, making it a target for theft via XSS."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation="Add the HttpOnly attribute so this cookie is inaccessible to JavaScript.",
                    scanner_name=self.name,
                )
            )
        if "samesite" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The '{cookie_name}' cookie set by {response.url} does not set SameSite, "
                        "leaving requests that carry it more exposed to cross-site request forgery."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation="Set SameSite=Lax (or Strict, where workflows allow) on this cookie.",
                    scanner_name=self.name,
                )
            )
        return findings
