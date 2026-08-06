from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.headers.scanner import MissingSecurityHeadersScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestMissingSecurityHeadersScanner:
    def test_flags_all_missing_headers(self) -> None:
        response = ScannerResponse(status_code=200, headers={}, text="<html></html>", url=_BASE_URL + "/")
        http_client = FakeHttpClient({"/": response})

        findings = MissingSecurityHeadersScanner().scan(base_url=_BASE_URL, http_client=http_client)

        titles = {finding.title for finding in findings}
        assert "Missing content-security-policy header" in titles
        assert "Missing x-frame-options header" in titles
        assert len(findings) == 4

    def test_present_headers_are_not_flagged(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=63072000",
                "X-Content-Type-Options": "nosniff",
            },
            text="<html></html>",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = MissingSecurityHeadersScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})  # "/" not configured -> None

        findings = MissingSecurityHeadersScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
