from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.cookie_security.scanner import CookieSecurityScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestCookieSecurityScanner:
    def test_flags_cookie_missing_all_attributes(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={"Set-Cookie": "session=abc123; Path=/"},
            text="<html></html>",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = CookieSecurityScanner().scan(base_url=_BASE_URL, http_client=http_client)

        titles = {f.title for f in findings}
        assert "Cookie 'session' missing Secure attribute" in titles
        assert "Cookie 'session' missing HttpOnly attribute" in titles
        assert "Cookie 'session' missing SameSite attribute" in titles
        assert len(findings) == 3

    def test_fully_secured_cookie_is_not_flagged(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"},
            text="<html></html>",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = CookieSecurityScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_missing_secure_not_flagged_over_plain_http(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={"Set-Cookie": "session=abc123; HttpOnly; SameSite=Strict"},
            text="<html></html>",
            url="http://example.com/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = CookieSecurityScanner().scan(base_url="http://example.com", http_client=http_client)

        assert findings == []

    def test_no_cookie_yields_no_findings(self) -> None:
        response = ScannerResponse(status_code=200, headers={}, text="<html></html>", url=_BASE_URL + "/")
        http_client = FakeHttpClient({"/": response})

        findings = CookieSecurityScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = CookieSecurityScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
