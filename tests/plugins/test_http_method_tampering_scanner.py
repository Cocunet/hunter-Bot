from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.http_methods.scanner import HttpMethodTamperingScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestHttpMethodTamperingScanner:
    def test_flags_dangerous_methods_in_allow_header(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE, TRACE"},
            text="",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient(options_responses={"/": response})

        findings = HttpMethodTamperingScanner().scan(base_url=_BASE_URL, http_client=http_client)

        titles = {f.title for f in findings}
        assert "HTTP PUT method advertised as routable" in titles
        assert "HTTP DELETE method advertised as routable" in titles
        assert "HTTP TRACE method advertised as routable" in titles
        assert len(findings) == 3

    def test_safe_methods_only_are_not_flagged(self) -> None:
        response = ScannerResponse(
            status_code=200, headers={"Allow": "GET, HEAD, OPTIONS"}, text="", url=_BASE_URL + "/"
        )
        http_client = FakeHttpClient(options_responses={"/": response})

        findings = HttpMethodTamperingScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_missing_allow_header_yields_no_findings(self) -> None:
        response = ScannerResponse(status_code=200, headers={}, text="", url=_BASE_URL + "/")
        http_client = FakeHttpClient(options_responses={"/": response})

        findings = HttpMethodTamperingScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = HttpMethodTamperingScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
