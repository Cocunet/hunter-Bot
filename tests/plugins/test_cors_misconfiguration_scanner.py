from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.cors_misconfiguration.scanner import CorsMisconfigurationScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestCorsMisconfigurationScanner:
    def test_flags_wildcard_origin_with_credentials(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            text="<html></html>",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = CorsMisconfigurationScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert len(findings) == 1
        assert findings[0].severity.value == "high"

    def test_wildcard_alone_is_not_flagged(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "*"},
            text="<html></html>",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = CorsMisconfigurationScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_specific_origin_with_credentials_is_not_flagged(self) -> None:
        response = ScannerResponse(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://trusted.example.com",
                "Access-Control-Allow-Credentials": "true",
            },
            text="<html></html>",
            url=_BASE_URL + "/",
        )
        http_client = FakeHttpClient({"/": response})

        findings = CorsMisconfigurationScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_no_cors_headers_yields_no_findings(self) -> None:
        response = ScannerResponse(status_code=200, headers={}, text="<html></html>", url=_BASE_URL + "/")
        http_client = FakeHttpClient({"/": response})

        findings = CorsMisconfigurationScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = CorsMisconfigurationScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
