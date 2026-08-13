from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.open_redirect.scanner import _PROBE_TARGET, OpenRedirectScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestOpenRedirectScanner:
    def test_flags_reflected_redirect_target(self) -> None:
        probe_path = f"/?url={_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                probe_path: ScannerResponse(
                    status_code=302,
                    headers={"Location": _PROBE_TARGET},
                    text="",
                    url=_BASE_URL + probe_path,
                )
            }
        )

        findings = OpenRedirectScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'url' parameter on /" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "medium"

    def test_redirect_to_same_site_path_is_not_flagged(self) -> None:
        probe_path = f"/?url={_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                probe_path: ScannerResponse(
                    status_code=302,
                    headers={"Location": "/login"},
                    text="",
                    url=_BASE_URL + probe_path,
                )
            }
        )

        findings = OpenRedirectScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_non_redirect_response_is_not_flagged(self) -> None:
        probe_path = f"/?url={_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text="ok",
                    url=_BASE_URL + probe_path,
                )
            }
        )

        findings = OpenRedirectScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = OpenRedirectScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
