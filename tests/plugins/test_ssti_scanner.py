from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.ssti.scanner import _EXPECTED_RESULT, SstiScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"
_JINJA_PAYLOAD = "{{1337*1337}}"


class TestSstiScanner:
    def test_flags_evaluated_expression(self) -> None:
        probe_path = f"/?name={_JINJA_PAYLOAD}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text=f"<html>hello {_EXPECTED_RESULT}</html>",
                    url=_BASE_URL + probe_path,
                ),
            }
        )

        findings = SstiScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'name' query parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "critical"
        assert matching[0].confidence.value == "confirmed"

    def test_verbatim_reflection_is_not_flagged(self) -> None:
        probe_path = f"/?name={_JINJA_PAYLOAD}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text=f"<html>hello {_JINJA_PAYLOAD}</html>",
                    url=_BASE_URL + probe_path,
                ),
            }
        )

        findings = SstiScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_result_present_in_baseline_disables_scanner(self) -> None:
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(
                    status_code=200, headers={}, text=f"count: {_EXPECTED_RESULT}", url=_BASE_URL + "/"
                ),
            }
        )

        findings = SstiScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unrelated_response_is_not_flagged(self) -> None:
        probe_path = f"/?name={_JINJA_PAYLOAD}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=200, headers={}, text="<html>hello there</html>", url=_BASE_URL + probe_path
                ),
            }
        )

        findings = SstiScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = SstiScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
