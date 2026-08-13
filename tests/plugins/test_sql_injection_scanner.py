from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.sql_injection.scanner import _PROBE_VALUE, SqlInjectionScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestSqlInjectionScanner:
    def test_flags_reflected_database_error(self) -> None:
        probe_path = f"/?id={_PROBE_VALUE}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=500,
                    headers={},
                    text="Warning: mysql_fetch_array(): supplied argument is not valid... "
                    "You have an error in your SQL syntax; check the manual",
                    url=_BASE_URL + probe_path,
                ),
            }
        )

        findings = SqlInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'id' query parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "critical"
        assert matching[0].confidence.value == "high"

    def test_error_present_in_baseline_is_not_flagged(self) -> None:
        probe_path = f"/?id={_PROBE_VALUE}"
        error_text = "You have an error in your SQL syntax"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text=error_text, url=_BASE_URL + "/"),
                probe_path: ScannerResponse(status_code=200, headers={}, text=error_text, url=_BASE_URL + probe_path),
            }
        )

        findings = SqlInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unrelated_response_is_not_flagged(self) -> None:
        probe_path = f"/?id={_PROBE_VALUE}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=200, headers={}, text="<html>no results</html>", url=_BASE_URL + probe_path
                ),
            }
        )

        findings = SqlInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = SqlInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_probes_every_candidate_parameter(self) -> None:
        http_client = FakeHttpClient({"/": ScannerResponse(status_code=200, headers={}, text="home", url=_BASE_URL)})

        SqlInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        probed = [p for p in http_client.requested_paths if p != "/"]
        assert len(probed) == 14
        assert all(_PROBE_VALUE in path for path in probed)
