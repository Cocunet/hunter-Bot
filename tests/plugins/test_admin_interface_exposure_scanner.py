from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.admin_interface_exposure.scanner import AdminInterfaceExposureScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestAdminInterfaceExposureScanner:
    def test_flags_exposed_werkzeug_console(self) -> None:
        http_client = FakeHttpClient(
            {
                "/console": ScannerResponse(
                    status_code=200, headers={}, text="<html>Werkzeug Debugger</html>", url=_BASE_URL + "/console"
                ),
            }
        )

        findings = AdminInterfaceExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "/console" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "critical"

    def test_flags_exposed_phpmyadmin(self) -> None:
        http_client = FakeHttpClient(
            {
                "/phpmyadmin/": ScannerResponse(
                    status_code=200, headers={}, text="phpMyAdmin login", url=_BASE_URL + "/phpmyadmin/"
                ),
            }
        )

        findings = AdminInterfaceExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "/phpmyadmin/" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "high"

    def test_ignores_404_candidate_paths(self) -> None:
        http_client = FakeHttpClient(
            {
                "/console": ScannerResponse(status_code=404, headers={}, text="", url=_BASE_URL + "/console"),
            }
        )

        findings = AdminInterfaceExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_ignores_empty_body_even_with_200(self) -> None:
        http_client = FakeHttpClient(
            {
                "/elmah.axd": ScannerResponse(status_code=200, headers={}, text="", url=_BASE_URL + "/elmah.axd"),
            }
        )

        findings = AdminInterfaceExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = AdminInterfaceExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
