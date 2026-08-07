from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.info_disclosure.scanner import InformationDisclosureScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestInformationDisclosureScanner:
    def test_flags_versioned_server_header(self) -> None:
        response = ScannerResponse(
            status_code=200, headers={"Server": "Apache/2.4.41 (Ubuntu)"}, text="<html></html>", url=_BASE_URL + "/"
        )
        http_client = FakeHttpClient({"/": response})

        findings = InformationDisclosureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        titles = {f.title for f in findings}
        assert "Server header discloses detailed version information" in titles

    def test_does_not_flag_generic_server_header(self) -> None:
        response = ScannerResponse(status_code=200, headers={"Server": "nginx"}, text="<html></html>", url=_BASE_URL + "/")
        http_client = FakeHttpClient({"/": response})

        findings = InformationDisclosureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        titles = {f.title for f in findings}
        assert "Server header discloses detailed version information" not in titles

    def test_flags_x_powered_by_header(self) -> None:
        response = ScannerResponse(
            status_code=200, headers={"X-Powered-By": "PHP/8.1.2"}, text="<html></html>", url=_BASE_URL + "/"
        )
        http_client = FakeHttpClient({"/": response})

        findings = InformationDisclosureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        titles = {f.title for f in findings}
        assert "X-Powered-By header discloses backend technology" in titles

    def test_flags_exposed_phpinfo(self) -> None:
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html></html>", url=_BASE_URL + "/"),
                "/phpinfo.php": ScannerResponse(
                    status_code=200, headers={}, text="phpinfo() output...", url=_BASE_URL + "/phpinfo.php"
                ),
            }
        )

        findings = InformationDisclosureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "/phpinfo.php" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "high"

    def test_ignores_404_candidate_paths(self) -> None:
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html></html>", url=_BASE_URL + "/"),
                "/phpinfo.php": ScannerResponse(status_code=404, headers={}, text="", url=_BASE_URL + "/phpinfo.php"),
            }
        )

        findings = InformationDisclosureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_root_yields_no_header_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = InformationDisclosureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
