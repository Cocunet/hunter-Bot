from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.directory_exposure.scanner import DirectoryListingExposureScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestDirectoryListingExposureScanner:
    def test_flags_apache_style_listing(self) -> None:
        body = "<html><head><title>Index of /uploads</title></head><body>...</body></html>"
        http_client = FakeHttpClient(
            {"/uploads/": ScannerResponse(status_code=200, headers={}, text=body, url=_BASE_URL + "/uploads/")}
        )

        findings = DirectoryListingExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert len(findings) == 1
        assert "/uploads/" in findings[0].title

    def test_flags_python_http_server_style_listing(self) -> None:
        body = '<html><body><h1>Directory listing for /backup/</h1><ul><li><a href="a.txt">a.txt</a></li></ul></body></html>'
        http_client = FakeHttpClient(
            {"/backup/": ScannerResponse(status_code=200, headers={}, text=body, url=_BASE_URL + "/backup/")}
        )

        findings = DirectoryListingExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert len(findings) == 1

    def test_ignores_normal_200_page(self) -> None:
        http_client = FakeHttpClient(
            {
                "/images/": ScannerResponse(
                    status_code=200, headers={}, text="<html><body>Gallery</body></html>", url=_BASE_URL + "/images/"
                )
            }
        )

        findings = DirectoryListingExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_ignores_404_responses(self) -> None:
        http_client = FakeHttpClient(
            {"/uploads/": ScannerResponse(status_code=404, headers={}, text="Not Found", url=_BASE_URL + "/uploads/")}
        )

        findings = DirectoryListingExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_checks_every_candidate_path(self) -> None:
        http_client = FakeHttpClient({})

        DirectoryListingExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert set(http_client.requested_paths) == {
            "/images/",
            "/uploads/",
            "/backup/",
            "/files/",
            "/assets/",
            "/logs/",
        }
