from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.exposure.scanner import SensitiveFileExposureScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestSensitiveFileExposureScanner:
    def test_flags_exposed_env_file(self) -> None:
        http_client = FakeHttpClient(
            {
                "/.env": ScannerResponse(
                    status_code=200, headers={}, text="DB_PASSWORD=secret", url=_BASE_URL + "/.env"
                )
            }
        )

        findings = SensitiveFileExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert len(findings) == 1
        assert "/.env" in findings[0].title

    def test_ignores_404_responses(self) -> None:
        http_client = FakeHttpClient(
            {"/.env": ScannerResponse(status_code=404, headers={}, text="Not Found", url=_BASE_URL + "/.env")}
        )

        findings = SensitiveFileExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_ignores_empty_200_response(self) -> None:
        http_client = FakeHttpClient(
            {"/.env": ScannerResponse(status_code=200, headers={}, text="   ", url=_BASE_URL + "/.env")}
        )

        findings = SensitiveFileExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_checks_every_candidate_path(self) -> None:
        http_client = FakeHttpClient({})

        SensitiveFileExposureScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert set(http_client.requested_paths) == {
            "/.env",
            "/.git/config",
            "/backup.zip",
            "/database.sql",
            "/.DS_Store",
        }
