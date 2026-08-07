import pytest
from fastapi.testclient import TestClient

from hunterbot.api.app import create_app
from hunterbot.config.settings import get_config


@pytest.fixture
def configured_api_key(monkeypatch: pytest.MonkeyPatch):
    """Sets HUNTERBOT_API_KEY and clears get_config's cache around the test.

    get_config is process-wide @lru_cache'd, so a plain monkeypatch.setenv
    alone wouldn't take effect (or un-take-effect on teardown) without
    explicitly clearing that cache on both sides.
    """
    monkeypatch.setenv("HUNTERBOT_API_KEY", "test-secret-key")
    get_config.cache_clear()
    yield "test-secret-key"
    get_config.cache_clear()


class TestApiKeyAuth:
    def test_open_by_default(self, client) -> None:
        # No HUNTERBOT_API_KEY configured in the test environment.
        response = client.get("/scopes")
        assert response.status_code == 200

    def test_missing_header_rejected_when_key_configured(self, client, configured_api_key: str) -> None:
        response = client.get("/scopes")
        assert response.status_code == 401

    def test_wrong_key_rejected(self, client, configured_api_key: str) -> None:
        response = client.get("/scopes", headers={"Authorization": "Bearer wrong-key"})
        assert response.status_code == 401

    def test_correct_key_accepted(self, client, configured_api_key: str) -> None:
        response = client.get("/scopes", headers={"Authorization": f"Bearer {configured_api_key}"})
        assert response.status_code == 200

    def test_write_endpoints_are_also_gated(self, client, configured_api_key: str) -> None:
        response = client.post(
            "/scopes", json={"target": "example.com", "program_name": "Acme", "authorized_by": "Alice"}
        )
        assert response.status_code == 401


class TestDocsGating:
    def test_docs_available_when_no_key_configured(self) -> None:
        client = TestClient(create_app())
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200

    def test_docs_disabled_when_key_configured(self, configured_api_key: str) -> None:
        client = TestClient(create_app())
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
