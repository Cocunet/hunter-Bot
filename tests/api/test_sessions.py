class TestSessionsApi:
    def _create_scope(self, client) -> int:
        response = client.post(
            "/scopes", json={"target": "example.com", "program_name": "Acme", "authorized_by": "Alice"}
        )
        return response.json()["id"]

    def test_create_and_list_session(self, client) -> None:
        scope_id = self._create_scope(client)

        response = client.post(
            "/sessions",
            json={"scope_id": scope_id, "name": "admin-user", "headers": {"Cookie": "session=super-secret"}},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["name"] == "admin-user"
        assert body["scope_id"] == scope_id
        assert body["is_active"] is True
        # Header values are credential material and must never come back.
        assert body["headers"] == {"Cookie": "***redacted***"}
        assert "super-secret" not in response.text

        listed = client.get("/sessions").json()
        assert len(listed) == 1
        assert listed[0]["headers"] == {"Cookie": "***redacted***"}

    def test_create_session_for_unknown_scope_returns_400(self, client) -> None:
        response = client.post(
            "/sessions", json={"scope_id": 999, "name": "admin-user", "headers": {"Cookie": "x"}}
        )

        assert response.status_code == 400

    def test_create_session_with_empty_headers_returns_422(self, client) -> None:
        scope_id = self._create_scope(client)

        response = client.post("/sessions", json={"scope_id": scope_id, "name": "admin-user", "headers": {}})

        assert response.status_code == 422

    def test_list_filters_by_scope_id(self, client) -> None:
        scope_a = self._create_scope(client)
        scope_b = client.post(
            "/scopes", json={"target": "other.example.com", "program_name": "Acme", "authorized_by": "Alice"}
        ).json()["id"]
        client.post("/sessions", json={"scope_id": scope_a, "name": "session-a", "headers": {"Cookie": "a"}})
        client.post("/sessions", json={"scope_id": scope_b, "name": "session-b", "headers": {"Cookie": "b"}})

        results = client.get("/sessions", params={"scope_id": scope_a}).json()

        assert len(results) == 1
        assert results[0]["name"] == "session-a"


class TestScanWithSessionApi:
    def test_scan_with_unknown_session_returns_404(self, client, live_server: str) -> None:
        client.post(
            "/scopes", json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"}
        )

        response = client.post("/scans", json={"base_url": live_server, "session_id": 999})

        assert response.status_code == 404

    def test_scan_with_session_from_wrong_scope_returns_403(self, client, live_server: str) -> None:
        client.post(
            "/scopes", json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"}
        )
        other_scope_id = client.post(
            "/scopes", json={"target": "totally-different.example.com", "program_name": "X", "authorized_by": "Y"}
        ).json()["id"]
        session_id = client.post(
            "/sessions",
            json={"scope_id": other_scope_id, "name": "admin-user", "headers": {"Cookie": "session=abc"}},
        ).json()["id"]

        response = client.post("/scans", json={"base_url": live_server, "session_id": session_id})

        assert response.status_code == 403

    def test_scan_with_valid_session_succeeds(self, client, live_server: str) -> None:
        scope_id = client.post(
            "/scopes", json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"}
        ).json()["id"]
        session_id = client.post(
            "/sessions",
            json={"scope_id": scope_id, "name": "admin-user", "headers": {"Cookie": "session=abc"}},
        ).json()["id"]

        response = client.post("/scans", json={"base_url": live_server, "session_id": session_id})

        assert response.status_code == 200
        assert len(response.json()) > 0
