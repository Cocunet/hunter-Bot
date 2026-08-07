class TestScopesApi:
    def test_create_and_list_scope(self, client) -> None:
        response = client.post(
            "/scopes",
            json={"target": "example.com", "program_name": "Acme", "authorized_by": "Alice"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["target"] == "example.com"
        assert body["id"] is not None

        listed = client.get("/scopes").json()
        assert len(listed) == 1
        assert listed[0]["target"] == "example.com"

    def test_check_authorized_target(self, client) -> None:
        client.post(
            "/scopes",
            json={"target": "example.com", "program_name": "Acme", "authorized_by": "Alice"},
        )

        response = client.get("/scopes/check", params={"target": "api.example.com"})

        assert response.status_code == 200
        body = response.json()
        assert body["authorized"] is True
        assert body["scope"]["target"] == "example.com"

    def test_check_unauthorized_target(self, client) -> None:
        response = client.get("/scopes/check", params={"target": "unknown.example.com"})

        assert response.status_code == 200
        body = response.json()
        assert body["authorized"] is False
        assert body["scope"] is None

    def test_invalid_expiry_returns_422(self, client) -> None:
        response = client.post(
            "/scopes",
            json={
                "target": "example.com",
                "program_name": "Acme",
                "authorized_by": "Alice",
                "expires_at": "2000-01-01T00:00:00Z",
            },
        )

        assert response.status_code == 422
