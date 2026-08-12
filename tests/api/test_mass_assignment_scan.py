import http.server
import json
import threading

import pytest


class _VulnerableBindingHandler(http.server.BaseHTTPRequestHandler):
    """Simulates an endpoint that binds the whole request body onto the internal model."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode())
        body["id"] = 42
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args: object) -> None:
        pass


class _AllowlistedBindingHandler(http.server.BaseHTTPRequestHandler):
    """Simulates an endpoint that only accepts a fixed allowlist of fields."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode())
        response = {"id": 42, "name": body.get("name")}
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def vulnerable_binding_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableBindingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def allowlisted_binding_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AllowlistedBindingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestMassAssignmentScanApi:
    def _authorize(self, client, hostname: str) -> None:
        client.post("/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"})

    def test_confirms_field_took_effect(self, client, vulnerable_binding_server: str) -> None:
        hostname = vulnerable_binding_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/mass-assignment",
            json={
                "base_url": vulnerable_binding_server,
                "target_path": "/api/users",
                "injected_field": "role",
                "injected_value": "admin",
                "base_fields": {"name": "bob"},
            },
        )

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["scanner_name"] == "mass-assignment"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["confidence"] == "confirmed"

    def test_no_finding_against_allowlisted_endpoint(self, client, allowlisted_binding_server: str) -> None:
        hostname = allowlisted_binding_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/mass-assignment",
            json={
                "base_url": allowlisted_binding_server,
                "target_path": "/api/users",
                "injected_field": "role",
                "injected_value": "admin",
                "base_fields": {"name": "bob"},
            },
        )

        assert response.status_code == 200
        assert response.json() == []

    def test_unauthorized_target_returns_403(self, client, vulnerable_binding_server: str) -> None:
        response = client.post(
            "/scans/mass-assignment",
            json={
                "base_url": vulnerable_binding_server,
                "target_path": "/api/users",
                "injected_field": "role",
                "injected_value": "admin",
            },
        )

        assert response.status_code == 403

    def test_unsupported_method_returns_400(self, client, vulnerable_binding_server: str) -> None:
        hostname = vulnerable_binding_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/mass-assignment",
            json={
                "base_url": vulnerable_binding_server,
                "target_path": "/api/users",
                "injected_field": "role",
                "injected_value": "admin",
                "method": "DELETE",
            },
        )

        assert response.status_code == 400
