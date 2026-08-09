import http.server
import threading

import pytest

_BASELINE_COOKIE = "session=alice"
_TEST_COOKIE = "session=bob"


class _AccessControlHandler(http.server.BaseHTTPRequestHandler):
    """Simulates an endpoint that checks *authentication* but not *ownership*.

    Any request carrying a recognized session cookie (alice's or bob's) gets
    back the same private-looking payload for /api/orders/1; no cookie at
    all is refused. That's exactly the IDOR shape this scanner looks for:
    bob's session can read alice's order.
    """

    def do_GET(self) -> None:
        cookie = self.headers.get("Cookie", "")
        if self.path == "/api/orders/1":
            if cookie in (_BASELINE_COOKIE, _TEST_COOKIE):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"order #1: 4 widgets, ship to 42 Main St")
                return
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def idor_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _AccessControlHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestAccessControlScanApi:
    def _authorize_and_register_sessions(self, client, hostname: str) -> tuple[int, int]:
        scope_id = client.post(
            "/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"}
        ).json()["id"]
        baseline_id = client.post(
            "/sessions",
            json={"scope_id": scope_id, "name": "alice", "headers": {"Cookie": _BASELINE_COOKIE}},
        ).json()["id"]
        test_id = client.post(
            "/sessions",
            json={"scope_id": scope_id, "name": "bob", "headers": {"Cookie": _TEST_COOKIE}},
        ).json()["id"]
        return baseline_id, test_id

    def test_flags_idor_when_second_session_reads_first_sessions_resource(
        self, client, idor_server: str
    ) -> None:
        hostname = idor_server.split("//", 1)[1].split(":", 1)[0]
        baseline_id, test_id = self._authorize_and_register_sessions(client, hostname)

        response = client.post(
            "/scans/access-control",
            json={
                "base_url": idor_server,
                "baseline_session_id": baseline_id,
                "test_session_id": test_id,
                "candidate_paths": ["/api/orders/1"],
            },
        )

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["scanner_name"] == "access-control-idor"
        assert findings[0]["confidence"] == "confirmed"

        listed = client.get("/findings").json()
        assert len(listed) == 1

    def test_no_finding_when_second_session_is_denied(self, client, idor_server: str) -> None:
        hostname = idor_server.split("//", 1)[1].split(":", 1)[0]
        scope_id = client.post(
            "/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"}
        ).json()["id"]
        baseline_id = client.post(
            "/sessions",
            json={"scope_id": scope_id, "name": "alice", "headers": {"Cookie": _BASELINE_COOKIE}},
        ).json()["id"]
        test_id = client.post(
            "/sessions",
            json={"scope_id": scope_id, "name": "stranger", "headers": {"Cookie": "session=nobody"}},
        ).json()["id"]

        response = client.post(
            "/scans/access-control",
            json={
                "base_url": idor_server,
                "baseline_session_id": baseline_id,
                "test_session_id": test_id,
                "candidate_paths": ["/api/orders/1"],
            },
        )

        assert response.status_code == 200
        assert response.json() == []

    def test_unauthorized_target_returns_403(self, client, idor_server: str) -> None:
        response = client.post(
            "/scans/access-control",
            json={
                "base_url": idor_server,
                "baseline_session_id": 1,
                "test_session_id": 2,
                "candidate_paths": ["/api/orders/1"],
            },
        )

        assert response.status_code == 403

    def test_session_scoped_to_different_target_returns_400(self, client, idor_server: str) -> None:
        hostname = idor_server.split("//", 1)[1].split(":", 1)[0]
        client.post("/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"})
        other_scope_id = client.post(
            "/scopes", json={"target": "other.example", "program_name": "Other", "authorized_by": "Alice"}
        ).json()["id"]
        baseline_id = client.post(
            "/sessions",
            json={"scope_id": other_scope_id, "name": "alice", "headers": {"Cookie": _BASELINE_COOKIE}},
        ).json()["id"]
        test_id = client.post(
            "/sessions",
            json={"scope_id": other_scope_id, "name": "bob", "headers": {"Cookie": _TEST_COOKIE}},
        ).json()["id"]

        response = client.post(
            "/scans/access-control",
            json={
                "base_url": idor_server,
                "baseline_session_id": baseline_id,
                "test_session_id": test_id,
                "candidate_paths": ["/api/orders/1"],
            },
        )

        assert response.status_code == 400

    def test_empty_candidate_paths_returns_422(self, client, idor_server: str) -> None:
        hostname = idor_server.split("//", 1)[1].split(":", 1)[0]
        baseline_id, test_id = self._authorize_and_register_sessions(client, hostname)

        response = client.post(
            "/scans/access-control",
            json={
                "base_url": idor_server,
                "baseline_session_id": baseline_id,
                "test_session_id": test_id,
                "candidate_paths": [],
            },
        )

        assert response.status_code == 422
