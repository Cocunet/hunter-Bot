import http.server
import threading
import time

import pytest


def _make_race_handler():
    """Builds a Handler class closed over fresh, per-fixture mutable state.

    /api/redeem-guarded is protected by a lock: only the first request to
    acquire it succeeds. /api/redeem-unguarded deliberately reads the
    current count, sleeps (widening the TOCTOU window so the race is
    reliable under test), then writes -- exactly the bug this scanner is
    built to confirm.
    """
    state = {"guarded_count": 0, "unguarded_count": 0}
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)

            if self.path == "/api/redeem-guarded":
                with lock:
                    success = state["guarded_count"] < 1
                    if success:
                        state["guarded_count"] += 1
            elif self.path == "/api/redeem-unguarded":
                current = state["unguarded_count"]
                time.sleep(0.02)
                state["unguarded_count"] = current + 1
                success = current < 1
            else:
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200 if success else 409)
            self.end_headers()
            self.wfile.write(b"ok" if success else b"conflict")

        def log_message(self, *args: object) -> None:
            pass

    return Handler


@pytest.fixture
def race_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_race_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestRaceConditionScanApi:
    def _authorize(self, client, hostname: str) -> None:
        client.post("/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"})

    def test_confirms_race_on_unguarded_endpoint(self, client, race_server: str) -> None:
        hostname = race_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/race-condition",
            json={"base_url": race_server, "path": "/api/redeem-unguarded", "concurrency": 15},
        )

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["scanner_name"] == "race-condition"
        assert findings[0]["confidence"] == "confirmed"
        assert findings[0]["severity"] == "high"

    def test_no_finding_on_guarded_endpoint(self, client, race_server: str) -> None:
        hostname = race_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/race-condition",
            json={"base_url": race_server, "path": "/api/redeem-guarded", "concurrency": 15},
        )

        assert response.status_code == 200
        assert response.json() == []

    def test_unauthorized_target_returns_403(self, client, race_server: str) -> None:
        response = client.post(
            "/scans/race-condition",
            json={"base_url": race_server, "path": "/api/redeem-unguarded", "concurrency": 5},
        )

        assert response.status_code == 403

    def test_concurrency_out_of_range_returns_422(self, client, race_server: str) -> None:
        hostname = race_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/race-condition",
            json={"base_url": race_server, "path": "/api/redeem-unguarded", "concurrency": 1000},
        )

        assert response.status_code == 422
