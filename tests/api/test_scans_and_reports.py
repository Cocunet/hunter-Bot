import http.server
import threading

import pytest


class _PlainHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>hello</html>")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def live_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _PlainHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestScansApi:
    def test_scan_unauthorized_target_returns_403(self, client, live_server: str) -> None:
        response = client.post("/scans", json={"base_url": live_server})

        assert response.status_code == 403

    def test_scan_authorized_target_finds_missing_headers(self, client, live_server: str) -> None:
        client.post(
            "/scopes",
            json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"},
        )

        response = client.post("/scans", json={"base_url": live_server})

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) > 0
        assert any(f["scanner_name"] == "missing-security-headers" for f in findings)

        listed = client.get("/findings").json()
        assert len(listed) == len(findings)


class TestReportsApi:
    def test_generate_markdown_report_after_scan(self, client, live_server: str) -> None:
        client.post(
            "/scopes",
            json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"},
        )
        client.post("/scans", json={"base_url": live_server})

        response = client.post("/reports", json={"format": "markdown"})

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
        assert b"HunterBot Vulnerability Report" in response.content

    def test_unsupported_format_returns_400(self, client) -> None:
        response = client.post("/reports", json={"format": "csv"})

        assert response.status_code == 400
