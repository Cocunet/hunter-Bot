import http.server
import threading

import pytest


class _XxeHandler(http.server.BaseHTTPRequestHandler):
    """Simulates an endpoint whose XML parser resolves external entities."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        if "SYSTEM" in body and "/etc/passwd" in body:
            self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
        else:
            self.wfile.write(b"<r>ok</r>")

    def log_message(self, *args: object) -> None:
        pass


class _SafeXmlHandler(http.server.BaseHTTPRequestHandler):
    """Simulates an endpoint whose parser has external entities disabled."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"<r>ok</r>")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def vulnerable_xml_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _XxeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def safe_xml_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SafeXmlHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestXxeScanApi:
    def _authorize(self, client, hostname: str) -> None:
        client.post("/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"})

    def test_confirms_file_read(self, client, vulnerable_xml_server: str) -> None:
        hostname = vulnerable_xml_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/xxe", json={"base_url": vulnerable_xml_server, "target_path": "/api/import"}
        )

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["scanner_name"] == "xxe"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["confidence"] == "confirmed"

    def test_no_finding_against_safe_parser(self, client, safe_xml_server: str) -> None:
        hostname = safe_xml_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post("/scans/xxe", json={"base_url": safe_xml_server, "target_path": "/api/import"})

        assert response.status_code == 200
        assert response.json() == []

    def test_unauthorized_target_returns_403(self, client, vulnerable_xml_server: str) -> None:
        response = client.post(
            "/scans/xxe", json={"base_url": vulnerable_xml_server, "target_path": "/api/import"}
        )

        assert response.status_code == 403
