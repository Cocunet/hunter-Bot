import http.server
import threading

import pytest

from hunterbot.scanners.active_http_client import ActiveScannerHttpClient


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"content-type={content_type} body={body.decode(errors='replace')}".encode())

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def live_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestActiveScannerHttpClient:
    def test_get_behaves_like_the_read_only_client(self, live_server: str) -> None:
        client = ActiveScannerHttpClient(live_server)
        try:
            response = client.get("/")
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 200
        assert response.text == "ok"

    def test_post_sends_raw_body_and_content_type(self, live_server: str) -> None:
        client = ActiveScannerHttpClient(live_server)
        try:
            response = client.post("/submit", body='{"a": 1}', content_type="application/json")
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 200
        assert "content-type=application/json" in response.text
        assert '{"a": 1}' in response.text

    def test_post_multipart_sends_a_file(self, live_server: str) -> None:
        client = ActiveScannerHttpClient(live_server)
        try:
            response = client.post_multipart(
                "/upload",
                files={"file": ("probe.txt", b"hello-canary", "text/plain")},
                data={"description": "test upload"},
            )
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 200
        assert "multipart/form-data" in response.text
        assert "hello-canary" in response.text

    def test_extra_headers_are_sent(self, live_server: str) -> None:
        client = ActiveScannerHttpClient(live_server, extra_headers={"Cookie": "session=abc123"})
        try:
            response = client.get("/")
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 200

    def test_unreachable_target_returns_none_for_post(self) -> None:
        client = ActiveScannerHttpClient("http://127.0.0.1:1")
        try:
            response = client.post("/", body="x")
        finally:
            client.close()

        assert response is None
