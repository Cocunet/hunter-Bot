import http.server
import threading

import pytest

from hunterbot.scanners.http_client import ScannerHttpClient


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

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


class TestScannerHttpClient:
    def test_get_follows_redirects(self, live_server: str) -> None:
        client = ScannerHttpClient(live_server)
        try:
            response = client.get("/redirect")
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 200
        assert response.url == f"{live_server}/target"

    def test_get_no_redirect_returns_the_redirect_response_itself(self, live_server: str) -> None:
        client = ScannerHttpClient(live_server)
        try:
            response = client.get_no_redirect("/redirect")
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 302
        assert response.headers.get("location") == "/target"

    def test_get_no_redirect_on_non_redirect_path_behaves_like_get(self, live_server: str) -> None:
        client = ScannerHttpClient(live_server)
        try:
            response = client.get_no_redirect("/plain")
        finally:
            client.close()

        assert response is not None
        assert response.status_code == 200
        assert response.text == "ok"

    def test_unreachable_target_returns_none(self) -> None:
        client = ScannerHttpClient("http://127.0.0.1:1")
        try:
            response = client.get("/")
        finally:
            client.close()

        assert response is None
