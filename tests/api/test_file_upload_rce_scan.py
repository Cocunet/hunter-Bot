import http.server
import re
import threading

import pytest


def _make_upload_handler(*, execute: bool):
    """Builds a Handler simulating an upload endpoint.

    POST /api/upload accepts a multipart file, stores its raw bytes in
    memory, and returns a JSON body pointing at where it landed. GET
    /uploads/<name> serves it back -- either "executed" (only the code
    between the quotes, mimicking a PHP interpreter evaluating `echo`) or
    verbatim (mimicking a misconfigured server that just serves the file),
    depending on ``execute``.
    """
    store: dict[str, bytes] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/api/upload":
                self.send_response(404)
                self.end_headers()
                return
            content_type = self.headers.get("Content-Type", "")
            boundary = content_type.split("boundary=")[-1].encode()
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            filename = "upload"
            file_bytes = b""
            for part in body.split(b"--" + boundary):
                if b'name="file"' not in part:
                    continue
                header_end = part.find(b"\r\n\r\n")
                headers_blob = part[:header_end].decode(errors="replace")
                content = part[header_end + 4 :]
                if content.endswith(b"\r\n"):
                    content = content[:-2]
                file_bytes = content
                match = re.search(r'filename="([^"]*)"', headers_blob)
                if match:
                    filename = match.group(1)
                break
            store[filename] = file_bytes

            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"url": "/uploads/{filename}"}}'.encode())

        def do_GET(self) -> None:
            name = self.path.rsplit("/", 1)[-1]
            if name not in store:
                self.send_response(404)
                self.end_headers()
                return
            content = store[name]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if execute and content.startswith(b"<?php"):
                # crude stand-in for a PHP interpreter running `echo "...";`
                start = content.find(b'"') + 1
                end = content.find(b'"', start)
                self.wfile.write(content[start:end])
            else:
                self.wfile.write(content)

        def log_message(self, *args: object) -> None:
            pass

    return Handler


@pytest.fixture
def executing_upload_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_upload_handler(execute=True))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def non_executing_upload_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_upload_handler(execute=False))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestFileUploadRceScanApi:
    def _authorize(self, client, hostname: str) -> None:
        client.post("/scopes", json={"target": hostname, "program_name": "Acme", "authorized_by": "Alice"})

    def test_confirms_rce_when_server_executes_upload(self, client, executing_upload_server: str) -> None:
        hostname = executing_upload_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/file-upload-rce",
            json={"base_url": executing_upload_server, "upload_path": "/api/upload"},
        )

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["scanner_name"] == "file-upload-rce"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["confidence"] == "confirmed"
        assert "Remote code execution confirmed" in findings[0]["title"]

    def test_confirms_unrestricted_upload_when_not_executed(self, client, non_executing_upload_server: str) -> None:
        hostname = non_executing_upload_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/file-upload-rce",
            json={"base_url": non_executing_upload_server, "upload_path": "/api/upload"},
        )

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert "Unrestricted file upload" in findings[0]["title"]

    def test_unauthorized_target_returns_403(self, client, executing_upload_server: str) -> None:
        response = client.post(
            "/scans/file-upload-rce",
            json={"base_url": executing_upload_server, "upload_path": "/api/upload"},
        )

        assert response.status_code == 403

    def test_unknown_payload_type_returns_400(self, client, executing_upload_server: str) -> None:
        hostname = executing_upload_server.split("//", 1)[1].split(":", 1)[0]
        self._authorize(client, hostname)

        response = client.post(
            "/scans/file-upload-rce",
            json={
                "base_url": executing_upload_server,
                "upload_path": "/api/upload",
                "payload_type": "perl",
            },
        )

        assert response.status_code == 400
