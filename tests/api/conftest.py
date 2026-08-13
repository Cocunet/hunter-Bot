import http.server
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from hunterbot.api.app import app
from hunterbot.api.dependencies import get_session
from hunterbot.storage.database import get_session_factory, init_db


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
    """A minimal local HTTP server for tests that need a real scan target."""
    server = http.server.HTTPServer(("127.0.0.1", 0), _PlainHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def client():
    """A TestClient wired to its own isolated in-memory database.

    Overrides the get_session dependency instead of touching the module-
    level singleton app's real (lru_cache'd) engine, so tests never share
    state with each other or with a real HUNTERBOT_DATABASE_URL.

    Uses StaticPool (one shared connection) rather than
    create_engine_from_url's default pooling: TestClient runs each sync
    endpoint in a worker thread, and plain sqlite:///:memory: ties its one
    connection to whichever thread first opens it -- every other thread
    would see a brand new, empty database. A real deployment never hits
    this, since it points at a file-backed database instead.
    """
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    init_db(engine)
    session_factory = get_session_factory(engine)

    def override_get_session():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
