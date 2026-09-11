import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sllurp.reader_management import HTTPReaderManager, ReaderManagementError


class ReaderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/settings":
            self._write_json(200, {"mode": "inventory", "power": 30})
            return
        self._write_json(404, {"error": "missing"})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8")) if body else None
        self.server.last_method = "PATCH"
        self.server.last_path = self.path
        self.server.last_payload = payload
        self.server.last_authorization = self.headers.get("Authorization")
        self._write_json(200, {"updated": payload})


@pytest.fixture
def reader_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReaderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_get_and_update_settings_over_http(reader_server):
    host, port = reader_server.server_address
    manager = HTTPReaderManager(f"http://{host}:{port}")

    assert manager.get_settings("/settings") == {"mode": "inventory", "power": 30}
    result = manager.update_settings("/settings", {"power": 25})

    assert result == {"updated": {"power": 25}}
    assert reader_server.last_method == "PATCH"
    assert reader_server.last_path == "/settings"
    assert reader_server.last_payload == {"power": 25}


def test_basic_auth_header(reader_server):
    host, port = reader_server.server_address
    manager = HTTPReaderManager(
        f"http://{host}:{port}", username="admin", password="secret"
    )

    manager.update_settings("settings", {"enabled": True})

    expected = base64.b64encode(b"admin:secret").decode("ascii")
    assert reader_server.last_authorization == f"Basic {expected}"


def test_bearer_auth_header(reader_server):
    host, port = reader_server.server_address
    manager = HTTPReaderManager(
        f"http://{host}:{port}", bearer_token="token-value"
    )

    manager.update_settings("settings", {"enabled": True})

    assert reader_server.last_authorization == "Bearer token-value"


def test_http_errors_are_normalized(reader_server):
    host, port = reader_server.server_address
    manager = HTTPReaderManager(f"http://{host}:{port}")

    with pytest.raises(ReaderManagementError) as excinfo:
        manager.get_settings("/missing")

    assert excinfo.value.status == 404
    assert b"missing" in excinfo.value.body


def test_https_configuration_can_disable_verification():
    manager = HTTPReaderManager("https://reader.example", verify_tls=False)
    assert manager.base_url == "https://reader.example/"
    assert manager.verify_tls is False


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        HTTPReaderManager("reader.example")
    with pytest.raises(ValueError):
        HTTPReaderManager("http://reader.example", username="admin")
    with pytest.raises(ValueError):
        HTTPReaderManager(
            "http://reader.example",
            username="admin",
            password="secret",
            bearer_token="token",
        )


def test_rejects_unsupported_update_method():
    manager = HTTPReaderManager("http://reader.example")
    with pytest.raises(ValueError):
        manager.update_settings("settings", {"x": 1}, method="DELETE")
