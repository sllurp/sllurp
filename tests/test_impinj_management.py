import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sllurp.impinj_management import ImpinjRESTManager
from sllurp.reader_management import (
    UnsupportedReaderOperation,
    create_reader_manager,
)


class ImpinjHandler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        type(self).requests.append(
            (self.command, self.path, dict(self.headers), body)
        )

        expected = "Basic " + base64.b64encode(b"root:secret").decode()
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.end_headers()
            return

        if self.path == "/api/v1/system/diagnostics/debug-bundle/":
            return self._send(200, b"PK\x03\x04debug", "application/zip")

        if self.path in {
            "/api/v1/system/certificates/ca/certs",
            "/api/v1/system/certificates/tls/certs",
        }:
            assert self.command == "POST"
            content_type = self.headers.get("Content-Type", "")
            assert content_type.startswith("multipart/form-data; boundary=")
            assert b'name="certFile"' in body
            return self._json(200, {"certId": 7})

        payload = None
        if body:
            content_type = self.headers.get("Content-Type", "")
            if "json" in content_type.lower():
                payload = json.loads(body)

        return self._json(
            200,
            {
                "method": self.command,
                "path": self.path,
                "body": payload,
            },
        )

    def _json(self, status, value):
        return self._send(
            status,
            json.dumps(value).encode(),
            "application/json",
        )

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_POST = _handle
    do_DELETE = _handle


@pytest.fixture
def impinj_server():
    ImpinjHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImpinjHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def manager(base_url, model="R700"):
    return ImpinjRESTManager(
        base_url,
        model=model,
        username="root",
        password="secret",
    )


def test_status_uses_basic_auth_and_api_prefix(impinj_server):
    result = manager(impinj_server).get_status()
    assert result["method"] == "GET"
    assert result["path"] == "/api/v1/status"


def test_resource_helpers_accept_relative_and_prefixed_paths(impinj_server):
    client = manager(impinj_server)
    assert client.get("mqtt")["path"] == "/api/v1/mqtt"
    assert client.get("/api/v1/status")["path"] == "/api/v1/status"
    assert client.put("x", {"a": 1})["body"] == {"a": 1}
    assert client.patch("x", {"a": 2})["method"] == "PATCH"
    assert client.post("x", {"a": 3})["method"] == "POST"
    assert client.delete("x")["method"] == "DELETE"


def test_generic_settings_update_supports_documented_resources(impinj_server):
    client = manager(impinj_server)
    assert client.get_settings("custom/settings")["method"] == "GET"
    assert client.update_settings("custom/settings", {"x": 1})["body"] == {
        "x": 1
    }
    assert client.update_settings(
        "custom/settings", {"x": 2}, method="PATCH"
    )["method"] == "PATCH"
    assert client.update_settings(
        "custom/settings", {"x": 3}, method="POST"
    )["method"] == "POST"
    with pytest.raises(ValueError):
        client.update_settings("x", {}, method="DELETE")


def test_mqtt_and_power_wrappers(impinj_server):
    client = manager(impinj_server, model="Impinj R720")
    assert client.get_mqtt()["path"] == "/api/v1/mqtt"
    mqtt = client.set_mqtt({"brokerHostname": "broker", "tlsEnabled": True})
    assert mqtt["method"] == "PUT"
    assert mqtt["body"]["tlsEnabled"] is True

    assert client.get_power()["path"] == "/api/v1/system/power"
    power = client.set_power_source("PoEPlus")
    assert power["body"] == {"powerSource": "poeplus"}
    with pytest.raises(ValueError):
        client.set_power_source("   ")


def test_certificate_uploads_and_service_assignment(impinj_server):
    client = manager(impinj_server)
    assert client.install_ca_certificate(b"PEM", filename="root.pem") == {
        "certId": 7
    }
    assert client.install_tls_certificate(b"P12", filename="reader.p12") == {
        "certId": 7
    }

    assigned = client.set_tls_service_certificate("mqtt-client", 7)
    assert assigned["path"] == (
        "/api/v1/system/certificates/tls/services/mqtt-client"
    )
    assert assigned["body"] == {"certId": 7}
    with pytest.raises(ValueError):
        client.set_tls_service_certificate("", 1)


def test_debug_bundle_returns_binary(impinj_server):
    assert manager(impinj_server).get_debug_bundle() == b"PK\x03\x04debug"


def test_model_validation(impinj_server):
    with pytest.raises(ValueError):
        manager(impinj_server, model="R420")


def test_unified_factory_selects_r700_and_rejects_legacy(impinj_server):
    selected = create_reader_manager(
        "R700",
        impinj_server,
        username="root",
        password="secret",
    )
    assert isinstance(selected, ImpinjRESTManager)

    with pytest.raises(UnsupportedReaderOperation, match="RShell/SSH"):
        create_reader_manager(
            "Speedway R420",
            impinj_server,
            username="root",
            password="secret",
        )


def test_unified_factory_generic_escape_hatch(impinj_server):
    selected = create_reader_manager(
        "custom-reader",
        impinj_server,
        vendor="generic",
        username="root",
        password="secret",
    )
    result = selected.get_settings("/api/v1/status")
    assert result["path"] == "/api/v1/status"
