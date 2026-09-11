import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET

import pytest

from sllurp.reader_management import (
    ReaderManagementError,
    UnsupportedReaderOperation as SharedUnsupportedReaderOperation,
)
from sllurp.zebra_management import (
    UnsupportedReaderOperation,
    ZebraIoTConnectorManager,
    ZebraRMManager,
    zebra_reader_manager,
)


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


class ZebraManagementHandler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        type(self).requests.append(
            (self.command, self.path, dict(self.headers), body)
        )

        if self.path == "/cloud/localRestLogin":
            expected = "Basic " + base64.b64encode(b"admin:secret").decode()
            assert self.headers.get("Authorization") == expected
            return self._send(200, b"JWT Token: token-123", "text/plain")

        if self.path.startswith("/cloud/"):
            assert self.headers.get("Authorization") == "Bearer token-123"
            payload = {
                "method": self.command,
                "path": self.path,
                "body": json.loads(body) if body else None,
            }
            return self._send(
                200,
                json.dumps(payload).encode(),
                "application/json",
            )

        if self.path == "/control":
            root = ET.fromstring(body)
            device = next(
                element
                for element in root.iter()
                if local_name(element.tag) == "readerDevice"
            )
            operation = next(
                element
                for element in list(device)
                if local_name(element.tag) != "sessionID"
            )
            name = local_name(operation.tag)
            if name == "invalidXml":
                return self._send(200, b"<bad", "application/xml")
            if name == "fail":
                return self._send(
                    200,
                    b'<r:reply xmlns:r="urn:epcglobal:rm:xsd:1">'
                    b"<r:resultCode>9</r:resultCode>"
                    b"<r:resultDescription>nope</r:resultDescription>"
                    b"</r:reply>",
                    "application/xml",
                )
            if name == "doLogin":
                inner = "<m:sessionID>session-1</m:sessionID>"
            elif name == "getReaderProfileList":
                inner = (
                    "<m:value>a</m:value><m:value>b</m:value>"
                    "<m:activeProfileName>a</m:activeProfileName>"
                )
            else:
                inner = "<m:returnValue>ok</m:returnValue>"
            xml = (
                '<r:reply xmlns:r="urn:epcglobal:rm:xsd:1" '
                'xmlns:m="urn:motorfid:rm:xsd:1">'
                "<r:resultCode>0</r:resultCode>"
                f"<m:readerDevice><m:{name}>{inner}</m:{name}></m:readerDevice>"
                "</r:reply>"
            ).encode()
            return self._send(200, xml, "application/xml")

        return self._send(404, b"")

    def _send(self, status, body, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_PUT = _handle
    do_POST = _handle


@pytest.fixture
def management_server():
    ZebraManagementHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ZebraManagementHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_rm_login_session_and_repeated_values(management_server):
    manager = ZebraRMManager(
        management_server,
        username="admin",
        password="secret",
        model="FX7500",
        target_name="unit",
    )
    assert manager.login() == "session-1"
    profiles = manager.get_profiles()
    assert profiles["value"] == ["a", "b"]
    assert profiles["activeProfileName"] == "a"

    body = ZebraManagementHandler.requests[-1][3]
    root = ET.fromstring(body)
    assert any(
        local_name(element.tag) == "sessionID"
        and element.text == "session-1"
        for element in root.iter()
    )

    assert manager.logout() == {"returnValue": "ok"}
    assert manager.session_id is None


def test_rm_requires_login_and_normalizes_xml_errors(management_server):
    manager = ZebraRMManager(
        management_server,
        username="a",
        password="b",
        model="FX7500",
    )
    with pytest.raises(ReaderManagementError, match="login is required"):
        manager.command("x")

    manager.session_id = "s"
    with pytest.raises(ReaderManagementError, match="invalid RM XML"):
        manager.command("invalidXml")
    with pytest.raises(ReaderManagementError, match="resultCode 9: nope"):
        manager.command("fail")


def test_fx9500_capability_gates(management_server):
    manager = ZebraRMManager(
        management_server,
        username="a",
        password="b",
        model="FX9500",
    )
    manager.session_id = "s"

    with pytest.raises(UnsupportedReaderOperation):
        manager.set_network(Interface="ETH")
    with pytest.raises(UnsupportedReaderOperation):
        manager.set_dhcp()
    with pytest.raises(UnsupportedReaderOperation):
        manager.set_region("US", "FCC", [1])
    with pytest.raises(UnsupportedReaderOperation):
        manager.get_supported_regions()
    with pytest.raises(UnsupportedReaderOperation):
        manager.set_shell_status("ON")
    with pytest.raises(UnsupportedReaderOperation):
        manager.set_ftp_status("ON")
    with pytest.raises(UnsupportedReaderOperation):
        manager.discard_config()
    with pytest.raises(UnsupportedReaderOperation):
        manager.import_profile("p", "x")
    with pytest.raises(UnsupportedReaderOperation):
        manager.configure_firmware_update("ftp://host/image")

    assert manager.reboot() == {"returnValue": "ok"}


def test_rm_region_serializes_repeated_channels(management_server):
    manager = ZebraRMManager(
        management_server,
        username="a",
        password="b",
        model="FX7500",
    )
    manager.session_id = "s"
    manager.set_region("US", "FCC", [1, 2], lbt=True, hopping=True)

    root = ET.fromstring(ZebraManagementHandler.requests[-1][3])
    channels = [
        element.text
        for element in root.iter()
        if local_name(element.tag) == "channelUsed"
    ]
    assert channels == ["1", "2"]
    assert any(
        local_name(element.tag) == "doLBT" and element.text == "true"
        for element in root.iter()
    )


def test_rm_common_wrapper_parameters(monkeypatch):
    manager = ZebraRMManager(
        "http://reader",
        username="a",
        password="b",
        model="FX7500",
    )
    manager.session_id = "s"
    calls = []

    def fake_command(name, params=None, **kwargs):
        calls.append((name, params, kwargs))
        return name

    monkeypatch.setattr(manager, "command", fake_command)

    assert manager.get_info()["model"] == "getModel"
    manager.get_status()
    manager.get_network()
    manager.set_network(Interface="ETH")
    manager.set_dhcp()
    manager.get_supported_regions()
    manager.get_region_standards("US")
    manager.get_region()
    manager.get_llrp_config()
    manager.set_llrp_config(
        port=5084,
        secure=True,
        validate_peer=True,
        client=False,
    )
    manager.shutdown()
    manager.save_config()
    manager.discard_config()
    manager.has_config_changed()
    manager.get_config_changes_description()
    manager.set_name("n")
    manager.get_max_antennas()
    manager.get_read_points()
    manager.get_profiles()
    manager.activate_profile("p")
    manager.delete_profile("p")
    manager.import_profile("q", "data", set_active=True)
    manager.export_profile("q")
    manager.get_time()
    manager.set_time("2026-01-01T00:00:00Z")
    manager.get_time_zones()
    manager.set_time_zone(3)
    manager.get_shell_status()
    manager.set_shell_status("ON")
    manager.get_ftp_status()
    manager.set_ftp_status("OFF")
    manager.get_ext_antenna_mode()
    manager.set_ext_antenna_mode("MONOSTATIC")
    manager.configure_firmware_update(
        "ftp://host/fw", username="u", password="p"
    )
    manager.start_firmware_update()
    manager.get_debounce_time()
    manager.set_debounce_time(50)
    manager.change_password("u", "old", "new")

    names = [name for name, _, _ in calls]
    for expected in (
        "getManufacturer",
        "getModel",
        "getName",
        "getReaderVersionInfo",
        "getCPUUsage",
        "getRAMUsage",
        "getReaderDetails",
        "setLLRPConfig",
        "shutDown",
        "saveConfigChanges",
        "discardConfigChanges",
        "hasConfigChanged",
        "getAllReadPoints",
        "setProfileActive",
        "deleteProfile",
        "importProfileToReader",
        "exportProfileFromReader",
        "setTimeZone",
        "setShellStatus",
        "setFTPStatus",
        "setExtAntennaMode",
        "setFirmwareUpdateParams",
        "doFirmwareUpdate",
        "setDebounceTime",
        "doChangePassword",
    ):
        assert expected in names

    llrp = next(params for name, params, _ in calls if name == "setLLRPConfig")
    assert llrp["portNum"] == 5084
    assert llrp["IsSecure"] is True
    profile = next(
        params for name, params, _ in calls if name == "setProfileActive"
    )
    assert profile == {"ProfileName": "p"}
    read_points = next(
        params for name, params, _ in calls if name == "getAllReadPoints"
    )
    assert read_points == {
        "maintenanceMode": False,
        "refreshInterval": 0,
    }


def test_iot_login_then_bearer_and_wrappers(management_server):
    manager = ZebraIoTConnectorManager(
        management_server,
        model="FXR90-8",
        username="admin",
        password="secret",
    )
    assert manager.login() == "token-123"
    assert manager.get_info()["path"] == "/cloud/version"
    assert manager.get_status()["path"] == "/cloud/status"
    assert manager.get_capabilities()["path"] == "/cloud/readerCapabilities"
    assert manager.get_network("eth0")["body"] == {"interface": "eth0"}
    manager.set_network({"hostName": "x"})
    manager.get_hostname()
    manager.set_hostname("reader")
    manager.get_region()
    manager.get_supported_regions()
    manager.get_config()
    manager.set_config({"x": 1})
    manager.get_mode(verbose=True)
    manager.set_mode({"type": "INVENTORY"})
    manager.start(persist_state=True)
    manager.stop()
    manager.reboot()
    manager.get_gpi()
    manager.get_gpo()
    manager.set_gpo(2, False)
    manager.set_time_zone("UTC")
    manager.update_firmware({"url": "x"})

    assert any(
        request[1] == "/cloud/gpo" and request[0] == "PUT"
        for request in ZebraManagementHandler.requests
    )


def test_iot_token_and_validation(management_server):
    manager = ZebraIoTConnectorManager(
        management_server,
        model="FX9600",
        token="token-123",
    )
    assert manager.get_info()["path"] == "/cloud/version"

    with pytest.raises(ValueError):
        ZebraIoTConnectorManager(
            management_server,
            model="FX9500",
            token="x",
        )
    with pytest.raises(ValueError):
        ZebraIoTConnectorManager(
            management_server,
            model="FX9600",
            token="x",
            username="u",
            password="p",
        )
    with pytest.raises(ValueError):
        ZebraIoTConnectorManager(
            management_server,
            model="FX9600",
            username="u",
        )

    no_auth = ZebraIoTConnectorManager(management_server, model="FX9600")
    with pytest.raises(ReaderManagementError, match="required"):
        no_auth.login()


def test_factory_selects_protocol_by_model(management_server):
    assert isinstance(
        zebra_reader_manager(
            "fx9500",
            management_server,
            username="u",
            password="p",
        ),
        ZebraRMManager,
    )
    assert isinstance(
        zebra_reader_manager(
            "FXR90-4",
            management_server,
            token="token-123",
        ),
        ZebraIoTConnectorManager,
    )
    assert isinstance(
        zebra_reader_manager(
            "FX9600",
            management_server,
            api="iot",
            token="token-123",
        ),
        ZebraIoTConnectorManager,
    )
    with pytest.raises(ValueError):
        zebra_reader_manager("FX9600", management_server, api="bad")
    with pytest.raises(ValueError):
        ZebraRMManager(
            management_server,
            username="u",
            password="p",
            model="FXR90",
        )


def test_zebra_uses_shared_unsupported_operation_exception():
    assert UnsupportedReaderOperation is SharedUnsupportedReaderOperation
