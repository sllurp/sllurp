import ssl

import pytest
from click.testing import CliRunner

import sllurp.cli as cli_module
import sllurp.llrp as llrp_module
from sllurp.llrp import LLRPClient, LLRPReaderClient, LLRPReaderConfig


def _capabilities(max_antennas):
    return {
        "GeneralDeviceCapabilities": {
            "MaxNumberOfAntennaSupported": max_antennas,
        },
        "RegulatoryCapabilities": {
            "UHFBandCapabilities": {
                "TransmitPowerLevelTableEntry": [
                    {"Index": 1, "TransmitPowerValue": 3000},
                ],
                "UHFC1G2RFModeTable": {
                    "UHFC1G2RFModeTableEntry": [
                        {"ModeIdentifier": 1, "MinTari": 0, "MaxTari": 0},
                    ],
                },
            },
        },
    }


@pytest.mark.parametrize("max_antennas", [4, 8])
def test_all_antenna_wildcard_is_capability_driven(max_antennas):
    """FXR90 port-count variants must not require a hard-coded model profile."""
    config = LLRPReaderConfig(
        {
            "antennas": [0],
            "start_inventory": False,
            "reset_on_connect": False,
        }
    )
    client = LLRPClient(config, transport_tx_write=lambda _: None)

    client.parseCapabilities(_capabilities(max_antennas))

    assert client.max_ant == max_antennas
    assert config.antennas == [0]


def test_tls_config_defaults_are_backward_compatible():
    config = LLRPReaderConfig()

    assert config.tls_enabled is False
    assert config.tls_verify is True
    assert config.tls_ca_file is None
    assert config.tls_client_cert is None
    assert config.tls_client_key is None
    assert config.tls_server_hostname is None


def test_tls_context_uses_ca_and_client_certificate(monkeypatch):
    calls = {}

    class FakeContext:
        def load_cert_chain(self, certfile, keyfile=None):
            calls["cert_chain"] = (certfile, keyfile)

    fake_context = FakeContext()

    def fake_create_default_context(*, cafile=None):
        calls["cafile"] = cafile
        return fake_context

    monkeypatch.setattr(ssl, "create_default_context", fake_create_default_context)

    config = LLRPReaderConfig(
        {
            "tls_enabled": True,
            "tls_verify": True,
            "tls_ca_file": "/tmp/zebra-ca.pem",
            "tls_client_cert": "/tmp/client.pem",
            "tls_client_key": "/tmp/client.key",
        }
    )
    reader = LLRPReaderClient("fxr90.example", config=config)

    assert reader._create_tls_context() is fake_context
    assert calls["cafile"] == "/tmp/zebra-ca.pem"
    assert calls["cert_chain"] == ("/tmp/client.pem", "/tmp/client.key")


def test_tls_context_can_explicitly_disable_certificate_verification():
    config = LLRPReaderConfig(
        {
            "tls_enabled": True,
            "tls_verify": False,
            "start_inventory": False,
            "reset_on_connect": False,
        }
    )
    reader = LLRPReaderClient("192.0.2.10", config=config)

    context = reader._create_tls_context()

    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_tls_connection_wraps_connected_socket_with_server_hostname(monkeypatch):
    events = []

    class FakeSocket:
        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, address):
            events.append(("connect", address))

        def setsockopt(self, *args):
            events.append(("setsockopt", args))

        def close(self):
            events.append(("close",))

    raw_socket = FakeSocket()
    tls_socket = FakeSocket()

    class FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            events.append(("wrap", sock, server_hostname))
            return tls_socket

    monkeypatch.setattr(llrp_module, "socket", lambda *args: raw_socket)

    config = LLRPReaderConfig(
        {
            "tls_enabled": True,
            "tls_server_hostname": "reader.example",
            "start_inventory": False,
            "reset_on_connect": False,
        }
    )
    reader = LLRPReaderClient("192.0.2.10", port=5084, config=config)
    monkeypatch.setattr(reader, "_create_tls_context", lambda: FakeContext())

    reader._connect_socket()

    assert ("connect", ("192.0.2.10", 5084)) in events
    assert ("wrap", raw_socket, "reader.example") in events
    assert reader._socket is tls_socket


def test_tls_socket_pending_data_is_detected_without_select():
    class FakeTLSSocket:
        @staticmethod
        def pending():
            return 42

    reader = LLRPReaderClient("fxr90.example")
    reader._socket = FakeTLSSocket()

    assert reader._socket_has_pending_data() is True


def test_inventory_cli_forwards_tls_options(monkeypatch):
    captured = []
    monkeypatch.setattr(cli_module._inventory, "main", captured.append)

    result = CliRunner().invoke(
        cli_module.cli,
        [
            "inventory",
            "--tls",
            "--tls-no-verify",
            "--tls-ca-file",
            "/tmp/zebra-ca.pem",
            "--tls-client-cert",
            "/tmp/client.pem",
            "--tls-client-key",
            "/tmp/client.key",
            "--tls-server-hostname",
            "reader.example",
            "fxr90.example",
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    args = captured[0]
    assert args.tls_enabled is True
    assert args.tls_verify is False
    assert args.tls_ca_file == "/tmp/zebra-ca.pem"
    assert args.tls_client_cert == "/tmp/client.pem"
    assert args.tls_client_key == "/tmp/client.key"
    assert args.tls_server_hostname == "reader.example"


@pytest.mark.parametrize("command", ["inventory", "log", "access", "reset"])
def test_reader_commands_expose_tls_options(command):
    result = CliRunner().invoke(cli_module.cli, [command, "--help"])

    assert result.exit_code == 0
    assert "--tls" in result.output
    assert "--tls-no-verify" in result.output
    assert "--tls-ca-file" in result.output
    assert "--tls-client-cert" in result.output
    assert "--tls-client-key" in result.output
    assert "--tls-server-hostname" in result.output
