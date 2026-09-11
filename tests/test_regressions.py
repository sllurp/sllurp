import struct
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

import sllurp.cli as cli_module
from sllurp.llrp import (
    C1G2LockPayload,
    LLRPClient,
    LLRPReaderClient,
    LLRPReaderConfig,
    LLRP_SECURE_PORT,
    LLRPReaderState,
)
from sllurp.llrp_errors import ReaderConfigurationError
from sllurp.llrp_proto import decode_ImpinjFixedFrequencyList


def test_c1g2_lock_payload_rejects_out_of_range_data_field():
    with pytest.raises(ValueError, match="DataField"):
        C1G2LockPayload(Privilege=0, DataField=5)


def test_impinj_fixed_frequency_decoder_returns_channel_list():
    data = struct.pack("!HHHHH", 2, 0, 2, 4, 7)

    decoded, remaining = decode_ImpinjFixedFrequencyList(data)

    assert remaining == ""
    assert decoded["FixedFrequencyMode"] == 2
    assert decoded["ChannelList"] == [4, 7]


def test_reader_config_uses_canonical_channel_list_key():
    config = LLRPReaderConfig()

    assert config.frequencies["ChannelList"] == [1]
    assert "Channelist" not in config.frequencies


def test_multiple_fixed_channels_enable_impinj_extensions():
    config = LLRPReaderConfig(
        {
            "start_inventory": False,
            "reset_on_connect": False,
            "frequencies": {
                "HopTableId": 1,
                "ChannelList": [1, 2],
                "Automatic": False,
            },
        }
    )
    writes = []
    client = LLRPClient(config, transport_tx_write=writes.append)

    class SuccessfulConnectionNotification:
        msgdict = {}

        @staticmethod
        def getName():
            return "READER_EVENT_NOTIFICATION"

        @staticmethod
        def isSuccess():
            return True

    client.handleMessage(SuccessfulConnectionNotification())

    assert client.state == LLRPReaderState.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS
    assert writes


def test_set_tx_power_dbm_none_selects_max_power_index():
    config = LLRPReaderConfig({"start_inventory": False, "reset_on_connect": False})
    client = LLRPClient(config, transport_tx_write=lambda _: None)
    client.tx_power_table = [0, 10.0, 20.0]

    client.setTxPowerDbm()

    assert config.tx_power[1] == 2


def test_parse_capabilities_rejects_incompatible_tari():
    config = LLRPReaderConfig(
        {
            "start_inventory": False,
            "reset_on_connect": False,
            "mode_identifier": 1,
            "tari": 25,
        }
    )
    client = LLRPClient(config, transport_tx_write=lambda _: None)
    capabilities = {
        "GeneralDeviceCapabilities": {"MaxNumberOfAntennaSupported": 1},
        "RegulatoryCapabilities": {
            "UHFBandCapabilities": {
                "TransmitPowerLevelTableEntry": [
                    {"Index": 1, "TransmitPowerValue": 3000}
                ],
                "UHFC1G2RFModeTable": {
                    "UHFC1G2RFModeTableEntry": [
                        {"ModeIdentifier": 1, "MinTari": 10, "MaxTari": 20}
                    ]
                },
            }
        },
    }

    with pytest.raises(ReaderConfigurationError, match="Requested Tari"):
        client.parseCapabilities(capabilities)


def test_clear_unknown_state_callback_does_not_clear_message_callbacks():
    reader = LLRPReaderClient("localhost")
    callback = lambda *_: None
    reader.add_message_callback("KEEPALIVE", callback)

    reader.clear_state_callback(999999)

    assert callback in reader._llrp_message_callbacks["KEEPALIVE"]


def test_hard_disconnect_resets_partial_frame_state():
    reader = LLRPReaderClient("localhost")
    reader.partial_data = b"partial-frame"
    reader.expected_bytes = 100

    reader.hard_disconnect()

    assert reader.partial_data == b""
    assert reader.expected_bytes == 0


def test_log_cli_forwards_frequency_options(monkeypatch):
    captured = []
    monkeypatch.setattr(cli_module._log, "main", captured.append)

    result = CliRunner().invoke(
        cli_module.cli,
        ["log", "reader.example", "--frequencies", "3,4", "--hoptable-id", "2"],
    )

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0].frequencies == "3,4"
    assert captured[0].hoptable_id == 2

@pytest.mark.parametrize("tari", [10, 20])
def test_parse_capabilities_accepts_tari_boundaries(tari):
    config = LLRPReaderConfig(
        {
            "start_inventory": False,
            "reset_on_connect": False,
            "mode_identifier": 1,
            "tari": tari,
        }
    )
    client = LLRPClient(config, transport_tx_write=lambda _: None)
    capabilities = {
        "GeneralDeviceCapabilities": {"MaxNumberOfAntennaSupported": 1},
        "RegulatoryCapabilities": {
            "UHFBandCapabilities": {
                "TransmitPowerLevelTableEntry": [
                    {"Index": 1, "TransmitPowerValue": 3000}
                ],
                "UHFC1G2RFModeTable": {
                    "UHFC1G2RFModeTableEntry": [
                        {"ModeIdentifier": 1, "MinTari": 10, "MaxTari": 20}
                    ]
                },
            }
        },
    }

    client.parseCapabilities(capabilities)
    assert client.reader_mode["ModeIdentifier"] == 1


def test_reader_client_selects_secure_default_port_from_config():
    secure_config = LLRPReaderConfig(
        {"tls_enabled": True, "start_inventory": False, "reset_on_connect": False}
    )
    secure_reader = LLRPReaderClient("reader.example", config=secure_config)
    assert secure_reader.get_peername() == ("reader.example", LLRP_SECURE_PORT)

    explicit_reader = LLRPReaderClient(
        "reader.example", port=55085, config=secure_config
    )
    assert explicit_reader.get_peername() == ("reader.example", 55085)

    plain_reader = LLRPReaderClient("reader.example")
    assert plain_reader.get_peername() == ("reader.example", 5084)


def test_disconnect_callbacks_are_idempotent():
    reader = LLRPReaderClient("localhost")
    called = []
    reader.add_disconnected_callback(called.append)

    reader._on_disconnected()
    reader._on_disconnected()

    assert called == [reader]


def test_main_loop_unexpected_failure_cleans_up_and_notifies(monkeypatch):
    reader = LLRPReaderClient("localhost")
    reader._socket = Mock()
    called = []
    reader.add_disconnected_callback(called.append)

    def fail_select(*_args, **_kwargs):
        raise RuntimeError("select failed")

    monkeypatch.setattr("sllurp.llrp.select.select", fail_select)
    reader.main_loop()

    assert reader._socket is None
    assert called == [reader]
    reader._on_disconnected()
    assert called == [reader]
