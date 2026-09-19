import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

import sllurp.llrp as llrp
from sllurp.llrp import C1G2LockPayload, LLRPClient, LLRPReaderConfig
from sllurp.llrp_errors import ReaderConfigurationError
from sllurp.llrp_proto import LLRPError, LLRPROSpec, Param_struct


def test_c1g2_access_fields_are_separate():
    for name in ("C1G2Read", "C1G2Write", "C1G2BlockWrite"):
        fields = Param_struct[name]["fields"]
        assert "AccessPassword" in fields
        assert "MB" in fields
        assert "AccessPasswordMB" not in fields


def test_c1g2_block_write_uses_block_write_encoder():
    assert Param_struct["C1G2BlockWrite"]["encode"].__name__ == "encode_C1G2BlockWrite"


def test_rospec_tag_filter_default_is_not_mutable():
    assert inspect.signature(LLRPROSpec).parameters["tag_filter_mask"].default is None


@pytest.mark.parametrize("data_field", [-1, 5, 999])
def test_lock_payload_rejects_invalid_data_field(data_field):
    with pytest.raises(ValueError, match="DataField"):
        C1G2LockPayload(Privilege=0, DataField=data_field)


def test_set_state_none_raises_llrp_error():
    client = object.__new__(LLRPClient)
    with pytest.raises(LLRPError, match="state cannot be None"):
        client.setState(None)


def test_send_message_empty_raises_llrp_error(monkeypatch):
    client = object.__new__(LLRPClient)
    client.last_msg_id = 0
    client.transport_tx_write = lambda data: None
    monkeypatch.setattr(
        llrp,
        "LLRPMessage",
        lambda msgdict: SimpleNamespace(msgbytes=b""),
    )
    with pytest.raises(LLRPError, match="LLRPMessage is empty"):
        client.sendMessage({"KEEPALIVE_ACK": {}})


def _capabilities(min_tari=6250, max_tari=25000):
    return {
        "GeneralDeviceCapabilities": {"MaxNumberOfAntennaSupported": 1},
        "RegulatoryCapabilities": {
            "UHFBandCapabilities": {
                "TransmitPowerLevelTableEntry": [
                    {"Index": 1, "TransmitPowerValue": 3000}
                ],
                "UHFC1G2RFModeTable": {
                    "UHFC1G2RFModeTableEntry": [
                        {
                            "ModeIdentifier": 1,
                            "MinTari": min_tari,
                            "MaxTari": max_tari,
                        }
                    ]
                },
            }
        },
    }


@pytest.mark.parametrize("tari", [6250, 25000])
def test_tari_boundaries_are_valid(tari):
    config = LLRPReaderConfig(
        {
            "antennas": [1],
            "tx_power": 1,
            "mode_identifier": 1,
            "tari": tari,
        }
    )
    client = LLRPClient(config)
    client.parseCapabilities(_capabilities())
    assert client.reader_mode["ModeIdentifier"] == 1


@pytest.mark.parametrize("tari", [6249, 25001])
def test_out_of_range_tari_is_rejected(tari):
    config = LLRPReaderConfig(
        {
            "antennas": [1],
            "tx_power": 1,
            "mode_identifier": 1,
            "tari": tari,
        }
    )
    client = LLRPClient(config)
    with pytest.raises(ReaderConfigurationError, match="Requested Tari"):
        client.parseCapabilities(_capabilities())


def test_targeted_library_paths_have_no_bare_except_handlers():
    root = Path(llrp.__file__).resolve().parent
    paths = [
        root / "llrp.py",
        root / "lock.py",
        root / "verb" / "access.py",
        root / "verb" / "inventory.py",
        root / "verb" / "log.py",
        root / "verb" / "reset.py",
    ]
    offenders = []
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                offenders.extend(
                    f"{path.name}:{handler.lineno}"
                    for handler in node.handlers
                    if handler.type is None
                )
    assert offenders == []
