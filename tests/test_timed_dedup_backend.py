from types import SimpleNamespace

import pytest

from sllurp.llrp import (
    LLRPClient,
    LLRPReaderClient,
    LLRPReaderConfig,
    SOCKET_RECV_CHUNK,
    ZEBRA_TIMED_DEDUP_MAX_SECONDS,
)
from sllurp.llrp_errors import ReaderConfigurationError
from sllurp.llrp_proto import LLRPError


def config(**overrides):
    values = {
        "start_inventory": False,
        "reset_on_connect": False,
        "dedup_seconds": 60,
    }
    values.update(overrides)
    return LLRPReaderConfig(values)


def zebra_periodic_capability(enabled=True):
    flags = 0x10 if enabled else 0
    return {
        "SllurpDecodeError": [
            {
                "VendorID": 161,
                "Subtype": 110,
                "Data": b"\x00\x00\x00\x01" + bytes([flags]),
            }
        ]
    }


def test_auto_prefers_zebra_hardware_and_falls_back_to_memory():
    client = LLRPClient(config(), transport_tx_write=lambda data: None)
    assert client._select_dedup_backend(zebra_periodic_capability()) == "hardware"

    client = LLRPClient(config(), transport_tx_write=lambda data: None)
    assert client._select_dedup_backend({}) == "memory"

    client = LLRPClient(config(dedup_seconds=601), transport_tx_write=lambda data: None)
    assert client._select_dedup_backend(zebra_periodic_capability()) == "memory"


def test_hardware_backend_requires_capability_and_600_second_limit():
    with pytest.raises(LLRPError, match="at most 600"):
        config(dedup_seconds=601, dedup_backend="hardware")

    client = LLRPClient(
        config(dedup_backend="hardware"), transport_tx_write=lambda data: None
    )
    with pytest.raises(ReaderConfigurationError, match="hardware timed dedup"):
        client._select_dedup_backend({})

    assert ZEBRA_TIMED_DEDUP_MAX_SECONDS == 600


def test_hardware_rospec_uses_zebra_periodic_custom_trigger():
    client = LLRPClient(config(), transport_tx_write=lambda data: None)
    client.dedup_backend_active = "hardware"
    rospec = client.getROSpec()
    report = rospec["ROReportSpec"]

    assert report["ROReportTrigger"] == "None"
    assert report["N"] == 60
    assert report["CustomParameter"] == [
        {"VendorID": 161, "Subtype": 125, "Payload": b"\x01"}
    ]


def test_memory_backend_filters_before_user_callback():
    reader = LLRPReaderClient("reader", config=config(dedup_backend="memory"))
    reader.llrp.dedup_backend_active = "memory"
    calls = []
    reader.add_tag_report_callback(lambda _reader, tags: calls.append(tags))
    tag = {"EPC-96": b"0123456789ab", "TagSeenCount": 1}
    msg = SimpleNamespace(
        msgdict={"RO_ACCESS_REPORT": {"TagReportData": [tag]}}
    )

    reader._on_llrp_tag_report(None, msg)
    reader._on_llrp_tag_report(None, msg)

    assert calls == [[tag]]
    assert reader.dedup_backend_active == "memory"


def test_socket_burst_hardening_defaults():
    cfg = config()
    assert SOCKET_RECV_CHUNK >= 64 * 1024
    assert cfg.socket_receive_buffer_bytes >= 1024 * 1024


def test_dedup_config_validation():
    for value in (0, -1, 1.5, True):
        with pytest.raises(LLRPError, match="positive integer"):
            config(dedup_seconds=value)

    with pytest.raises(LLRPError, match="dedup_backend"):
        config(dedup_backend="invalid")
