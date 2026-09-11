from types import SimpleNamespace

import pytest

from sllurp.llrp import (
    C1G2BlockErase,
    C1G2BlockPermalock,
    C1G2BlockWrite,
    C1G2GetBlockPermalockStatus,
    C1G2Kill,
    C1G2Lock,
    C1G2LockPayload,
    C1G2Read,
    C1G2Recommission,
    C1G2TargetTag,
    C1G2Write,
    LLRP_MSG_ID_MAX,
    LLRPClient,
    LLRPMessage,
    LLRPReaderClient,
    LLRPReaderConfig,
    LLRPReaderState,
)
from sllurp.llrp_errors import ReaderConfigurationError
from sllurp.llrp_proto import LLRPError, Message_struct, msg_header_encode


def client_config(**overrides):
    values = {"start_inventory": False, "reset_on_connect": False}
    values.update(overrides)
    return LLRPReaderConfig(values)


def test_llrp_message_receive_decode_and_send_encode_paths():
    keepalive = msg_header_encode(
        Message_struct["KEEPALIVE"]["type"], 1, 0, 99
    )
    decoded = LLRPMessage(msgbytes=keepalive)
    encoded = LLRPMessage(
        msgdict={"ENABLE_EVENTS_AND_REPORTS": {"Ver": 1, "ID": 99}}
    )

    assert decoded.getName() == "KEEPALIVE"
    assert decoded.msgdict["KEEPALIVE"]["ID"] == 99
    assert decoded.msgdict["KEEPALIVE"]["Ver"] == 1
    assert "KEEPALIVE" in repr(decoded)
    assert encoded.getName() == "ENABLE_EVENTS_AND_REPORTS"
    assert encoded.msgbytes


def test_llrp_message_requires_input_and_rejects_unknown_types():
    with pytest.raises(LLRPError, match="Provide either"):
        LLRPMessage()

    with pytest.raises(LLRPError, match="Unknown message type"):
        LLRPMessage(msgdict={"NOT_A_REAL_MESSAGE": {}})


def _status_message(name, payload):
    message = object.__new__(LLRPMessage)
    message.msgname = name
    message.msgdict = {name: payload} if payload is not None else None
    message.msgbytes = b""
    return message


@pytest.mark.parametrize(
    "message,expected",
    [
        (_status_message("KEEPALIVE", None), False),
        (
            _status_message(
                "READER_EVENT_NOTIFICATION",
                {
                    "ReaderEventNotificationData": {
                        "ConnectionAttemptEvent": {"Status": "Success"}
                    }
                },
            ),
            True,
        ),
        (
            _status_message(
                "READER_EVENT_NOTIFICATION",
                {
                    "ReaderEventNotificationData": {
                        "AntennaEvent": {"EventType": "Connected"}
                    }
                },
            ),
            True,
        ),
        (
            _status_message(
                "GET_READER_CONFIG_RESPONSE",
                {"LLRPStatus": {"StatusCode": "Success"}},
            ),
            True,
        ),
        (
            _status_message(
                "GET_READER_CONFIG_RESPONSE",
                {"LLRPStatus": {"StatusCode": "M_Failure"}},
            ),
            False,
        ),
    ],
)
def test_llrp_message_success_detection(message, expected):
    assert message.isSuccess() is expected


@pytest.mark.parametrize(
    "factory,kwargs,expected",
    [
        (C1G2TargetTag, {"MB": 3, "Pointer": 32, "TagMask": "aa", "TagData": "bb"}, {"MB": 3, "Pointer": 32}),
        (C1G2Read, {"OpSpecID": 1, "AccessPassword": 2, "MB": 3, "WordPtr": 4, "WordCount": 5}, {"WordCount": 5}),
        (C1G2Write, {"OpSpecID": 1, "AccessPassword": 2, "MB": 3, "WordPtr": 4, "WriteDataWordCount": 2, "WriteData": b"abcd"}, {"WriteData": b"abcd"}),
        (C1G2Kill, {"OpSpecID": 9, "KillPassword": 1234}, {"KillPassword": 1234}),
        (C1G2Recommission, {"OpSpecID": 1, "KillPassword": 2, "Flag3SB": True, "Flag2SB": False, "FlagLSB": True}, {"Flag3SB": True, "FlagLSB": True}),
        (C1G2BlockErase, {"OpSpecID": 1, "AccessPassword": 2, "MB": 3, "WordPtr": 4, "WriteCount": 5}, {"WriteCount": 5}),
        (C1G2BlockWrite, {"OpSpecID": 1, "AccessPassword": 2, "MB": 3, "WordPtr": 4, "WriteDataWordCount": 2, "WriteData": b"abcd"}, {"WriteDataWordCount": 2}),
        (C1G2BlockPermalock, {"OpSpecID": 1, "AccessPassword": 2, "MB": 3, "BlockPtr": 4, "BlockMaskWordCount": 2, "BlockMask": b"xy"}, {"BlockMask": b"xy"}),
        (C1G2GetBlockPermalockStatus, {"OpSpecID": 1, "AccessPassword": 2, "MB": 3, "BlockPtr": 4, "BlockRange": 5}, {"BlockRange": 5}),
    ],
)
def test_c1g2_operation_objects_preserve_wire_fields(factory, kwargs, expected):
    value = factory(**kwargs)

    for name, expected_value in expected.items():
        assert getattr(value, name) == expected_value


def test_c1g2_lock_requires_payload_and_normalizes_scalar_to_list():
    with pytest.raises(ValueError, match="At least one"):
        C1G2Lock()

    payload = C1G2LockPayload(1, 2)
    scalar = C1G2Lock(AccessPassword=123, LockPayload=payload)
    multiple = C1G2Lock(LockPayload=[payload, C1G2LockPayload(2, 3)])

    assert scalar.LockPayload == [payload]
    assert len(multiple.LockPayload) == 2


def test_reader_states_round_trip_names_and_reject_unknown_state():
    states = list(LLRPReaderState.getStates())
    numbers = [number for _, number in states]

    assert len(numbers) == len(set(numbers))
    for name, number in states:
        assert LLRPReaderState.getStateName(number) == name

    with pytest.raises(LLRPError, match="unknown state"):
        LLRPReaderState.getStateName(999999)


def test_client_config_update_state_and_deferred_callbacks():
    transitions = []
    config = client_config()
    client = LLRPClient(config, transport_tx_write=lambda data: None, state_change_callback=transitions.append)
    new_config = client_config(antennas=[1, 2])

    client.update_config(new_config)
    client.setState(LLRPReaderState.STATE_CONNECTED)
    calls = []
    client._deferreds["TEST_RESPONSE"].append(lambda state, success: calls.append((state, success)))
    client.processDeferreds("TEST_RESPONSE", True)
    client.processDeferreds("NO_CALLBACKS", False)

    assert client.config is new_config
    assert transitions == [LLRPReaderState.STATE_CONNECTED]
    assert calls == [(LLRPReaderState.STATE_CONNECTED, True)]
    assert "TEST_RESPONSE" not in client._deferreds
    assert client.parseReaderConfig({}) is None


def test_parse_power_table_supports_empty_and_normal_capabilities():
    assert LLRPClient.parsePowerTable({}) == [0]
    assert LLRPClient.parsePowerTable(
        {
            "TransmitPowerLevelTableEntry": [
                {"Index": 1, "TransmitPowerValue": 1000},
                {"Index": 2, "TransmitPowerValue": 3150},
            ]
        }
    ) == [0, 10.0, 31.5]


def test_get_tx_power_handles_max_valid_and_invalid_indices():
    client = LLRPClient(client_config(antennas=[1, 2]), transport_tx_write=lambda data: None)
    client.tx_power_table = [0, 10.0, 20.0]

    assert client.get_tx_power({1: 0, 2: 1}) == {1: (2, 20.0), 2: (1, 10.0)}

    with pytest.raises(LLRPError, match="Invalid tx_power"):
        client.get_tx_power({1: 99})
    with pytest.raises(LLRPError, match="Invalid tx_power"):
        client.get_tx_power({1: -1})


def test_set_tx_power_dbm_uses_floor_mapping():
    config = client_config(antennas=[1], tx_power=0)
    client = LLRPClient(config, transport_tx_write=lambda data: None)
    client.tx_power_table = [0, 10.0, 20.0, 30.0]

    client.setTxPowerDbm({1: 25.0})

    assert config.tx_power == {1: 2}
    assert config.tx_power_dbm == {1: 25.0}


def test_pause_and_resume_state_machine_without_reader(monkeypatch):
    sent = []
    client = LLRPClient(client_config(), transport_tx_write=lambda data: None)
    client.rospec = {"ROSpecID": 7}
    monkeypatch.setattr(client, "getROSpec", lambda force_new=False: {"ROSpecID": 7})
    monkeypatch.setattr(client, "sendMessage", sent.append)

    with pytest.raises(ReaderConfigurationError, match="not yet"):
        client.pause(duration_seconds=1)

    assert client.pause() is None

    callback = client.pause(force=True)
    assert sent[-1] == {"DISABLE_ROSPEC": {"ROSpecID": 7}}
    assert client.state == LLRPReaderState.STATE_PAUSING
    callback(client.state, True)
    assert client.state == LLRPReaderState.STATE_PAUSED

    enabled = []

    def fake_enable(_, rospec, onCompletion=None):
        enabled.append(rospec)
        onCompletion(client.state, True)

    monkeypatch.setattr(client, "send_ENABLE_ROSPEC", fake_enable)
    client.resume()
    assert enabled == [{"ROSpecID": 7}]
    assert client.state == LLRPReaderState.STATE_INVENTORYING

    started = []
    monkeypatch.setattr(client, "startInventory", lambda *args, **kwargs: started.append((args, kwargs)))
    client.setState(LLRPReaderState.STATE_CONNECTED)
    client.resume()
    assert started


def test_send_message_assigns_and_rolls_over_message_ids():
    writes = []
    client = LLRPClient(client_config(), transport_tx_write=writes.append)
    client.last_msg_id = LLRP_MSG_ID_MAX
    payload = {"ENABLE_EVENTS_AND_REPORTS": {}}

    sent = client.sendMessage(payload)

    assert sent == [("ENABLE_EVENTS_AND_REPORTS", 1)]
    assert payload["ENABLE_EVENTS_AND_REPORTS"]["ID"] == 1
    assert writes and isinstance(writes[0], bytes)


def test_reader_config_validation_edges():
    with pytest.raises(LLRPError, match="tls_client_key requires"):
        client_config(tls_client_key="key.pem")
    with pytest.raises(LLRPError, match="Must specify tx_power"):
        client_config(antennas=[1, 2], tx_power={1: 1})
    with pytest.raises(LLRPError, match="tx_power must be dict or int"):
        client_config(tx_power="max")
    with pytest.raises(LLRPError, match="Must specify tx_power"):
        client_config(antennas=[1, 2], tx_power_dbm={1: 10.0})
    with pytest.raises(LLRPError, match="tx_power must be dict or float"):
        client_config(tx_power_dbm=10)

    config = client_config(antennas=[1, 2], tx_power_dbm=12.5)
    assert config.tx_power_dbm == {1: 12.5, 2: 12.5}


def test_reader_client_callback_registration_and_clearing():
    reader = LLRPReaderClient("reader-a", config=client_config())
    state_cb = lambda *args: None
    message_cb = lambda *args: None
    tag_cb = lambda *args: None
    event_cb = lambda *args: None
    disconnected_cb = lambda *args: None

    reader.add_state_callback(LLRPReaderState.STATE_CONNECTED, state_cb)
    reader.add_state_callback(LLRPReaderState.STATE_CONNECTED, state_cb)
    reader.remove_state_callback(LLRPReaderState.STATE_CONNECTED, state_cb)
    reader.add_state_callback(LLRPReaderState.STATE_CONNECTED, state_cb)
    reader.clear_state_callback(LLRPReaderState.STATE_CONNECTED)

    reader.add_message_callback("KEEPALIVE", message_cb)
    reader.add_message_callback("KEEPALIVE", message_cb)
    reader.remove_message_callback("KEEPALIVE", message_cb)
    reader.add_message_callback("KEEPALIVE", message_cb)
    reader.clear_message_callback("KEEPALIVE")
    reader.add_message_callback("KEEPALIVE", message_cb)
    reader.clear_message_callback()

    reader.add_tag_report_callback(tag_cb)
    reader.remove_tag_report_callback(tag_cb)
    reader.add_tag_report_callback(tag_cb)
    reader.clear_tag_report_callback(tag_cb)

    reader.add_event_callback(event_cb)
    reader.remove_event_callback(event_cb)
    reader.add_event_callback(event_cb)
    reader.clear_event_callback(event_cb)

    reader.add_disconnected_callback(disconnected_cb)
    reader.remove_disconnected_callback(disconnected_cb)
    reader.add_disconnected_callback(disconnected_cb)
    reader.clear_disconnected_callback(disconnected_cb)

    assert reader._llrp_state_callbacks[LLRPReaderState.STATE_CONNECTED] == []
    assert "KEEPALIVE" not in reader._llrp_message_callbacks
    assert len(reader._llrp_message_callbacks["RO_ACCESS_REPORT"]) == 1
    assert len(reader._llrp_message_callbacks["READER_EVENT_NOTIFICATION"]) == 1
    assert reader._tag_report_callbacks == []
    assert reader._event_notification_callbacks == []
    assert reader._disconnected_callbacks == []


def test_reader_client_dispatches_user_callbacks_and_survives_errors():
    reader = LLRPReaderClient("reader-a", config=client_config())
    calls = []

    def good(*args):
        calls.append(args)

    def bad(*args):
        raise RuntimeError("user callback failure")

    reader.add_disconnected_callback(bad)
    reader.add_disconnected_callback(good)
    reader.add_state_callback(LLRPReaderState.STATE_CONNECTED, bad)
    reader.add_state_callback(LLRPReaderState.STATE_CONNECTED, good)
    reader.add_message_callback("KEEPALIVE", bad)
    reader.add_message_callback("KEEPALIVE", good)
    reader.add_tag_report_callback(bad)
    reader.add_tag_report_callback(good)
    reader.add_event_callback(bad)
    reader.add_event_callback(good)

    keepalive = SimpleNamespace(getName=lambda: "KEEPALIVE")
    report = SimpleNamespace(msgdict={"RO_ACCESS_REPORT": {"TagReportData": [{"EPC": "x"}]}})
    event = SimpleNamespace(
        msgdict={"READER_EVENT_NOTIFICATION": {"ReaderEventNotificationData": {"x": 1}}}
    )

    reader._on_disconnected()
    reader._on_llrp_state_changed(LLRPReaderState.STATE_CONNECTED)
    reader._on_llrp_message_received(keepalive)
    reader._on_llrp_tag_report(None, report)
    reader._on_llrp_event_notification(None, event)

    assert len(calls) == 5


def test_start_access_spec_validates_types_and_clamps_negative_count(monkeypatch):
    reader = LLRPReaderClient("reader-a", config=client_config())
    calls = []
    monkeypatch.setattr(reader.llrp, "startAccess", lambda **kwargs: calls.append(kwargs))

    with pytest.raises(ValueError, match="op_spec"):
        reader.start_access_spec(object())
    with pytest.raises(ValueError, match="target_spec"):
        reader.start_access_spec(C1G2Read(), target_spec=object())

    target = C1G2TargetTag()
    op = C1G2Read()
    reader.start_access_spec(op, target_spec=target, stop_after_count=-5, access_spec_id=9)

    assert calls == [
        {
            "opSpec": op,
            "targetSpec": target,
            "stopAfterCount": 0,
            "accessSpecID": 9,
        }
    ]


def test_send_data_requires_socket_and_uses_sendall():
    reader = LLRPReaderClient("reader-a", config=client_config())
    with pytest.raises(ReaderConfigurationError, match="Not connected"):
        reader.send_data(b"x")

    sent = []
    reader._socket = SimpleNamespace(sendall=sent.append)
    reader.send_data(b"abc")
    assert sent == [b"abc"]
