from types import SimpleNamespace

import pytest

import sllurp.llrp as llrp_module
from sllurp.llrp import (
    C1G2BlockWrite,
    C1G2Lock,
    C1G2LockPayload,
    C1G2Read,
    C1G2TargetTag,
    C1G2Write,
    LLRPClient,
    LLRPReaderConfig,
    LLRPReaderState,
)
from sllurp.llrp_errors import ReaderConfigurationError
from sllurp.llrp_proto import LLRPError


def config(**overrides):
    values = {"start_inventory": False, "reset_on_connect": False}
    values.update(overrides)
    return LLRPReaderConfig(values)


class FakeMessage:
    def __init__(self, name, success=True, payload=None):
        self.name = name
        self.success = success
        if payload is None:
            if name == "READER_EVENT_NOTIFICATION":
                payload = {
                    "ReaderEventNotificationData": {
                        "ConnectionAttemptEvent": {"Status": "Success"}
                    }
                }
            else:
                payload = {"LLRPStatus": {"StatusCode": "Success", "ErrorDescription": ""}}
        self.msgdict = {name: payload}

    def getName(self):
        return self.name

    def isSuccess(self):
        return self.success


def test_keepalive_is_acknowledged_in_any_state(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    calls = []
    monkeypatch.setattr(client, "send_KEEPALIVE_ACK", lambda: calls.append("ack"))
    client.setState(LLRPReaderState.STATE_SENT_SET_CONFIG)

    client.handleMessage(FakeMessage("KEEPALIVE"))

    assert calls == ["ack"]


def test_non_inventory_tag_report_is_ignored(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    calls = []
    monkeypatch.setattr(client, "processDeferreds", lambda *args: calls.append(args))

    client.handleMessage(FakeMessage("RO_ACCESS_REPORT"))

    assert calls == []


def test_successful_connection_starts_capability_request(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    calls = []

    def send_caps(_, onCompletion):
        calls.append(onCompletion)

    monkeypatch.setattr(client, "send_GET_READER_CAPABILITIES", send_caps)

    client.handleMessage(FakeMessage("READER_EVENT_NOTIFICATION"))

    assert len(calls) == 1
    calls[0](client.state, True)
    assert client.state == LLRPReaderState.STATE_CONNECTED


def test_successful_connection_enables_impinj_extensions_when_requested(monkeypatch):
    client = LLRPClient(
        config(impinj_extended_configuration=True), transport_tx_write=lambda _: None
    )
    enable_callbacks = []
    cap_callbacks = []
    monkeypatch.setattr(
        client,
        "send_ENABLE_IMPINJ_EXTENSIONS",
        lambda onCompletion: enable_callbacks.append(onCompletion),
    )
    monkeypatch.setattr(
        client,
        "send_GET_READER_CAPABILITIES",
        lambda _, onCompletion: cap_callbacks.append(onCompletion),
    )

    client.handleMessage(FakeMessage("READER_EVENT_NOTIFICATION"))
    enable_callbacks[0](client.state, True)

    assert len(cap_callbacks) == 1


def test_failed_connection_does_not_advance(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    calls = []
    monkeypatch.setattr(client, "send_GET_READER_CAPABILITIES", lambda *a, **k: calls.append(1))
    payload = {
        "ReaderEventNotificationData": {
            "ConnectionAttemptEvent": {"Status": "Failed"}
        }
    }

    client.handleMessage(FakeMessage("READER_EVENT_NOTIFICATION", False, payload))

    assert calls == []
    assert client.state == LLRPReaderState.STATE_DISCONNECTED


def test_capabilities_response_parses_and_requests_config(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    client.setState(LLRPReaderState.STATE_SENT_GET_CAPABILITIES)
    parsed = []
    requested = []
    monkeypatch.setattr(client, "parseCapabilities", parsed.append)
    monkeypatch.setattr(
        client,
        "send_GET_READER_CONFIG",
        lambda onCompletion: requested.append(onCompletion),
    )
    payload = {"LLRPStatus": {"StatusCode": "Success"}, "marker": 1}

    client.handleMessage(FakeMessage("GET_READER_CAPABILITIES_RESPONSE", True, payload))

    assert parsed == [payload]
    assert len(requested) == 1
    requested[0](client.state, True)
    assert client.state == LLRPReaderState.STATE_SENT_GET_CONFIG


def test_get_config_response_parses_and_sends_configuration(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    client.setState(LLRPReaderState.STATE_SENT_GET_CONFIG)
    parsed = []
    events = []
    set_callbacks = []
    monkeypatch.setattr(client, "parseReaderConfig", parsed.append)
    monkeypatch.setattr(client, "send_ENABLE_EVENTS_AND_REPORTS", lambda: events.append(True))
    monkeypatch.setattr(
        client,
        "send_SET_READER_CONFIG",
        lambda onCompletion: set_callbacks.append(onCompletion),
    )
    payload = {"LLRPStatus": {"StatusCode": "Success"}, "marker": 2}

    client.handleMessage(FakeMessage("GET_READER_CONFIG_RESPONSE", True, payload))

    assert parsed == [payload]
    assert events == [True]
    assert len(set_callbacks) == 1
    set_callbacks[0](client.state, True)
    assert client.state == LLRPReaderState.STATE_SENT_SET_CONFIG


def test_set_config_response_starts_inventory_when_configured(monkeypatch):
    client = LLRPClient(
        config(start_inventory=True, reset_on_connect=False), transport_tx_write=lambda _: None
    )
    client.setState(LLRPReaderState.STATE_SENT_SET_CONFIG)
    starts = []
    monkeypatch.setattr(client, "startInventory", lambda: starts.append(True))

    client.handleMessage(FakeMessage("SET_READER_CONFIG_RESPONSE"))

    assert starts == [True]


def test_set_config_response_can_reset_before_inventory(monkeypatch):
    client = LLRPClient(
        config(start_inventory=True, reset_on_connect=True), transport_tx_write=lambda _: None
    )
    client.setState(LLRPReaderState.STATE_SENT_SET_CONFIG)
    stops = []
    starts = []

    def stop(onCompletion=None, disconnect=False):
        stops.append(disconnect)
        onCompletion(client.state, True)

    monkeypatch.setattr(client, "stopPolitely", stop)
    monkeypatch.setattr(client, "startInventory", lambda: starts.append(True))

    client.handleMessage(FakeMessage("SET_READER_CONFIG_RESPONSE"))

    assert stops == [False]
    assert starts == [True]
    assert client.state == LLRPReaderState.STATE_CONNECTED


@pytest.mark.parametrize(
    "state,message_name",
    [
        (LLRPReaderState.STATE_SENT_ADD_ROSPEC, "ADD_ROSPEC_RESPONSE"),
        (LLRPReaderState.STATE_SENT_ENABLE_ROSPEC, "ENABLE_ROSPEC_RESPONSE"),
        (LLRPReaderState.STATE_PAUSING, "DISABLE_ROSPEC_RESPONSE"),
        (LLRPReaderState.STATE_SENT_START_ROSPEC, "START_ROSPEC_RESPONSE"),
        (LLRPReaderState.STATE_INVENTORYING, "ADD_ACCESSSPEC_RESPONSE"),
        (LLRPReaderState.STATE_SENT_DELETE_ACCESSSPEC, "DELETE_ACCESSSPEC_RESPONSE"),
        (LLRPReaderState.STATE_SENT_DELETE_ROSPEC, "DELETE_ROSPEC_RESPONSE"),
    ],
)
def test_response_states_dispatch_deferreds(monkeypatch, state, message_name):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    client.setState(state)
    calls = []
    monkeypatch.setattr(
        client, "processDeferreds", lambda name, success: calls.append((name, success))
    )

    client.handleMessage(FakeMessage(message_name))

    assert calls == [(message_name, True)]


def test_inventory_state_accepts_reports_and_events(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    client.setState(LLRPReaderState.STATE_INVENTORYING)
    calls = []
    monkeypatch.setattr(
        client, "processDeferreds", lambda name, success: calls.append((name, success))
    )

    client.handleMessage(FakeMessage("RO_ACCESS_REPORT"))
    client.handleMessage(FakeMessage("READER_EVENT_NOTIFICATION"))

    # Reader events are globally handled before the inventory-state dispatch.
    assert calls == [("RO_ACCESS_REPORT", True)]


def test_unexpected_response_raises_in_strict_configuration_states():
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    client.setState(LLRPReaderState.STATE_SENT_GET_CAPABILITIES)
    with pytest.raises(ReaderConfigurationError):
        client.handleMessage(FakeMessage("SET_READER_CONFIG_RESPONSE"))


def test_send_helpers_set_state_and_register_callbacks(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    sent = []
    monkeypatch.setattr(client, "sendMessage", sent.append)
    callback = lambda *args: None
    rospec = {"ROSpecID": 7}

    client.send_ENABLE_IMPINJ_EXTENSIONS(callback)
    assert client.state == LLRPReaderState.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS
    assert callback in client._deferreds["IMPINJ_ENABLE_EXTENSIONS_RESPONSE"]

    client.send_GET_READER_CAPABILITIES(None, callback)
    assert client.state == LLRPReaderState.STATE_SENT_GET_CAPABILITIES
    assert callback in client._deferreds["GET_READER_CAPABILITIES_RESPONSE"]

    client.send_GET_READER_CONFIG(callback)
    assert client.state == LLRPReaderState.STATE_SENT_GET_CONFIG

    client.send_ADD_ROSPEC(rospec, callback)
    assert client.state == LLRPReaderState.STATE_SENT_ADD_ROSPEC

    client.send_ENABLE_ROSPEC(None, rospec, callback)
    assert client.state == LLRPReaderState.STATE_SENT_ENABLE_ROSPEC

    client.send_START_ROSPEC(None, rospec, callback)
    assert client.state == LLRPReaderState.STATE_SENT_START_ROSPEC

    assert len(sent) == 6


def test_set_reader_config_builds_optional_keepalive_gpi_and_impinj_fields(monkeypatch):
    cfg = config(
        keepalive_interval=1234,
        gpi_ports_config={2: True, 3: False},
        event_selector={"GPIEvent": True},
        impinj_event_selector={"AntennaAttemptEvent": True},
    )
    client = LLRPClient(cfg, transport_tx_write=lambda _: None)
    sent = []
    monkeypatch.setattr(client, "sendMessage", sent.append)
    callback = lambda *args: None

    client.send_SET_READER_CONFIG(callback)

    body = sent[0]["SET_READER_CONFIG"]
    assert body["KeepaliveSpec"]["TimeInterval"] == 1234
    assert body["ReaderEventNotificationSpec"]["EventNotificationState"]["GPIEvent"] is True
    assert body["GPIPortCurrentState"] == [
        {"GPIPortNum": 2, "GPIConfig": True},
        {"GPIPortNum": 3, "GPIConfig": False},
    ]
    assert body["ImpinjAntennaConfiguration"]["ImpinjAntennaEventConfiguration"] is True
    assert callback in client._deferreds["SET_READER_CONFIG_RESPONSE"]


def test_accessspec_send_helpers_register_only_requested_callbacks(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    sent = []
    monkeypatch.setattr(client, "sendMessage", sent.append)
    callback = lambda *args: None

    client.send_ADD_ACCESSSPEC({"AccessSpecID": 4}, callback)
    client.send_DISABLE_ACCESSSPEC(4, callback)
    client.send_ENABLE_ACCESSSPEC(None, 4, callback)
    client.send_DELETE_ACCESSSPEC(4)

    assert callback in client._deferreds["ADD_ACCESSSPEC_RESPONSE"]
    assert callback in client._deferreds["DISABLE_ACCESSSPEC_RESPONSE"]
    assert callback in client._deferreds["ENABLE_ACCESSSPEC_RESPONSE"]
    assert not client._deferreds["DELETE_ACCESSSPEC_RESPONSE"]
    assert len(sent) == 4


@pytest.mark.parametrize(
    "opspec,key",
    [
        (C1G2Read(OpSpecID=1, MB=3, WordCount=2), "C1G2Read"),
        (
            C1G2Write(
                OpSpecID=2, MB=3, WriteDataWordCount=1, WriteData=b"ab"
            ),
            "C1G2Write",
        ),
        (
            C1G2BlockWrite(
                OpSpecID=3, MB=3, WriteDataWordCount=1, WriteData=b"cd"
            ),
            "C1G2BlockWrite",
        ),
        (
            C1G2Lock(
                OpSpecID=4,
                LockPayload=[C1G2LockPayload(1, 2), C1G2LockPayload(2, 3)],
            ),
            "C1G2Lock",
        ),
    ],
)
def test_start_access_builds_every_supported_opspec(monkeypatch, opspec, key):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    captured = []
    monkeypatch.setattr(
        client,
        "send_ADD_ACCESSSPEC",
        lambda spec, onCompletion: captured.append((spec, onCompletion)),
    )
    target = C1G2TargetTag(MB=1, Pointer=32, TagMask="ff", TagData="aa")

    client.startAccess(opspec, targetSpec=target, stopAfterCount=5, accessSpecID=9)

    spec, callback = captured[0]
    assert spec["AccessSpecID"] == 9
    assert spec["AccessSpecStopTrigger"]["OperationCountValue"] == 5
    assert key in spec["AccessCommand"]["OpSpecParameter"][0]
    callback(client.state, True)


def test_start_access_rejects_too_many_targets_and_unknown_opspec(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    targets = [C1G2TargetTag(), C1G2TargetTag(), C1G2TargetTag()]
    with pytest.raises(ValueError, match="maximum of 2"):
        client.startAccess(C1G2Read(), targetSpec=targets)
    with pytest.raises(LLRPError, match="not yet supported"):
        client.startAccess(SimpleNamespace(), targetSpec=C1G2TargetTag())


def test_next_access_chains_disable_delete_and_start(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    disabled = []
    deleted = []
    started = []

    def disable(access_id, onCompletion=None):
        disabled.append(access_id)
        onCompletion(client.state, True)

    def delete(access_id, onCompletion=None):
        deleted.append(access_id)
        onCompletion(client.state, True)

    monkeypatch.setattr(client, "send_DISABLE_ACCESSSPEC", disable)
    monkeypatch.setattr(client, "send_DELETE_ACCESSSPEC", delete)
    monkeypatch.setattr(client, "startAccess", lambda **kwargs: started.append(kwargs))

    client.nextAccess(C1G2Read(), accessSpecID=3)

    assert disabled == [3]
    assert deleted == [3]
    assert started[0]["accessSpecID"] == 3


def test_start_inventory_callback_chain(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    rospec = {"ROSpecID": 5}
    monkeypatch.setattr(client, "getROSpec", lambda force_new=False: rospec)

    def add(spec, onCompletion=None):
        assert spec is rospec
        onCompletion(client.state, True)

    def enable(state, spec, onCompletion=None):
        assert spec is rospec
        onCompletion(client.state, True)

    monkeypatch.setattr(client, "send_ADD_ROSPEC", add)
    monkeypatch.setattr(client, "send_ENABLE_ROSPEC", enable)

    client.startInventory()

    assert client.state == LLRPReaderState.STATE_INVENTORYING
    assert client.startInventory() is None


def test_get_rospec_caches_and_regenerates(monkeypatch):
    constructed = []

    def fake_rospec(reader_mode, rospec_id, **kwargs):
        value = {"ROSpecID": rospec_id, "generation": len(constructed) + 1, **kwargs}
        constructed.append(value)
        return value

    monkeypatch.setattr(llrp_module, "LLRPROSpec", fake_rospec)
    client = LLRPClient(config(antennas=[1, 2]), transport_tx_write=lambda _: None)
    first = client.getROSpec()
    cached = client.getROSpec()
    regenerated = client.getROSpec(force_new=True)

    assert first is cached
    assert regenerated is not first
    assert len(constructed) == 2
    assert constructed[0]["antennas"] == [1, 2]


def test_stop_politely_chains_accessspec_and_rospec_deletion(monkeypatch):
    client = LLRPClient(config(), transport_tx_write=lambda _: None)
    sent = []
    monkeypatch.setattr(client, "sendMessage", sent.append)
    completed = []

    client.stopPolitely(onCompletion=lambda state, success: completed.append(success), disconnect=True)
    assert client.disconnecting is True
    assert client.state == LLRPReaderState.STATE_SENT_DELETE_ACCESSSPEC

    access_cb = client._deferreds["DELETE_ACCESSSPEC_RESPONSE"][0]
    access_cb(client.state, True)
    assert client.state == LLRPReaderState.STATE_SENT_DELETE_ROSPEC

    rospec_cb = client._deferreds["DELETE_ROSPEC_RESPONSE"][0]
    rospec_cb(client.state, True)

    assert completed == [True]
    assert sent[0] == {"DELETE_ACCESSSPEC": {"AccessSpecID": 0}}
    assert sent[1] == {"DELETE_ROSPEC": {"ROSpecID": 0}}
