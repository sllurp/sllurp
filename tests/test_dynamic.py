import struct

import pytest
from hypothesis import given, settings, strategies as st

from sllurp.llrp import C1G2LockPayload, LLRPReaderClient, LLRPReaderConfig
from sllurp.llrp_decoder import (
    TYPE_CUSTOM,
    TVE_PARAM_FORMATS,
    msg_header_custom_size,
    msg_header_decode,
    msg_header_encode,
    msg_header_size,
    param_header_decode,
    par_vendor_subtype_size,
    tlv_par_header_size,
    tve_param_header_decode,
)
from sllurp.llrp_proto import Message_struct, Param_struct, decode_param, hex_to_bit_array
from sllurp.util import BIT, BITMASK, find_closest, natural_keys, reverse_dict


PROPERTY_SETTINGS = settings(max_examples=200, deadline=None, derandomize=True)


@PROPERTY_SETTINGS
@given(
    msgtype=st.integers(min_value=0, max_value=TYPE_CUSTOM - 1),
    version=st.integers(min_value=0, max_value=7),
    body_length=st.integers(min_value=0, max_value=1_000_000),
    msgid=st.integers(min_value=0, max_value=0xFFFFFFFF),
)
def test_standard_message_header_round_trip(msgtype, version, body_length, msgid):
    encoded = msg_header_encode(msgtype, version, body_length, msgid)

    decoded = msg_header_decode(encoded)

    assert decoded == (
        msgtype,
        0,
        0,
        version,
        msg_header_size,
        msg_header_size + body_length,
        msgid,
    )


@PROPERTY_SETTINGS
@given(
    version=st.integers(min_value=0, max_value=7),
    body_length=st.integers(min_value=0, max_value=1_000_000),
    msgid=st.integers(min_value=0, max_value=0xFFFFFFFF),
    vendorid=st.integers(min_value=0, max_value=0xFFFFFFFF),
    subtype=st.integers(min_value=0, max_value=0xFF),
)
def test_custom_message_header_round_trip(
    version, body_length, msgid, vendorid, subtype
):
    encoded = msg_header_encode(
        TYPE_CUSTOM,
        version,
        body_length,
        msgid,
        vendorid=vendorid,
        subtype=subtype,
    )

    decoded = msg_header_decode(encoded)

    assert decoded == (
        TYPE_CUSTOM,
        vendorid,
        subtype,
        version,
        msg_header_custom_size,
        msg_header_custom_size + body_length,
        msgid,
    )


@PROPERTY_SETTINGS
@given(
    partype=st.integers(min_value=0, max_value=TYPE_CUSTOM - 1),
    length=st.integers(min_value=tlv_par_header_size, max_value=0xFFFF),
)
def test_standard_parameter_header_round_trip(partype, length):
    encoded = struct.pack("!HH", partype, length)

    decoded = param_header_decode(encoded)

    assert decoded == (partype, 0, 0, tlv_par_header_size, length)


@PROPERTY_SETTINGS
@given(
    length=st.integers(
        min_value=tlv_par_header_size + par_vendor_subtype_size,
        max_value=0xFFFF,
    ),
    vendorid=st.integers(min_value=0, max_value=0xFFFFFFFF),
    subtype=st.integers(min_value=0, max_value=0xFFFFFFFF),
)
def test_custom_parameter_header_round_trip(length, vendorid, subtype):
    encoded = struct.pack("!HHII", TYPE_CUSTOM, length, vendorid, subtype)

    decoded = param_header_decode(encoded)

    assert decoded == (
        TYPE_CUSTOM,
        vendorid,
        subtype,
        tlv_par_header_size + par_vendor_subtype_size,
        length,
    )


@pytest.mark.parametrize(
    "param_type,param_name,param_struct",
    [
        (param_type, param_name, param_struct)
        for param_type, (param_name, param_struct) in TVE_PARAM_FORMATS.items()
    ],
)
def test_every_registered_tve_parameter_decodes(
    param_type, param_name, param_struct
):
    wire = bytes([0x80 | param_type]) + bytes(param_struct.size)

    header = param_header_decode(wire)
    decoded_name, decoded_value, consumed = decode_param(wire)

    assert header == (param_type, 0, 0, 1, len(wire))
    assert decoded_name == param_name
    assert decoded_value is not None
    assert consumed == len(wire)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00",
        b"\x00\x01",
        b"\x00\x01\x00",
        struct.pack("!HH", TYPE_CUSTOM, 12) + b"\x00" * 7,
        b"\xff",
    ],
)
def test_truncated_parameter_headers_are_reported_as_incomplete(data):
    assert param_header_decode(data) == (None, 0, 0, 0, 0)


def test_empty_tve_header_is_incomplete_not_struct_error():
    assert tve_param_header_decode(b"") == (None, 0, 0)


@PROPERTY_SETTINGS
@given(
    value=st.text(
        alphabet="0123456789abcdefABCDEF",
        min_size=0,
        max_size=128,
    )
)
def test_hex_to_bit_array_matches_hex_semantics(value):
    bit_count, data = hex_to_bit_array(value)
    padded = value if len(value) % 2 == 0 else value + "0"

    assert bit_count == len(value) * 4
    assert data == bytes.fromhex(padded)


@PROPERTY_SETTINGS
@given(n=st.integers(min_value=0, max_value=128))
def test_bit_helpers_match_integer_arithmetic(n):
    assert BIT(n) == 2**n
    assert BITMASK(n) == (2**n) - 1


@PROPERTY_SETTINGS
@given(values=st.lists(st.integers(), min_size=0, max_size=50, unique=True))
def test_reverse_dict_is_an_involution_for_unique_values(values):
    original = {f"k{index}": value for index, value in enumerate(values)}

    assert reverse_dict(reverse_dict(original)) == original


@PROPERTY_SETTINGS
@given(
    numbers=st.lists(
        st.integers(min_value=0, max_value=100_000),
        min_size=0,
        max_size=50,
        unique=True,
    )
)
def test_natural_keys_orders_numeric_suffixes_numerically(numbers):
    names = [f"reader{number}" for number in reversed(numbers)]

    assert sorted(names, key=natural_keys) == [
        f"reader{number}" for number in sorted(numbers)
    ]


@PROPERTY_SETTINGS
@given(
    table=st.lists(
        st.integers(min_value=-100_000, max_value=100_000),
        min_size=1,
        max_size=50,
        unique=True,
    ).map(sorted),
    target=st.integers(min_value=-200_000, max_value=200_000),
)
def test_find_closest_returns_floor_with_endpoint_clamping(table, target):
    index, value = find_closest(table, target)

    eligible = [i for i, candidate in enumerate(table) if candidate <= target]
    expected_index = eligible[-1] if eligible else 0

    assert index == expected_index
    assert value == table[expected_index]


def test_find_closest_rejects_empty_tables():
    with pytest.raises(ValueError, match="must not be empty"):
        find_closest([], 10)


@PROPERTY_SETTINGS
@given(
    antennas=st.lists(
        st.integers(min_value=1, max_value=8),
        min_size=1,
        max_size=8,
        unique=True,
    ),
    power=st.integers(min_value=0, max_value=0xFFFF),
)
def test_reader_config_expands_scalar_tx_power_per_antenna(antennas, power):
    config = LLRPReaderConfig({"antennas": antennas, "tx_power": power})

    assert config.tx_power == {antenna: power for antenna in antennas}


@PROPERTY_SETTINGS
@given(
    privilege=st.integers(min_value=0, max_value=3),
    data_field=st.integers(min_value=0, max_value=4),
)
def test_lock_payload_accepts_every_valid_enum_combination(privilege, data_field):
    payload = C1G2LockPayload(privilege, data_field)

    assert payload.Privilege == privilege
    assert payload.DataField == data_field


@PROPERTY_SETTINGS
@given(
    privilege=st.one_of(
        st.integers(min_value=-1000, max_value=-1),
        st.integers(min_value=4, max_value=1000),
    ),
    data_field=st.integers(min_value=0, max_value=4),
)
def test_lock_payload_rejects_invalid_privilege(privilege, data_field):
    with pytest.raises(ValueError, match="Privilege"):
        C1G2LockPayload(privilege, data_field)


@PROPERTY_SETTINGS
@given(
    privilege=st.integers(min_value=0, max_value=3),
    data_field=st.one_of(
        st.integers(min_value=-1000, max_value=-1),
        st.integers(min_value=5, max_value=1000),
    ),
)
def test_lock_payload_rejects_invalid_data_field(privilege, data_field):
    with pytest.raises(ValueError, match="DataField"):
        C1G2LockPayload(privilege, data_field)


def _keepalive_frame(message_id):
    return msg_header_encode(
        Message_struct["KEEPALIVE"]["type"],
        1,
        0,
        message_id,
    )


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 5, 7, 9, 10, 64])
def test_reader_reassembles_fragmented_llrp_frames(chunk_size):
    config = LLRPReaderConfig({"start_inventory": False, "reset_on_connect": False})
    reader = LLRPReaderClient("localhost", config=config)
    seen = []
    reader._on_llrp_message_received = seen.append
    reader.llrp.handleMessage = lambda message: None
    frame = _keepalive_frame(1234)

    for offset in range(0, len(frame), chunk_size):
        reader.raw_data_received(frame[offset : offset + chunk_size])

    assert len(seen) == 1
    assert reader.expected_bytes == 0
    assert reader.partial_data == b""


def test_reader_decodes_multiple_frames_from_one_tcp_read():
    config = LLRPReaderConfig({"start_inventory": False, "reset_on_connect": False})
    reader = LLRPReaderClient("localhost", config=config)
    seen = []
    reader._on_llrp_message_received = seen.append
    reader.llrp.handleMessage = lambda message: None

    reader.raw_data_received(_keepalive_frame(1) + _keepalive_frame(2))

    assert len(seen) == 2


@pytest.mark.parametrize("registry", [Message_struct, Param_struct])
def test_protocol_registry_entries_have_callable_codecs(registry):
    assert registry
    for name, definition in registry.items():
        assert "type" in definition, name
        assert isinstance(definition["type"], int), name
        if "encode" in definition:
            assert callable(definition["encode"]), name
        if "decode" in definition:
            assert callable(definition["decode"]), name
