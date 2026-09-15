import struct

import pytest

import sllurp.llrp_proto as proto


def test_get_reader_config_uses_specified_wire_order():
    info = proto.Message_struct["GET_READER_CONFIG"]
    encoded = info["encode"](
        {
            "AntennaID": 2,
            "RequestedData": 3,
            "GPIPortNum": 4,
            "GPOPortNum": 5,
        },
        info,
    )
    assert encoded == struct.pack("!HBHH", 2, 3, 4, 5)


def test_gpi_trigger_value_has_distinct_parameter_type():
    assert proto.Param_struct["PeriodicTriggerValue"]["type"] == 180
    assert proto.Param_struct["GPITriggerValue"]["type"] == 181
    assert proto.Param_Type2Name[(181, 0, 0)] == "GPITriggerValue"


def test_regulatory_capabilities_encoder_packs_fixed_fields():
    info = proto.Param_struct["RegulatoryCapabilities"]
    encoded = info["encode"](
        {"CountryCode": 840, "CommunicationsStandard": 1},
        info,
    )
    assert encoded == struct.pack("!HH", 840, 1)


def test_aispec_event_decodes_optional_tv_singulation_details():
    fixed = struct.pack("!BIH", 0, 7, 2)
    singulation = b"\x92" + struct.pack("!HH", 11, 13)
    decoded, remainder = proto.Param_struct["AISpecEvent"]["decode"](
        fixed + singulation,
        "AISpecEvent",
    )
    assert remainder == ""
    assert decoded["EventType"] == "End_of_AISpec"
    assert decoded["ROSpecID"] == 7
    assert decoded["SpecIndex"] == 2
    assert decoded["C1G2SingulationDetails"] == (11, 13)


@pytest.mark.parametrize(
    ("parameter", "field", "sentence"),
    [
        ("ImpinjGGASentence", "GGASentence", b"$GPGGA,synthetic*00"),
        ("ImpinjRMCSentence", "RMCSentence", b"$GPRMC,synthetic*00"),
    ],
)
def test_impinj_nmea_decoders_preserve_complete_sentence(parameter, field, sentence):
    body = struct.pack("!H", len(sentence)) + sentence
    decoded, remainder = proto.Param_struct[parameter]["decode"](body, parameter)
    assert remainder == ""
    assert decoded[field] == sentence


def test_motorola_filter_tag_list_uses_match_aware_decoder():
    info = proto.Param_struct["MotoFilterTagList"]
    assert info["decode"] is proto.decode_MotoFilterTagList
    decoded, remainder = info["decode"](b"\x00", "MotoFilterTagList")
    assert remainder == ""
    assert decoded == {"Match": "Inclusive"}


def test_tv_parameter_encoder_sets_tv_flag_and_type():
    name = "SyntheticTVRegressionParameter"
    proto.Param_struct[name] = {
        "type": 18,
        "tv_encoded": True,
        "encode": lambda par, info: struct.pack("!HH", 1, 2),
    }
    try:
        assert proto.encode_param(name, {}) == b"\x92\x00\x01\x00\x02"
    finally:
        del proto.Param_struct[name]
