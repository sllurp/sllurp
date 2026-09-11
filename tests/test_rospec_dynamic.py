import pytest
from hypothesis import given, settings, strategies as st

from sllurp.llrp_proto import LLRPError, LLRPROSpec, llrp_data2xml


PROPERTY_SETTINGS = settings(max_examples=150, deadline=None, derandomize=True)


def _antenna_configs(rospec):
    return rospec["AISpec"][0]["InventoryParameterSpec"][0]["AntennaConfiguration"]


@PROPERTY_SETTINGS
@given(
    antennas=st.lists(
        st.integers(min_value=1, max_value=8),
        min_size=1,
        max_size=8,
        unique=True,
    ),
    tx_power=st.integers(min_value=0, max_value=100),
    channel=st.integers(min_value=1, max_value=64),
    session=st.integers(min_value=0, max_value=3),
    population=st.integers(min_value=1, max_value=10_000),
)
def test_rospec_scalar_power_expands_across_dynamic_antenna_sets(
    antennas, tx_power, channel, session, population
):
    rospec = LLRPROSpec(
        None,
        1,
        antennas=antennas,
        tx_power=tx_power,
        session=session,
        tag_population=population,
        frequencies={"HopTableId": 1, "ChannelList": [channel], "Automatic": False},
    )

    configs = _antenna_configs(rospec)
    assert [entry["AntennaID"] for entry in configs] == antennas
    for entry in configs:
        assert entry["RFTransmitter"]["TransmitPower"] == tx_power
        assert entry["RFTransmitter"]["ChannelIndex"] == channel
        singulation = entry["C1G2InventoryCommand"][0]["C1G2SingulationControl"]
        assert singulation["Session"] == session
        assert singulation["TagPopulation"] == population


@PROPERTY_SETTINGS
@given(
    antennas=st.lists(
        st.integers(min_value=1, max_value=8),
        min_size=1,
        max_size=8,
        unique=True,
    ),
    powers=st.lists(
        st.integers(min_value=0, max_value=100),
        min_size=8,
        max_size=8,
    ),
)
def test_rospec_per_antenna_power_mapping_is_preserved(antennas, powers):
    power_map = {antenna: powers[antenna - 1] for antenna in antennas}

    rospec = LLRPROSpec(None, 1, antennas=antennas, tx_power=power_map)

    assert {
        entry["AntennaID"]: entry["RFTransmitter"]["TransmitPower"]
        for entry in _antenna_configs(rospec)
    } == power_map


@pytest.mark.parametrize("rospecid", [-100, -1, 0])
def test_rospec_rejects_non_positive_ids(rospecid):
    with pytest.raises(LLRPError, match="need >0"):
        LLRPROSpec(None, rospecid)


@pytest.mark.parametrize("priority", [-1, 8, 100])
def test_rospec_rejects_invalid_priorities(priority):
    with pytest.raises(LLRPError, match="priority"):
        LLRPROSpec(None, 1, priority=priority)


def test_rospec_rejects_unknown_state_and_bad_power_shapes():
    with pytest.raises(LLRPError, match="state"):
        LLRPROSpec(None, 1, state="NotAState")
    with pytest.raises(LLRPError, match="all antennas"):
        LLRPROSpec(None, 1, antennas=[1, 2], tx_power={1: 10})
    with pytest.raises(LLRPError, match="dictionary or integer"):
        LLRPROSpec(None, 1, tx_power="max")


@PROPERTY_SETTINGS
@given(
    duration=st.floats(
        min_value=0,
        max_value=30,
        allow_nan=False,
        allow_infinity=False,
    ),
    report_every=st.integers(min_value=1, max_value=1000),
    timeout=st.integers(min_value=0, max_value=60_000),
)
def test_rospec_duration_and_tag_observation_triggers(duration, report_every, timeout):
    rospec = LLRPROSpec(
        None,
        1,
        duration_sec=duration,
        report_every_n_tags=report_every,
        report_timeout_ms=timeout,
    )

    duration_ms = int(duration * 1000)
    assert rospec["ROBoundarySpec"]["ROSpecStopTrigger"] == {
        "ROSpecStopTriggerType": "Duration",
        "DurationTriggerValue": duration_ms,
    }
    trigger = rospec["AISpec"][0]["AISpecStopTrigger"]
    assert trigger["AISpecStopTriggerType"] == "Tag observation"
    assert trigger["DurationTriggerValue"] == duration_ms
    observation = trigger["TagObservationTrigger"]
    assert observation["NumberOfTags"] == report_every
    assert observation["Timeout"] == timeout


@pytest.mark.parametrize(
    "frequencies,expected_mode,expected_channels",
    [
        (
            {"HopTableId": 1, "ChannelList": [1], "Automatic": False},
            None,
            None,
        ),
        (
            {"HopTableId": 2, "ChannelList": [3, 5, 7], "Automatic": False},
            2,
            [3, 5, 7],
        ),
        (
            {"HopTableId": 1, "ChannelList": [1], "Automatic": True},
            1,
            [],
        ),
    ],
)
def test_rospec_fixed_frequency_modes(frequencies, expected_mode, expected_channels):
    rospec = LLRPROSpec(None, 1, antennas=[1, 2], frequencies=frequencies)

    for antenna in _antenna_configs(rospec):
        command = antenna["C1G2InventoryCommand"][0]
        if expected_mode is None:
            assert "ImpinjFixedFrequencyList" not in command
        else:
            fixed = command["ImpinjFixedFrequencyList"]
            assert fixed["FixedFrequencyMode"] == expected_mode
            assert fixed["ChannelList"] == expected_channels
        assert antenna["RFTransmitter"]["HopTableId"] == frequencies["HopTableId"]


@PROPERTY_SETTINGS
@given(
    channels=st.lists(
        st.integers(min_value=1, max_value=64),
        min_size=2,
        max_size=20,
        unique=True,
    )
)
def test_rospec_dynamic_multi_channel_lists_round_trip_into_fixed_frequency_extension(channels):
    rospec = LLRPROSpec(
        None,
        1,
        frequencies={"HopTableId": 1, "ChannelList": channels, "Automatic": False},
    )

    fixed = _antenna_configs(rospec)[0]["C1G2InventoryCommand"][0][
        "ImpinjFixedFrequencyList"
    ]
    assert fixed == {"FixedFrequencyMode": 2, "ChannelList": channels}


def test_rospec_rejects_empty_explicit_channel_list_cleanly():
    with pytest.raises((LLRPError, ValueError), match="[Cc]hannel"):
        LLRPROSpec(
            None,
            1,
            frequencies={"HopTableId": 1, "ChannelList": [], "Automatic": False},
        )


@PROPERTY_SETTINGS
@given(
    masks=st.lists(
        st.text(alphabet="0123456789abcdef", min_size=1, max_size=16),
        min_size=0,
        max_size=5,
    )
)
def test_rospec_tag_filters_are_deduplicated_and_encoded(masks):
    rospec = LLRPROSpec(None, 1, tag_filter_mask=masks)
    command = _antenna_configs(rospec)[0]["C1G2InventoryCommand"][0]

    if masks:
        filters = command["C1G2Filter"]
        assert {entry["C1G2TagInventoryMask"]["TagMask"] for entry in filters} == set(masks)
        assert all(entry["C1G2TagInventoryMask"]["MB"] == 1 for entry in filters)
        assert all(entry["C1G2TagInventoryMask"]["Pointer"] == 0x20 for entry in filters)
    else:
        assert "C1G2Filter" not in command


def test_rospec_reader_mode_tari_and_impinj_extensions_are_applied():
    mode = {"ModeIdentifier": 42, "MinTari": 10, "MaxTari": 30}
    report_selector = {
        "EnableRFPhaseAngle": True,
        "EnablePeakRSSI": False,
        "EnableRFDopplerFrequency": True,
    }

    rospec = LLRPROSpec(
        mode,
        1,
        tari=20,
        impinj_search_mode=2,
        impinj_tag_content_selector=report_selector,
    )

    command = _antenna_configs(rospec)[0]["C1G2InventoryCommand"][0]
    assert command["C1G2RFControl"] == {"ModeIndex": 42, "Tari": 20}
    assert command["ImpinjInventorySearchMode"] == {"InventorySearchMode": 2}
    selector = rospec["ROReportSpec"]["ImpinjTagReportContentSelector"]
    assert selector["ImpinjEnableRFPhaseAngle"]["RFPhaseAngleMode"] is True
    assert selector["ImpinjEnablePeakRSSI"]["PeakRSSIMode"] is False
    assert selector["ImpinjEnableRFDopplerFrequency"]["RFDopplerFrequencyMode"] is True


def test_rospec_tari_at_or_above_mode_max_is_not_overridden():
    mode = {"ModeIdentifier": 7, "MinTari": 10, "MaxTari": 20}
    rospec = LLRPROSpec(mode, 1, tari=20)

    control = _antenna_configs(rospec)[0]["C1G2InventoryCommand"][0]["C1G2RFControl"]
    assert control == {"ModeIndex": 7, "Tari": 0}


def test_tag_report_content_selector_overrides_defaults():
    rospec = LLRPROSpec(
        None,
        1,
        tag_content_selector={
            "EnableROSpecID": False,
            "EnablePeakRSSI": False,
            "EnableAntennaID": False,
        },
    )

    selector = rospec["ROReportSpec"]["TagReportContentSelector"]
    assert selector["EnableROSpecID"] is False
    assert selector["EnablePeakRSSI"] is False
    assert selector["EnableAntennaID"] is False
    assert selector["EnableTagSeenCount"] is True


def test_rospec_repr_and_xml_render_known_and_unknown_fields():
    rospec = LLRPROSpec(None, 1)
    rendered = repr(rospec)
    assert "<ROSpec>" in rendered
    assert "<ROSpecID>1</ROSpecID>" in rendered

    unknown = llrp_data2xml(
        {
            "UnknownThing": {
                "Name": "VendorBlob",
                "DecodeError": "UnknownParameter",
                "Type": 999,
                "Data": b"abc",
                "VendorID": 123,
                "Subtype": 456,
            }
        }
    )
    assert "UnknownParameter" in unknown
    assert "VendorBlob" in unknown
    assert "123" in unknown


def test_xml_renderer_handles_empty_input():
    assert llrp_data2xml({}) == ""
    assert llrp_data2xml(None) == ""
