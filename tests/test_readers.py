import pytest

from sllurp.readers import (
    LLRP_PORT,
    SECURE_LLRP_PORT,
    default_llrp_port,
    get_reader_profile,
    iter_reader_profiles,
    supports_secure_llrp,
)


@pytest.mark.parametrize(
    "model",
    [
        "FX7400",
        "FX7500",
        "FX9500",
        "FX9600",
        "ATR7000",
        "Speedway R220",
        "R420",
        "R700",
        "R720",
        "xArray",
        "xSpan",
        "IF2",
        "IF61",
    ],
)
def test_vendor_confirmed_secure_llrp_readers(model):
    assert supports_secure_llrp(model) is True


@pytest.mark.parametrize(
    "model",
    [
        "FXR90",
        "MC3090Z",
        "MC319Z",
        "MC9090",
        "MC9190-Z",
        "xPortal",
        "R1000",
        "IZAR",
        "Sargas",
        "Mercury6",
        "ALR-9900+",
    ],
)
def test_unverified_secure_llrp_is_not_misreported(model):
    assert supports_secure_llrp(model) is None


def test_model_alias_lookup_is_case_and_punctuation_insensitive():
    assert get_reader_profile("mc9190z").key == "zebra-mc9000-rfid"
    assert get_reader_profile("Mercury 6").key == "thingmagic-mercury6"
    assert get_reader_profile("impinj r720").key == "impinj-r700-series"


def test_unknown_reader_is_not_given_an_invented_profile():
    assert get_reader_profile("FutureReader-9000") is None
    assert supports_secure_llrp("FutureReader-9000") is None


def test_standard_llrp_ports():
    assert default_llrp_port() == LLRP_PORT == 5084
    assert default_llrp_port(secure=True) == SECURE_LLRP_PORT == 5085


def test_confirmed_secure_profiles_have_a_secure_port():
    secure_profiles = list(iter_reader_profiles(secure_only=True))
    assert secure_profiles
    assert all(profile.secure_llrp_port is not None for profile in secure_profiles)
