"""Known LLRP reader families and secure-LLRP capabilities.

The core sllurp protocol implementation is intentionally reader-neutral.  This
module records model/family information that is useful to applications without
hard-coding reader-specific behavior into the LLRP state machine.

``secure_llrp`` values mean:

* ``True``  - vendor documentation explicitly describes LLRP over TLS.
* ``False`` - vendor documentation explicitly says encrypted LLRP is unavailable.
* ``None``  - standard LLRP is documented, but secure LLRP has not been verified.

A value of ``None`` does not prevent callers from using sllurp's generic TLS
transport when a particular firmware build exposes a secure LLRP endpoint.
"""

from dataclasses import dataclass
from typing import Iterable, Optional


LLRP_PORT = 5084
SECURE_LLRP_PORT = 5085


@dataclass(frozen=True)
class ReaderProfile:
    """Protocol capabilities for one reader family."""

    key: str
    vendor: str
    family: str
    models: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    llrp_version: Optional[str] = None
    secure_llrp: Optional[bool] = None
    llrp_port: int = LLRP_PORT
    secure_llrp_port: Optional[int] = SECURE_LLRP_PORT
    notes: str = ""

    @property
    def all_names(self) -> tuple[str, ...]:
        return self.models + self.aliases


def _profile(
    key,
    vendor,
    family,
    models,
    *,
    aliases=(),
    llrp_version=None,
    secure_llrp=None,
    secure_llrp_port=SECURE_LLRP_PORT,
    notes="",
):
    return ReaderProfile(
        key=key,
        vendor=vendor,
        family=family,
        models=tuple(models),
        aliases=tuple(aliases),
        llrp_version=llrp_version,
        secure_llrp=secure_llrp,
        secure_llrp_port=secure_llrp_port,
        notes=notes,
    )


READER_PROFILES = (
    _profile(
        "zebra-fx7400",
        "Zebra/Motorola",
        "FX7400",
        ("FX7400",),
        secure_llrp=True,
        notes=(
            "Zebra Reader Management get/setLLRPConfig exposes IsSecure and "
            "ValidatePeerInSecureMode for FX7400. Secure port is configurable."
        ),
    ),
    _profile(
        "zebra-fx7500",
        "Zebra",
        "FX7500",
        ("FX7500",),
        secure_llrp=True,
        notes="Zebra documents Secure LLRP/TLS; encrypted LLRP uses port 5085 by default.",
    ),
    _profile(
        "zebra-fx9500",
        "Zebra/Motorola",
        "FX9500",
        ("FX9500",),
        secure_llrp=True,
        notes=(
            "Zebra Reader Management get/setLLRPConfig exposes IsSecure and "
            "ValidatePeerInSecureMode for FX9500. Secure port is configurable."
        ),
    ),
    _profile(
        "zebra-fx9600",
        "Zebra",
        "FX9600",
        ("FX9600",),
        secure_llrp=True,
        notes="Zebra documents Secure LLRP/TLS; encrypted LLRP uses port 5085 by default.",
    ),
    _profile(
        "zebra-atr7000",
        "Zebra",
        "ATR7000",
        ("ATR7000",),
        secure_llrp=True,
        notes="Zebra documents Secure LLRP/TLS and Reader Management secure-mode controls.",
    ),
    _profile(
        "zebra-fxr90",
        "Zebra",
        "FXR90",
        ("FXR90", "FXR90-4", "FXR90-8"),
        secure_llrp=None,
        notes=(
            "Standard LLRP is supported. sllurp's TLS transport can be used when the "
            "installed FXR90 firmware exposes LLRP over TLS; verify endpoint/port on-reader."
        ),
    ),
    _profile(
        "zebra-mc3000-rfid",
        "Zebra/Motorola",
        "MC3000 RFID",
        ("MC3090Z", "MC319Z"),
        secure_llrp=None,
        notes="Zebra documents LLRP custom extensions for the MC3000 RFID series.",
    ),
    _profile(
        "zebra-mc9000-rfid",
        "Zebra/Motorola",
        "MC9000 RFID",
        ("MC9090", "MC9190-Z", "MC919Z"),
        aliases=("MC9190Z",),
        secure_llrp=None,
        notes="Zebra documents LLRP custom extensions for the MC9000 RFID series.",
    ),
    _profile(
        "impinj-speedway",
        "Impinj",
        "Speedway",
        ("Speedway R220", "Speedway R420"),
        aliases=("R220", "R420"),
        secure_llrp=True,
        notes="Current Impinj Speedway documentation lists TLS 1.2 for Secure LLRP.",
    ),
    _profile(
        "impinj-r700-series",
        "Impinj",
        "R700 Series",
        ("R700", "R720"),
        aliases=("Impinj R700", "Impinj R720"),
        secure_llrp=True,
        notes="R700-series LLRPS uses port 5085; supported TLS versions depend on firmware.",
    ),
    _profile(
        "impinj-xportal",
        "Impinj",
        "xPortal",
        ("xPortal",),
        secure_llrp=None,
        notes="LLRP-compatible Speedway-platform gateway; verify secure-LLRP support by firmware.",
    ),
    _profile(
        "impinj-xarray",
        "Impinj",
        "xArray",
        ("xArray",),
        secure_llrp=True,
        notes="Impinj xArray datasheet lists TLS 1.2 for Secure LLRP.",
    ),
    _profile(
        "impinj-xspan",
        "Impinj",
        "xSpan",
        ("xSpan",),
        secure_llrp=True,
        notes="Impinj xSpan datasheet lists TLS 1.2 for Secure LLRP.",
    ),
    _profile(
        "impinj-speedway-r1000",
        "Impinj",
        "Speedway R1000",
        ("Speedway R1000",),
        aliases=("R1000",),
        secure_llrp=None,
        notes="Legacy sllurp-supported reader; secure LLRP not verified for this generation.",
    ),
    _profile(
        "honeywell-intermec-if2",
        "Honeywell/Intermec",
        "IF2",
        ("IF2",),
        secure_llrp=True,
        llrp_version="1.0.1",
        notes="IF2 exposes unsecure LLRP on 5084 and secure LLRP/TLS on 5085.",
    ),
    _profile(
        "honeywell-intermec-if61",
        "Honeywell/Intermec",
        "IF61",
        ("IF61",),
        secure_llrp=True,
        llrp_version="1.0.1",
        notes="Intermec LLRP implementation documents TLS on IANA port 5085 for IF61.",
    ),
    _profile(
        "thingmagic-izar-sargas",
        "JADAK ThingMagic",
        "Network Readers",
        ("IZAR", "Sargas"),
        aliases=("ThingMagic IZAR", "ThingMagic Sargas"),
        secure_llrp=None,
        notes="ThingMagic documents standard LLRP and states generic LLRP clients should work.",
    ),
    _profile(
        "thingmagic-mercury6",
        "JADAK ThingMagic",
        "Mercury6",
        ("Mercury6", "M6", "Astra-EX"),
        aliases=("Mercury 6",),
        secure_llrp=None,
        notes="ThingMagic documents standard LLRP support; secure LLRP not verified.",
    ),
    _profile(
        "alien-alr9900plus",
        "Alien Technology",
        "ALR-9900+",
        ("ALR-9900+", "ALR-9900+EMA"),
        secure_llrp=None,
        llrp_version="1.1",
        notes="Alien documents LLRP 1.1 support for the ALR-9900+ family.",
    ),
)


def _normalize(name: str) -> str:
    return "".join(ch for ch in name.casefold() if ch.isalnum())


_PROFILE_BY_NAME = {
    _normalize(name): profile
    for profile in READER_PROFILES
    for name in (profile.key, profile.family, *profile.all_names)
}


def get_reader_profile(name: str) -> Optional[ReaderProfile]:
    """Return a known reader profile for a model/family name, if present."""
    return _PROFILE_BY_NAME.get(_normalize(name))


def iter_reader_profiles(*, secure_only: bool = False) -> Iterable[ReaderProfile]:
    """Iterate known reader profiles, optionally only vendor-confirmed TLS readers."""
    for profile in READER_PROFILES:
        if secure_only and profile.secure_llrp is not True:
            continue
        yield profile


def supports_secure_llrp(name: str) -> Optional[bool]:
    """Return True/False/None for vendor-confirmed secure-LLRP capability."""
    profile = get_reader_profile(name)
    return None if profile is None else profile.secure_llrp


def default_llrp_port(*, secure: bool = False) -> int:
    """Return the IANA standard LLRP port for the requested transport."""
    return SECURE_LLRP_PORT if secure else LLRP_PORT


__all__ = [
    "LLRP_PORT",
    "SECURE_LLRP_PORT",
    "ReaderProfile",
    "READER_PROFILES",
    "get_reader_profile",
    "iter_reader_profiles",
    "supports_secure_llrp",
    "default_llrp_port",
]
