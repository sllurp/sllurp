"""Small corrections for legacy LLRP protocol registry definitions.

These corrections address deterministic wire-format and decoder defects in the
large :mod:`sllurp.llrp_proto` registry without changing its public API.
"""

from __future__ import annotations

import struct

from . import llrp_proto as _p


def _encode_get_reader_config(msg, param_info):
    antenna_id = msg.get("AntennaID", 0)
    requested_data = msg["RequestedData"]
    gpi_port = msg.get("GPIPortNum", 0)
    gpo_port = msg.get("GPOPortNum", 0)
    packed = struct.pack("!HBHH", antenna_id, requested_data, gpi_port, gpo_port)
    return _p.encode_all_parameters(msg, param_info, packed)


def _encode_param(name, par):
    _p.logger.debugfast("Encode: %s", name)
    try:
        param_info = _p.Param_struct[name]
    except KeyError:
        _p.logger.warning(
            "Encoding error. No parameter found in Param_struct for: %s", name
        )
        return b""

    try:
        encode_func = param_info["encode"]
    except KeyError:
        _p.logger.warning("No encoder found for parameter: %s", name)
        return b""

    param_type = param_info["type"]
    sub_data = encode_func(par, param_info)

    if param_info.get("tv_encoded", False):
        if not 0 <= param_type <= 0x7F:
            raise _p.LLRPError(f"TV parameter type out of range: {param_type}")
        data = _p.tve_header_pack(0x80 | param_type)
    elif param_type == _p.TYPE_CUSTOM:
        if name != "CustomParameter":
            vendor_id = param_info["vendorid"]
            subtype = param_info["subtype"]
        else:
            vendor_id = par["VendorID"]
            subtype = par["Subtype"]
        data = _p.par_custom_header_pack(
            param_type,
            _p.par_custom_header_len + len(sub_data),
            vendor_id,
            subtype,
        )
    else:
        data = _p.par_header_pack(param_type, _p.par_header_len + len(sub_data))

    return data + sub_data


def _decode_aispec_event(data, name=None):
    if len(data) < _p.ubyte_uint_ushort_size:
        raise _p.LLRPError("Truncated AISpecEvent")

    event_type, rospec_id, spec_index = _p.ubyte_uint_ushort_unpack(
        data[: _p.ubyte_uint_ushort_size]
    )
    if event_type != 0:
        raise _p.LLRPError(f"Unsupported AISpecEvent EventType: {event_type}")

    par = {
        "ROSpecID": rospec_id,
        "SpecIndex": spec_index,
        "EventType": "End_of_AISpec",
    }
    trailing = data[_p.ubyte_uint_ushort_size :]
    if trailing:
        par, _ = _p.decode_all_parameters(trailing, name or "AISpecEvent", par)
    return par, ""


def _decode_nmea_sentence(data, field_name, parameter_name):
    if len(data) < _p.ushort_size:
        raise _p.LLRPError(f"Truncated {parameter_name}")
    byte_count = _p.ushort_unpack(data[: _p.ushort_size])[0]
    body = data[_p.ushort_size :]
    if len(body) < byte_count:
        raise _p.LLRPError(
            f"Truncated {parameter_name}: declared {byte_count} bytes, got {len(body)}"
        )

    par = {field_name: body[:byte_count]}
    trailing = body[byte_count:]
    if trailing:
        par, _ = _p.decode_all_parameters(trailing, parameter_name, par)
    return par, ""


def _decode_impinj_gga(data, name=None):
    return _decode_nmea_sentence(data, "GGASentence", name or "ImpinjGGASentence")


def _decode_impinj_rmc(data, name=None):
    return _decode_nmea_sentence(data, "RMCSentence", name or "ImpinjRMCSentence")


def apply():
    # LLRP 1.1 17.1.40: AntennaID, RequestedData, GPIPortNum, GPOPortNum.
    _p.Message_struct["GET_READER_CONFIG"]["encode"] = _encode_get_reader_config

    # TV parameters have a one-byte header: high bit set plus the 7-bit type.
    _p.encode_param = _encode_param

    # LLRP 1.1 parameter table: PeriodicTriggerValue=180, GPITriggerValue=181.
    _p.Param_struct["GPITriggerValue"]["type"] = 181
    _p.Param_Type2Name[(180, 0, 0)] = "PeriodicTriggerValue"
    _p.Param_Type2Name[(181, 0, 0)] = "GPITriggerValue"

    # AISpecEvent has a fixed seven-byte prefix followed by optional parameters.
    _p.Param_struct["AISpecEvent"]["decode"] = _decode_aispec_event

    # Preserve the entire length-prefixed NMEA sentence and trailing parameters.
    _p.Param_struct["ImpinjGGASentence"]["decode"] = _decode_impinj_gga
    _p.Param_struct["ImpinjRMCSentence"]["decode"] = _decode_impinj_rmc

    # This encoder was accidentally wired to Struct.unpack instead of Struct.pack.
    _p.Param_struct["RegulatoryCapabilities"]["encode"] = (
        _p.basic_auto_param_encode_generator(
            _p.ushort_ushort_pack,
            "CountryCode",
            "CommunicationsStandard",
        )
    )

    # The dedicated decoder consumes the leading Match byte before EPC parameters.
    _p.Param_struct["MotoFilterTagList"]["n_fields"] = ["EPC", "CustomParameter"]
    _p.Param_struct["MotoFilterTagList"]["decode"] = _p.decode_MotoFilterTagList


apply()
