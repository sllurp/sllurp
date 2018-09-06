from __future__ import unicode_literals
from struct import Struct, error as StructError

from .log import get_logger

logger = get_logger(__name__)

tve_header_struct = Struct('!B')
tve_header_len = tve_header_struct.size
tve_header_unpack = tve_header_struct.unpack

struct_short = Struct('!h')
struct_ushort = Struct('!H')
struct_ulonglong = Struct('!Q')
struct_schar = Struct('!b')
struct_uint = Struct('!I')
struct_2ushort = Struct('!HH')

tve_param_formats = {
    # param type: (param name, struct format)
    1: ('AntennaID', struct_ushort),
    2: ('FirstSeenTimestampUTC', struct_ulonglong),
    3: ('FirstSeenTimestampUptime', struct_ulonglong),
    4: ('LastSeenTimestampUTC', struct_ulonglong),
    5: ('LastSeenTimestampUptime', struct_ulonglong),
    6: ('PeakRSSI', struct_schar),
    7: ('ChannelIndex', struct_ushort),
    8: ('TagSeenCount', struct_ushort),
    9: ('ROSpecID', struct_uint),
    10: ('InventoryParameterSpecID', struct_ushort),
    11: ('C1G2CRC', struct_ushort),
    12: ('C1G2PC', struct_ushort),
    14: ('SpecIndex', struct_ushort),
    15: ('ClientRequestOpSpecResult', struct_ushort),
    16: ('AccessSpecID', struct_uint),
    17: ('OpSpecID', struct_ushort),
    18: ('C1G2SingulationDetails', struct_2ushort),
    19: ('C1G2XPCW1', struct_ushort),
    20: ('C1G2XPCW2', struct_ushort),
}

custom_param_formats = {
    25882: { # Impinj
        56: ('ImpinjPhase', struct_ushort),
        57: ('ImpinjPeakRSSI', struct_short),
        68: ('ImpinjRFDopplerFrequency', struct_short)
    }
}

# TLV param header: Type, Size
nontve_header_struct = Struct('!HH')
nontve_header_len = nontve_header_struct.size
nontve_header_unpack = nontve_header_struct.unpack

vendor_subtype_struct = Struct('!II')
vendor_subtype_len = vendor_subtype_struct.size
vendor_subtype_unpack = vendor_subtype_struct.unpack

def decode_tve_parameter(data):
    """Generic byte decoding function for TVE parameters.

    Given an array of bytes, tries to interpret a TVE parameter from the
    beginning of the array.  Returns the decoded data and the number of bytes
    it read."""

    # Most common case first
    # decode the TVE field's header (1 bit "reserved" + 7-bit type)
    tve_msgtype = tve_header_unpack(data[:tve_header_len])[0]
    if tve_msgtype & 0b10000000:
        tve_msgtype = tve_msgtype & 0x7f
        try:
            param_name, param_struct = tve_param_formats[tve_msgtype]
            #logger.debugfast('found %s (type=%s)', param_name, tve_msgtype)
        except KeyError:
            return None, 0

        # decode the body
        size = tve_header_len + param_struct.size
        param_value_offset = tve_header_len
    else:
        # not a TV-encoded param, maybe a custom parameter
        (nontve, size) = nontve_header_unpack(data[:nontve_header_len])
        # Check that it is a customparameter
        if nontve != 1023:
            return None, 0
        param_value_offset = nontve_header_len + vendor_subtype_len
        (vendor, subtype) = vendor_subtype_unpack(
            data[nontve_header_len:param_value_offset])
        try:
            param_name, param_struct = custom_param_formats[vendor][subtype]
        except KeyError:
            logger.error('Unknown tlv custom parameter {vendor: %d, '
                         'subtype:%d}', vendor, subtype)
            return None, 0

    try:
        unpacked = param_struct.unpack(
            data[param_value_offset:param_value_offset+param_struct.size])
        # return directly the value if only 1 element.
        if len(unpacked) == 1:
            unpacked = unpacked[0]
        return {param_name: unpacked}, size
    except StructError:
        return None, 0


def decode_parameter(data):
    """Decode a single parameter."""
