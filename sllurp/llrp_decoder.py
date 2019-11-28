from __future__ import unicode_literals
from struct import Struct, error as StructError

from .util import BITMASK
from .log import get_logger

logger = get_logger(__name__)


msg_header_struct = Struct('!HII')
msg_header_size = msg_header_struct.size
msg_header_unpack = msg_header_struct.unpack

msg_vendor_subtype_struct = Struct('!IB')
msg_vendor_subtype_size = msg_vendor_subtype_struct.size
msg_vendor_subtype_unpack = msg_vendor_subtype_struct.unpack


# TV param header: Type
tve_header_struct = Struct('!B')
tve_header_size = tve_header_struct.size
tve_header_unpack = tve_header_struct.unpack

# TLV param header: Type, Size
tlv_par_header_struct = Struct('!HH')
tlv_par_header_size = tlv_par_header_struct.size
tlv_par_header_unpack = tlv_par_header_struct.unpack

par_vendor_subtype_struct = Struct('!II')
par_vendor_subtype_size = par_vendor_subtype_struct.size
par_vendor_subtype_unpack = par_vendor_subtype_struct.unpack


## LEGACY to REMOVE
# TLV param header: Type, Size
nontve_header_struct = Struct('!HH')
nontve_header_size = nontve_header_struct.size
nontve_header_unpack = nontve_header_struct.unpack


struct_short = Struct('!h')
struct_ushort = Struct('!H')
struct_ulonglong = Struct('!Q')
struct_schar = Struct('!b')
struct_uint = Struct('!I')
struct_2ushort = Struct('!HH')
struct_96bits = Struct('!12s')

TVE_PARAM_TYPE_MAX = 127
TYPE_CUSTOM = 1023
VENDOR_ID_IMPINJ = 25882


TVE_PARAM_FORMATS = {
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
    13: ('EPC-96', struct_96bits),
    14: ('SpecIndex', struct_ushort),
    15: ('ClientRequestOpSpecResult', struct_ushort),
    16: ('AccessSpecID', struct_uint),
    17: ('OpSpecID', struct_ushort),
    18: ('C1G2SingulationDetails', struct_2ushort),
    19: ('C1G2XPCW1', struct_ushort),
    20: ('C1G2XPCW2', struct_ushort),
}


def msg_header_decode(data):
    msgtype, length, msgid = msg_header_unpack(data[:msg_header_size])
    hdr_len = msg_header_size
    version = (msgtype >> 10) & BITMASK(3)
    msgtype = msgtype & BITMASK(10)
    if msgtype == TYPE_CUSTOM:
        vendorid, subtype = msg_vendor_subtype_unpack(
            data[hdr_len:hdr_len + msg_vendor_subtype_size])
        hdr_len += msg_vendor_subtype_size
    else:
        vendorid = 0
        subtype = 0
    return msgtype, vendorid, subtype, version, hdr_len, length, msgid


def tlv_param_header_decode(data):
    # Decode for normal param header (non-tve)
    partype, length = tlv_par_header_unpack(data[:tlv_par_header_size])
    hdr_len = tlv_par_header_size
    partype = partype & BITMASK(10)
    if partype == TYPE_CUSTOM:
        vendorid, subtype = par_vendor_subtype_unpack(
            data[hdr_len:hdr_len + par_vendor_subtype_size])
        hdr_len += par_vendor_subtype_size
    else:
        vendorid = 0
        subtype = 0
    return partype, vendorid, subtype, hdr_len, length


def tve_param_header_decode(data):
    """Generic byte decoding function for TVE parameters.

    Given an array of bytes, tries to interpret a TVE parameter from the
    beginning of the array.  Returns the decoded data and the number of bytes
    it read."""

    # Most common case first
    # decode the TVE field's header (1 bit "reserved" + 7-bit type)
    tve_msgtype = tve_header_unpack(data[:tve_header_size])[0]

    if not tve_msgtype & 0b10000000:
        # Not a tve parameter
        return None, 0, 0

    tve_msgtype = tve_msgtype & 0x7f
    try:
        param_name, param_struct = TVE_PARAM_FORMATS[tve_msgtype]
        #logger.debugfast('found %s (type=%s)', param_name, tve_msgtype)
    except KeyError:
        return None, 0, 0

    # decode the body
    length = tve_header_size + param_struct.size

    return tve_msgtype, tve_header_size, length


def param_header_decode(data):
    vendorid = 0
    subtype = 0

    if len(data) < tve_header_size:
        # No parameter can be smaller than a tve_header
        return None, 0, 0, 0, 0

    # Check first for tve encoded parameters
    partype, hdr_len, full_length = tve_param_header_decode(data)
    if not partype:
        (partype,
         vendorid,
         subtype,
         hdr_len,
         full_length) = tlv_param_header_decode(data)

    return partype, vendorid, subtype, hdr_len, full_length


def tve_param_body_decode(data):
        try:
            param_name, param_struct = TVE_PARAM_FORMATS[tve_msgtype]
            #logger.debugfast('found %s (type=%s)', param_name, tve_msgtype)
        except KeyError:
            return None, 0

        # decode the body
        size = tve_header_size + param_struct.size
        param_value_offset = tve_header_size


