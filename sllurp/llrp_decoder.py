from __future__ import unicode_literals
import struct
import logging
import math

logger = logging.getLogger(__name__)

tve_header = '!B'
tve_header_len = struct.calcsize(tve_header)

tve_param_formats = {
    # param type: (param name, struct format)
    1: ('AntennaID', '!H'),
    2: ('FirstSeenTimestampUTC', '!Q'),
    3: ('FirstSeenTimestampUptime', '!Q'),
    4: ('LastSeenTimestampUTC', '!Q'),
    5: ('LastSeenTimestampUptime', '!Q'),
    6: ('PeakRSSI', '!b'),
    7: ('ChannelIndex', '!H'),
    8: ('TagSeenCount', '!H'),
    9: ('ROSpecID', '!I'),
    10: ('InventoryParameterSpecID', '!H'),
    14: ('SpecIndex', '!H'),
    15: ('ClientRequestOpSpecResult', '!H'),
    16: ('AccessSpecID', '!I'),
    17: ('OpSpecID', '!H')
}

ext_param_formats = {
    56: ('ImpinjPhase', '!H'),
    57: ('ImpinjPeakRSSI', '!h'),
    68: ('RFDopplerFrequency', '!h')
}

nontve_header = '!H'
nontve_header_len = struct.calcsize(nontve_header)


def decode_tve_parameter(data):
    """Generic byte decoding function for TVE parameters.

    Given an array of bytes, tries to interpret a TVE parameter from the
    beginning of the array.  Returns the decoded data and the number of bytes
    it read."""

    (nontve,) = struct.unpack(nontve_header, data[:nontve_header_len])
    if nontve == 1023:  # customparameter
        (size,) = struct.unpack('!H',
                                data[nontve_header_len:nontve_header_len+2])
        (subtype,) = struct.unpack('!H', data[size-4:size-2])
        param_name, param_fmt = ext_param_formats[subtype]
        (unpacked,) = struct.unpack(param_fmt, data[size-2:size])
        return {param_name: unpacked}, size

    # decode the TVE field's header (1 bit "reserved" + 7-bit type)
    (msgtype,) = struct.unpack(tve_header, data[:tve_header_len])
    if not msgtype & 0b10000000:
        # not a TV-encoded param
        return None, 0
    msgtype = msgtype & 0x7f
    try:
        param_name, param_fmt = tve_param_formats[msgtype]
        logger.debug('found %s (type=%s)', param_name, msgtype)
    except KeyError:
        return None, 0

    # decode the body
    nbytes = struct.calcsize(param_fmt)
    end = tve_header_len + nbytes
    try:
        unpacked = struct.unpack(param_fmt, data[tve_header_len:end])
        return {param_name: unpacked}, end
    except struct.error:
        return None, 0


def decode_parameter(data):
    """Decode a single parameter."""
