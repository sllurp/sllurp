import struct
import logging

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
    16: ('AccessSpecID', '!I')
}


def decode_tve_parameter(data):
    """Generic byte decoding function for TVE parameters.

    Given an array of bytes, tries to interpret a TVE parameter from the
    beginning of the array.  Returns the decoded data and the number of bytes
    it read."""

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
