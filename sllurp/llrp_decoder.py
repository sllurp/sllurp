import struct
import logging
from llrp_errors import *

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

def decode_tve_parameter (data):
    """Generic byte decoding function for TVE parameters.

    Given an array of bytes, tries to interpret a TVE parameter from the
    beginning of the array.  Returns the decoded data and the number of bytes it
    read."""
    #logging.debug('TVE parameter bytes: {}'.format(data.encode('hex')))

    # decode the TVE field's header (1 bit "reserved" + 7-bit type)
    (msgtype,) = struct.unpack(tve_header, data[:tve_header_len])
    msgtype = msgtype & 0x7f
    try:
        param_name, param_fmt = tve_param_formats[msgtype]
        #logging.debug('found {} (type={})'.format(param_name, msgtype))
    except KeyError as err:
        return None, 0

    # decode the body
    nbytes = struct.calcsize(param_fmt)
    end = tve_header_len + nbytes
    try:
        unpacked = struct.unpack(param_fmt, data[tve_header_len:end])
        return {param_name: unpacked}, end
    except struct.error:
        return None, 0

def decode_tve_parameters (data):
    """Decode a sequence of TVE-formatted parameters."""
    params = {}

    offset = 0
    while offset < len(data):
        try:
            par, nbytes = decode_tve_parameter(data[offset:])
            logging.debug(par)
            params.update(par)
            offset += nbytes
        except LLRPError as err:
            raise err

    return params

def decode_parameter (data):
    """Decode a single parameter."""
    pass
