#!/usr/bin/env python

# llrp_proto.py - LLRP protocol client support
#
# Copyright (C) 2009 Rodolfo Giometti <giometti@linux.it>
# Copyright (C) 2009 CAEN RFID <support.rfid@caen.it>
# Copyright (C) 2013, 2014 Benjamin Ransford <ransford@cs.washington.edu>
# Copyright (C) 2019-2020 Florent Viard <florent@sodria.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


from __future__ import unicode_literals
import logging
import struct
from collections import defaultdict
from binascii import hexlify, unhexlify

from .util import BIT, BITMASK, reverse_dict, iteritems
from .llrp_decoder import (msg_header_encode, msg_header_decode,
                           param_header_decode, par_vendor_subtype_size,
                           par_vendor_subtype_unpack, TVE_PARAM_FORMATS,
                           TVE_PARAM_TYPE_MAX, TYPE_CUSTOM, VENDOR_ID_IMPINJ,
                           VENDOR_ID_MOTOROLA)
from .llrp_errors import LLRPError
from .log import get_logger, is_general_debug_enabled

#
# Define exported symbols
#

__all__ = [
    # Class
    "LLRPError"
    "LLRPROSpec",
    "LLRPMessageDict",

    # Const
    "AirProtocol",
    "DEFAULT_CHANNEL_INDEX",
    "DEFAULT_HOPTABLE_INDEX",

    # Misc
    "Capability_Name2Type",
    "get_message_name_from_type",
    "llrp_data2xml",
    "Message_struct",
    "msg_header_encode",
    "msg_header_decode",
    "Param_struct",
]

logger = get_logger(__name__)


#
# LLRP defines & structs
#


VER_PROTO_V1 = 1

DEFAULT_CHANNEL_INDEX = 1
DEFAULT_HOPTABLE_INDEX = 1

DECODE_ERROR_PARNAME = "SllurpDecodeError"


msg_header = '!HII'
msg_header_len = struct.calcsize(msg_header)
msg_header_pack = struct.Struct(msg_header).pack
msg_header_unpack = struct.Struct(msg_header).unpack

par_header = '!HH'
par_header_len = struct.calcsize(par_header)
par_header_pack = struct.Struct(par_header).pack
par_header_unpack = struct.Struct(par_header).unpack
tve_header = '!B'
tve_header_len = struct.calcsize(tve_header)
tve_header_pack = struct.Struct(tve_header).pack
tve_header_unpack = struct.Struct(tve_header).unpack
par_custom_header = "!HHII"
par_custom_header_len = struct.calcsize(par_custom_header)
par_custom_header_pack = struct.Struct(par_custom_header).pack

# Common types unpacks
ubyte_size = struct.calcsize('!B')
short_size = struct.calcsize('!h')
ushort_size = struct.calcsize('!H')
uint_size = struct.calcsize('!I')
ulonglong_size = struct.calcsize('!Q')
ubyte_ubyte_size = struct.calcsize('!BB')
ubyte_ushort_size = struct.calcsize('!BH')
ubyte_uint_size = struct.calcsize('!BI')
ushort_ubyte_size = struct.calcsize('!HB')
ushort_ushort_size = struct.calcsize('!HH')
ushort_uint_size = struct.calcsize('!HI')
uint_ubyte_size = struct.calcsize('!IB')
uint_uint_size = struct.calcsize('!II')
ulonglong_ulonglong_size = struct.calcsize('!QQ')
ubyte_ubyte_ushort_size = struct.calcsize('!BBH')
ubyte_ushort_short_size = struct.calcsize('!BHh')
ubyte_ushort_ushort_size = struct.calcsize('!BHH')
ubyte_ushort_uint_size = struct.calcsize('!BHI')
ubyte_uint_ushort_size = struct.calcsize('!BIH')
ubyte_uint_uint_size = struct.calcsize('!BII')
ushort_ubyte_ubyte_size = struct.calcsize('!HBB')
ushort_ubyte_uint_size = struct.calcsize('!HBI')
ushort_ushort_ushort_size = struct.calcsize('!HHH')
ushort_ushort_uint_size = struct.calcsize('!HHI')
uint_ubyte_ubyte_size = struct.calcsize('!IBB')

ubyte_pack = struct.Struct('!B').pack
ushort_pack = struct.Struct('!H').pack
uint_pack = struct.Struct('!I').pack
ulonglong_pack = struct.Struct('!Q').pack
byte_ubyte_pack = struct.Struct('!bB').pack
ubyte_ushort_pack = struct.Struct('!BH').pack
ubyte_uint_pack = struct.Struct('!BI').pack
ushort_ubyte_pack = struct.Struct('!HB').pack
ushort_ushort_pack = struct.Struct('!HH').pack
ushort_uint_pack = struct.Struct('!HI').pack
uint_uint_pack = struct.Struct('!II').pack
ulonglong_ulonglong_pack = struct.Struct('!QQ').pack
ubyte_ushort_ushort_pack = struct.Struct('!BHH').pack
ubyte_ushort_uint_pack = struct.Struct('!BHI').pack
ubyte_uint_ushort_pack = struct.Struct('!BIH').pack
ubyte_uint_uint_pack = struct.Struct('!BII').pack
ushort_ubyte_uint_pack = struct.Struct('!HBI').pack
ushort_ushort_ushort_pack = struct.Struct('!HHH').pack
uint_ubyte_ubyte_pack = struct.Struct('!IBB').pack
ubyte_ushort_ushort_ushort_pack = struct.Struct('!BHHH').pack

ubyte_unpack = struct.Struct('!B').unpack
short_unpack = struct.Struct('!h').unpack
ushort_unpack = struct.Struct('!H').unpack
uint_unpack = struct.Struct('!I').unpack
ulonglong_unpack = struct.Struct('!Q').unpack
ubyte_ubyte_unpack = struct.Struct('!BB').unpack
ubyte_ushort_unpack = struct.Struct('!BH').unpack
ubyte_uint_unpack = struct.Struct('!BI').unpack
ushort_ubyte_unpack = struct.Struct('!HB').unpack
ushort_ushort_unpack = struct.Struct('!HH').unpack
ushort_uint_unpack = struct.Struct('!HI').unpack
uint_ubyte_unpack = struct.Struct('!IB').unpack
uint_uint_unpack = struct.Struct('!II').unpack
ulonglong_ulonglong_unpack = struct.Struct('!QQ').unpack
ubyte_ubyte_ushort_unpack = struct.Struct('!BBH').unpack
ubyte_ushort_short_unpack = struct.Struct('!BHh').unpack
ubyte_ushort_ushort_unpack = struct.Struct('!BHH').unpack
ubyte_ushort_uint_unpack = struct.Struct('!BHI').unpack
ubyte_uint_ushort_unpack = struct.Struct('!BIH').unpack
ubyte_uint_uint_unpack = struct.Struct('!BII').unpack
ushort_ubyte_ubyte_unpack = struct.Struct('!HBB').unpack
ushort_ubyte_uint_unpack = struct.Struct('!HBI').unpack
ushort_ushort_ushort_unpack = struct.Struct('!HHH').unpack
ushort_ushort_uint_unpack = struct.Struct('!HHI').unpack
uint_ubyte_ubyte_unpack = struct.Struct('!IBB').unpack

AirProtocol = {
    'UnspecifiedAirProtocol': 0,
    'EPCGlobalClass1Gen2': 1,
}

# 9.1.1 Capabilities requests
Capability_Name2Type = {
    'All':                  0,
    'General Device Capabilities':      1,
    'LLRP Capabilities':            2,
    'Regulatory Capabilities':      3,
    'Air Protocol LLRP Capabilities':   4
}

Capability_Type2Name = reverse_dict(Capability_Name2Type)

# 10.2.1 ROSpec states
ROSpecState_Name2Type = {
    'Disabled':             0,
    'Inactive':             1,
    'Active':               2
}

ROSpecState_Type2Name = reverse_dict(ROSpecState_Name2Type)

# 10.2.1.1.1 ROSpec Start trigger
ROSpecStartTriggerType_Name2Type = {
    'Null':                 0,
    'Immediate':            1,
    'Periodic':             2,
    'GPI':                  3
}

ROSpecStartTriggerType_Type2Name = reverse_dict(ROSpecStartTriggerType_Name2Type)

# 10.2.1.1.2 (LLRP v1.1 section 10.2.1.1.2)
ROSpecStopTriggerType_Name2Type = {
    'Null':                 0,
    'Duration':             1,
    'GPI with timeout':     2,
}

ROSpecStopTriggerType_Type2Name = reverse_dict(ROSpecStopTriggerType_Name2Type)

# 10.2.2.1 (LLRP v1.1 section 11.2.2.1)
AISpecStopTriggerType_Name2Type = {
    'Null':                 0,
    'Duration':             1,
    'GPI with timeout':     2,
    'Tag observation':      3
}

AISpecStopTriggerType_Type2Name = reverse_dict(AISpecStopTriggerType_Name2Type)

# 10.2.2.1.1 (LLRP v1.1 section 11.2.2.1.1)
TagObservationTrigger_Name2Type = {
    'UponNTags': 0,
    'UponSilenceMs': 1,
    'UponNAttempts': 2,
    'UponNUniqueTags': 3,
    'UponUniqueSilenceMs': 4,
}

TagObservationTrigger_Type2Name = reverse_dict(TagObservationTrigger_Name2Type)

AccessReportTrigger_Name2Type = {
    'Upon_ROReport': 0,
    'Upon_End_Of_AccessSpec': 1
}

AccessReportTrigger_Type2Name = reverse_dict(AccessReportTrigger_Name2Type)

# 12.2.4 (LLRP v1.1 section 13.2.4)
KeepaliveTriggerType_Name2Type = {
    'Null': 0,
    'Immediate': 1,
}

KeepaliveTriggerType_Type2Name = reverse_dict(KeepaliveTriggerType_Name2Type)

# 13.2.6.11 Connection attemp events
ConnEvent_Name2Type = {
    'Success':                          0,
    'Failed (a Reader initiated connection already exists)':    1,
    'Failed (a Client initiated connection already exists)':    2,
    'Failed (any reason other than a connection already exists)':   3,
    'Another connection attempted':                 4,
}

ConnEvent_Type2Name = reverse_dict(ConnEvent_Name2Type)

# http://www.gs1.org/gsmp/kc/epcglobal/llrp/llrp_1_0_1-standard-20070813.pdf
# Section 14.1.1 Error messages
Error_Name2Type = {
    'Success': 0,
    'ParameterError': 100,
    'FieldError': 101,
    'UnexpectedParameter': 102,
    'MissingParameter': 103,
    'DuplicateParameter': 104,
    'OverflowParameter': 105,
    'OverflowField': 106,
    'UnknownParameter': 107,
    'UnknownField': 108,
    'UnsupportedMessage': 109,
    'UnsupportedVersion': 110,
    'UnsupportedParameter': 111,
    'P_ParameterError': 200,
    'P_FieldError': 201,
    'P_UnexpectedParameter': 202,
    'P_MissingParameter': 203,
    'P_DuplicateParameter': 204,
    'P_OverflowParameter': 205,
    'P_OverflowField': 206,
    'P_UnknownParameter': 207,
    'P_UnknownField': 208,
    'P_UnsupportedParameter': 209,
    'A_Invalid': 300,
    'A_OutOfRange': 301,
    'DeviceError': 401,
}

Error_Type2Name = reverse_dict(Error_Name2Type)

# 13.2.5.1 EventNotificationState events list
EventState_Name2Value = {
    'HoppingEvent': 0,
    'GPIEvent': 1,
    'ROSpecEvent': 2,
    'ReportBufferFillWarning': 3,
    'ReaderExceptionEvent': 4,
    'RFSurveyEvent': 5,
    'AISpecEvent': 6,
    'AISpecEventWithSingulation': 7,
    'AntennaEvent': 8,
    # New event only available in llrp v.2:
    'SpecLoopEvent': 9,
}

EventState_Value2Name = reverse_dict(EventState_Name2Value)

# 13.2.1 ROReportTrigger
ROReportTrigger_Name2Value = {
    'None': 0,
    'Upon_N_Tags_Or_End_Of_AISpec': 1,
    'Upon_N_Tags_Or_End_Of_ROSpec': 2,
    'Upon_N_Seconds': 3,
    'Upon_N_Seconds_Or_End_Of_ROSpec': 4,
    'Upon_N_Milliseconds': 5,
    'Upon_N_Milliseconds_Or_End_Of_ROSpec': 6,
}

ROReportTrigger_Value2Name = reverse_dict(ROReportTrigger_Name2Value)

# v1.0:16.2.1.1.2.1 UHFC1G2RFModeTable, to be filled in by capabilities parser
ModeIndex_Name2Type = defaultdict(int)

# v1.0:16.2.1.1.2.1
Modulation_Name2Type = {
    'FM0': 0,
    'M2': 1,
    'M4': 2,
    'M8': 3,
    'WISP5pre': 0,
    'WISP5': 0,
}

#
# LLRP Messages and parameters
#

Message_struct = {}
Param_struct = {}

# Load Param_struct with existing tv encoded parameters and an automatic
# decoder..
# Note: This needs to be done early, so that the decoder of a specific param
# can still be overriden later.
for p_type, p_format in iteritems(TVE_PARAM_FORMATS):
    p_name = p_format[0]
    p_unpack_func = p_format[1].unpack
    if not p_name:
        logging.warning('Name is missing for TVE Param %d', p_type)
        continue
    def local_decode(data, name=None, p_unpack_func=p_unpack_func):
        return p_unpack_func(data)[0], ''
    p_struct = {
        'type': p_type,
        'tv_encoded': True,
        'fields': [],
        # TODO: encode tv parameters
        #'encode': local_encode,
        #'decode': lambda data: (p_unpack_func(data)[0], '')
        'decode': local_decode
    }
    Param_struct[p_name] = p_struct

# Global helpers


def get_message_name_from_type(msgtype, vendorid=0, subtype=0):
    name = Message_Type2Name[(msgtype, vendorid, subtype)]
    return name


def basic_param_encode_generator(pack_func=None, *args):
    """Generate a encode function for simple parameters"""
    if pack_func is None:
        def generated_func(par_dict, param_info):
            return b''
        return generated_func

    if not args:
        raise LLRPError('Error basic_param_encode_generator used with a pack '
                        'function but no argument.')

    def generated_func(par_dict, param_info):
        return pack_func(*[par_dict[k] for k in args])

    return generated_func


def basic_auto_param_encode_generator(pack_func=None, *args):
    """Generate a encode function for simple parameters with auto encode

    Generate a function that encode first a set of fixed parameters,
    using the pack_func function and then, try to automatically
    encode remaining dynamic parameter objects.
    """
    if not args:
        raise LLRPError('Error basic_auto_param_encode_generator used with a '
                        'pack function but no argument.')

    def generated_func(par_dict, param_info):
        packed = pack_func(*[par_dict[k] for k in args])

        data = encode_all_parameters(par_dict, param_info, packed)
        return data

    return generated_func


def basic_param_decode_generator(unpack_func, *args):
    """Generate a decode function for simple parameters"""
    if args:
        def generated_func(data, name=None):
            unpacked = unpack_func(data)
            return dict(zip(args, unpacked)), ''

    else:
        def generated_func(data, name=None):
            unpacked = unpack_func(data)
            return unpacked[0], ''
    return generated_func


def basic_auto_param_decode_generator(unpack_func, unpack_size, *args):
    """Generate a decode function for simple parameters with auto decode

    Generate a function that decode first a set of fixed parameters of size
    unpack_size, using the unpack_func function and then, try to automatically
    decode remaining dynamic parameter objects.
    """
    if not args:
        raise LLRPError('Error basic_auto_param_decode_generator used with a '
                        'unpack function but no argument.')

    def generated_func(data, name=None):
        unpacked = unpack_func(data[:unpack_size])
        par = dict(zip(args, unpacked))
        data = data[unpack_size:]
        if data:
            par, _ = decode_all_parameters(data, name, par)
        return par, ''

    return generated_func


def decode_param(data):
    """Decode any parameter to a byte sequence.

    :param data: byte sequence representing an LLRP parameter.
    :returns dict, bytes: where dict is {'Type': <decoded type>, 'Data':
        <decoded data>} and bytes is the remaining bytes trailing the bytes we
        could decode.
    """
    # logger.debugfast('decode_param data: %r', data)
    ret = None
    decoder_error = 'UnknownParameter'

    (partype,
     vendorid,
     subtype,
     hdr_len,
     full_length) = param_header_decode(data)

    if not partype:
        # No parameter can be smaller than a tve_header
        return None, None, data

    pardata = data[hdr_len:full_length]

    param_name = Param_Type2Name.get((partype, vendorid, subtype))
    if param_name:
        try:
            ret, _ = Param_struct[param_name]['decode'](pardata, param_name)
        except KeyError:
            logger.debugfast('"decode" func is missing for parameter %s',
                             param_name)
            decoder_error = 'DecodeFunctionMissing'
    else:
        logger.debugfast('"unknown parameter" can\'t be decoded (%s, %s, %s)',
                         partype, vendorid, subtype)

    if ret is None:
        # Default "unknown param" ret as a fallback
        ret = {
            'Name': '',
            'Type': partype,
            'DecodeError': decoder_error,
            'Data': pardata,
        }
        if vendorid and subtype:
            ret['VendorID'] = vendorid
            ret['Subtype'] = subtype
        if param_name:
            ret['Name'] = param_name
            # After saving the name, void it to avoid the returned value to
            # be considered as a correctly decoded parameter
            param_name = None

    return param_name, ret, full_length


def decode_all_parameters(data, name=None, par_dict=None, n_fields=None):
    if par_dict is None:
        par_dict = {}
    if name:
        logger.debugfast('decode_%s', name)
        if n_fields is None:
            n_fields = Param_struct[name]['n_fields']

    if n_fields is None:
        n_fields = []

    datalen = len(data)
    start_pos = 0
    while start_pos < datalen:
        subname, ret, sublength = decode_param(data[start_pos:])
        if not subname:
            if ret is None:
                raise LLRPError('Error decoding param. Invalid byte stream.')
            par_dict.setdefault(DECODE_ERROR_PARNAME, []).append(ret)
        elif subname not in n_fields:
            #prev_val = par_dict.get(subname)
            #if prev_val is not None:
            #    logger.warning('Multiple values were not expected for %s/%s',
            #                   name, subname)
            par_dict[subname] = ret
        else:
            par_dict.setdefault(subname, []).append(ret)

        if sublength == 0:
            logger.error('Loop in parameter body decoding (%d bytes left)',
                         datalen - start_pos)
            break
        start_pos += sublength

    return par_dict, ''


def decode_generic_message(data, msg_name=None, msg=None):
    """Auto decode a standard LLRP message without 'individual' modification"""
    if msg is None:
        msg = LLRPMessageDict()
    n_fields = []
    if msg_name:
        n_fields = Message_struct[msg_name]['n_fields']
    msg, _ = decode_all_parameters(data, msg_name, msg, n_fields)
    return msg


def decode_generic_message_with_status_check(data, msg_name=None):
    """Auto decode a standard LLRP message with check for LLRPStatus"""
    msg = decode_generic_message(data, msg_name)
    if 'LLRPStatus' not in msg:
        raise LLRPError('Missing or invalid LLRPStatus parameter')
    return msg


def encode_param(name, par):
    logger.debugfast("Encode: %s", name)
    try:
        param_info = Param_struct[name]
    except KeyError:
        logger.warning('Encoding error. No parameter found in Param_struct '
                       'for: %s', name)
        return b''
    try:
        encode_func = param_info['encode']
    except KeyError:
        logger.warning('No encoder found for parameter: %s', name)
        return b''
    param_type = param_info['type']

    sub_data = encode_func(par, param_info)

    if param_info.get('tv_encoded', False):
        data = tve_header_pack(param_type, len(sub_data))
    elif param_type == TYPE_CUSTOM:
        if name != 'CustomParameter':
            vendorid = param_info['vendorid']
            subtype = param_info['subtype']
        else:
            vendorid = par['VendorID']
            subtype = par['Subtype']
        data = par_custom_header_pack(param_type,
                                      par_custom_header_len + len(sub_data),
                                      vendorid, subtype)
    else:
        data = par_header_pack(param_type, par_header_len + len(sub_data))
    data += sub_data

    return data


def encode_all_parameters(par_dict, param_info=None, data=None, par_name=None):
    if data is None:
        data_list = []
    else:
        data_list = [data]
    if param_info is None:
        param_info = Param_struct[par_name]

    data_block_list = []

    for key, is_multiple in param_info['auto_fields']:
        if key not in par_dict:
            continue
        value = par_dict[key]
        if not is_multiple:
            data_list.append(encode_param(key, value))
        else:
            if not isinstance(value, list):
                logger.warning('Encoding error: "%s" parameter content should '
                            'be a list. Skipping...', key)
                continue
            for sub_value in value:
                data_list.append(encode_param(key, sub_value))

    return b''.join(data_list)


# 16.1.1 GET_READER_CAPABILITIES
Message_struct['GET_READER_CAPABILITIES'] = {
    'type': 1,
    'fields': [
        'ID',
        'RequestedData'
    ],
    'o_fields': [
        'ImpinjRequestedData'
    ],
    'encode': basic_auto_param_encode_generator(ubyte_pack, 'RequestedData')
}


# 16.1.2 GET_READER_CAPABILITIES_RESPONSE
Message_struct['GET_READER_CAPABILITIES_RESPONSE'] = {
    'type': 11,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
        'GeneralDeviceCapabilities',
        'LLRPCapabilities',
        'RegulatoryCapabilities',
        'C1G2LLRPCapabilities',
        'ImpinjDetailedVersion',
        'ImpinjFrequencyCapabilities',
        'ImpinjAntennaCapabilities',
        'MotoGeneralCapabilities',
        'MotoAutonomousCapabilities',
        'MotoTagEventsGenerationCapabilities',
        'MotoFilterCapabilities',
        'MotoPersistenceCapabilities',
        'MotoC1G2LLRPCapabilities',
        # Decoder not yet implemented:
        'ImpinjxArrayCapabilities',

    ],
    'decode': decode_generic_message_with_status_check
}


# GET_READER_CONFIG
def encode_GetReaderConfig(msg, param_info):
    req = msg['RequestedData']
    ant = msg.get('AntennaID', 0)
    gpipn = msg.get('GPIPortNum', 0)
    gpopn = msg.get('GPOPortNum', 0)
    packed = ubyte_ushort_ushort_ushort_pack(req, ant, gpipn, gpopn)

    data = encode_all_parameters(msg, param_info, packed)
    return data


Message_struct['GET_READER_CONFIG'] = {
    'type': 2,
    'fields': [
        'ID',
        'AntennaID',
        'RequestedData',
        'GPIPortNum',
        'GPOPortNum'
    ],
    'o_fields': [
        'ImpinjRequestedData'
    ],
    'encode': encode_GetReaderConfig
}


Message_struct['GET_READER_CONFIG_RESPONSE'] = {
    'type': 12,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
        'Identification',
        'ReaderEventNotificationSpec',
        'ROReportSpec',
        'AccessReportSpec',
        'LLRPConfigurationStateValue',
        'KeepaliveSpec',
        'EventsAndReports',
        # Optional N custom parameters after
        'ImpinjSubRegulatoryRegion',
        'ImpinjReaderTemperature',
        'ImpinjLinkMonitorConfiguration',
        'ImpinjAccessSpecConfiguration',
        'ImpinjReportBufferConfiguration',
        'ImpinjGPSNMEASentences',
        'ImpinjAntennaConfiguration',
        'MotoAutonomousState',
        'MotoDefaultSpec',
        'MotoFilterList',
        'MotoPersistenceSaveParams',
        'MotoCustomCommandOptions',
        # Custom parameter without decoder yet
        'ImpinjBeaconConfiguration',
        'ImpinjTiltConfiguration',
        'ImpinjPlacementConfiguration',
        'ImpinjLocationConfig',
        'ImpinjC1G2LocationConfig',
        'ImpinjLocationReporting',
        'ImpinjDirectionConfig',
        'ImpinjC1G2DirectionConfig',
        'ImpinjDirectionReporting',
        'ImpinjPolarizationControl',
    ],
    'n_fields': [
        'AntennaProperties',
        'AntennaConfiguration',
        'GPIPortCurrentState',
        'GPOWriteData',
        # Optional N custom parameters after
        'ImpinjHubConfiguration',
        'ImpinjAdvancedGPOConfiguration',
        'ImpinjGPIDebounceConfiguration',
    ],
    'decode': decode_generic_message_with_status_check
}


# SET_READER_CONFIG
def encode_SetReaderConfig(msg, param_info):
    reset_flag = int(msg.get('ResetToFactoryDefaults', False))
    reset = (reset_flag << 7) & 0xff
    packed = ubyte_pack(reset)
    return encode_all_parameters(msg, param_info, packed)


Message_struct['SET_READER_CONFIG'] = {
    'type': 3,
    'fields': [
        'ID',
        'ResetToFactoryDefaults',
        'ReaderEventNotificationSpec',
        'AntennaProperties',
        'AntennaConfiguration',
        'AccessReportSpec',
        'KeepaliveSpec',
        'GPOWriteData',
        'GPIPortCurrentState',
        'EventsAndReports',
        'ImpinjAntennaConfiguration',
    ],
    'o_fields': [
        'ReaderEventNotificationSpec',
        'ROReportSpec',
        'AccessReportSpec',
        'KeepaliveSpec',
        'EventsAndReports',
        'ImpinjAntennaConfiguration',
    ],
    'n_fields': [
        'AntennaProperties',
        'AntennaConfiguration',
        'GPOWriteData',
        'GPIPortCurrentState',
    ],
    'encode': encode_SetReaderConfig,
}


Message_struct['SET_READER_CONFIG_RESPONSE'] = {
    'type': 13,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# ENABLE_EVENTS_AND_REPORTS

Message_struct['ENABLE_EVENTS_AND_REPORTS'] = {
    'type': 64,
    'fields': [
        'ID',
    ],
    'encode': basic_param_encode_generator()
}


# 16.1.3 ADD_ROSPEC

Message_struct['ADD_ROSPEC'] = {
    'type': 20,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'ROSpec'
    ],
    'encode': encode_all_parameters
}


# 16.1.4 ADD_ROSPEC_RESPONSE
Message_struct['ADD_ROSPEC_RESPONSE'] = {
    'type': 30,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.5 DELETE_ROSPEC

Message_struct['DELETE_ROSPEC'] = {
    'type': 21,
    'fields': [
        'ID',
        'ROSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'ROSpecID')
}


# 16.1.6 DELETE_ROSPEC_RESPONSE
Message_struct['DELETE_ROSPEC_RESPONSE'] = {
    'type': 31,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.7 START_ROSPEC
Message_struct['START_ROSPEC'] = {
    'type': 22,
    'fields': [
        'ID',
        'ROSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'ROSpecID')
}


# 16.1.8 START_ROSPEC_RESPONSE
Message_struct['START_ROSPEC_RESPONSE'] = {
    'type': 32,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.9 STOP_ROSPEC
Message_struct['STOP_ROSPEC'] = {
    'type': 23,
    'fields': [
        'ID',
        'ROSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'ROSpecID')
}


# 16.1.10 STOP_ROSPEC_RESPONSE
Message_struct['STOP_ROSPEC_RESPONSE'] = {
    'type': 33,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.11 ENABLE_ROSPEC
def encode_EnableROSpec(msg):
    msgid = msg['ROSpecID']

    return struct.pack('!I', msgid)


Message_struct['ENABLE_ROSPEC'] = {
    'type': 24,
    'fields': [
        'ID',
        'ROSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'ROSpecID')
}


# 16.1.12 ENABLE_ROSPEC_RESPONSE
Message_struct['ENABLE_ROSPEC_RESPONSE'] = {
    'type': 34,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.13 DISABLE_ROSPEC
Message_struct['DISABLE_ROSPEC'] = {
    'type': 25,
    'fields': [
        'ID',
        'ROSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'ROSpecID')
}


# 16.1.14 DISABLE_ROSPEC_RESPONSE
Message_struct['DISABLE_ROSPEC_RESPONSE'] = {
    'type': 35,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


def decode_ROAccessReport(data, name=None):
    msg = LLRPMessageDict()
    # Ensure that there is always a TagReportData, even empty
    msg['TagReportData'] = []
    msg = decode_generic_message(data, name, msg)
    return msg


Message_struct['RO_ACCESS_REPORT'] = {
    'type': 61,
    'fields': [
        'ID',
    ],
    'n_fields': [
        'TagReportData',
    ],
    'decode': decode_ROAccessReport
}


# 16.1.35 KEEPALIVE
Message_struct['KEEPALIVE'] = {
    'type': 62,
    'fields': [
        'ID',
    ],
    'decode': decode_generic_message
}


# 16.1.36 KEEPALIVE_ACK
Message_struct['KEEPALIVE_ACK'] = {
    'type': 72,
    'fields': [
        'ID',
    ],
    'encode': basic_param_encode_generator()
}


# 16.1.33 READER_EVENT_NOTIFICATION
Message_struct['READER_EVENT_NOTIFICATION'] = {
    'type': 63,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'ReaderEventNotificationData'
    ],
    'encode': encode_all_parameters,
    'decode': decode_generic_message
}


# 16.1.40 CLOSE_CONNECTION
Message_struct['CLOSE_CONNECTION'] = {
    'type': 14,
    'fields': [
        'ID',
    ],
    'encode': basic_param_encode_generator()
}


# 16.1.41 CLOSE_CONNECTION_RESPONSE
Message_struct['CLOSE_CONNECTION_RESPONSE'] = {
    'type': 4,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.2.2.1 UTCTimestamp Parameter
Param_struct['UTCTimestamp'] = {
    'type': 128,
    'fields': [
        'Microseconds'
    ],
    'encode': basic_param_encode_generator(ulonglong_pack, 'Microseconds'),
    'decode': basic_param_decode_generator(ulonglong_unpack, 'Microseconds'),
}

# 16.2.2.2 Uptime Parameter
Param_struct['Uptime'] = {
    'type': 129,
    'fields': [
        'Microseconds'
    ],
    'encode': basic_param_encode_generator(ulonglong_pack, 'Microseconds'),
    'decode': basic_param_decode_generator(ulonglong_unpack, 'Microseconds'),
}

Param_struct['RegulatoryCapabilities'] = {
    'type': 143,
    'fields': [
        'CountryCode',
        'CommunicationsStandard',
    ],
    'o_fields': [
        'UHFBandCapabilities',
    ],
    'encode': basic_auto_param_encode_generator(ushort_ushort_unpack,
                                                'CountryCode',
                                                'CommunicationsStandard'),
    'decode': basic_auto_param_decode_generator(ushort_ushort_unpack,
                                                ushort_ushort_size,
                                                'CountryCode',
                                                'CommunicationsStandard')

}


Param_struct['UHFBandCapabilities'] = {
    'type': 144,
    'o_fields': [
        'TransmitPowerLevelTableEntry',
        'FrequencyInformation',
        'UHFC1G2RFModeTable',
        'RFSurveyFrequencyCapabilities'
    ],
    'n_fields': [
        'TransmitPowerLevelTableEntry',
    ],
    'decode': decode_all_parameters
}


Param_struct['TransmitPowerLevelTableEntry'] = {
    'type': 145,
    'fields': [
        'Index',
        'TransmitPowerValue'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           'Index', 'TransmitPowerValue')
}


def decode_FrequencyInformation(data, name=None):
    logger.debugfast('decode_FrequencyInformation')

    flags = ubyte_unpack(data[:ubyte_size])[0]
    par = {
        'Hopping': flags & BIT(7) == BIT(7)
    }

    data = data[ubyte_size:]
    par, _ = decode_all_parameters(data, 'FrequencyInformation', par)

    return par, ''


Param_struct['FrequencyInformation'] = {
    'type': 146,
    'fields': [
        'Hopping',
        'FrequencyHopTable',
        'FixedFrequencyTable'
    ],
    'o_fields': [
        'FixedFrequencyTable'
    ],
    'n_fields': [
        'FrequencyHopTable',
    ],
    'decode': decode_FrequencyInformation
}


def decode_FrequencyHopTable(data, name=None):
    logger.debugfast('decode_FrequencyHopTable')
    par = {}

    # Decode fields
    par['HopTableId'], flags, par['NumHops'] = \
        ubyte_ubyte_ushort_unpack(data[:ubyte_ubyte_ushort_size])
    data = data[ubyte_ubyte_ushort_size:]

    num = int(par['NumHops'])
    if num:
        par['Frequency'] = []
        for _ in range(1, num + 1):
            par['Frequency'].append(uint_unpack(data[:uint_size])[0])
            data = data[uint_size:]

    return par, ''


Param_struct['FrequencyHopTable'] = {
    'type': 147,
    'fields': [
        'HopTableId',
        'NumHops',
        'Frequency',
    ],
    'decode': decode_FrequencyHopTable
}


def decode_FixedFrequencyTable(data, name=None):
    logger.debugfast('decode_FixedFrequencyTable')
    par = {}

    # Decode fields
    par['NumFrequencies'] = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]

    num = int(par['NumFrequencies'])
    if num:
        par['Frequency'] = []
        for _ in range(1, num + 1):
            par['Frequency'].append(uint_unpack(data[:uint_size])[0])
            data = data[uint_size:]

    return par, ''


Param_struct['FixedFrequencyTable'] = {
    'type': 148,
    'fields': [
        'NumFrequencies',
        'Frequency',
    ],
    'decode': decode_FixedFrequencyTable
}


def decode_C1G2LLRPCapabilities(data, name=None):
    logger.debugfast('decode_C1G2LLRPCapabilities')
    par = {}

    (flags,
     par['MaxNumSelectFiltersPerQuery']) = ubyte_ushort_unpack(data)

    par['CanSupportBlockErase'] = (flags & BIT(7) == BIT(7))
    par['CanSupportBlockWrite'] = (flags & BIT(6) == BIT(6))
    par['CanSupportBlockPermalock'] = (flags & BIT(5) == BIT(5))
    par['CanSupportTagRecommissioning'] = (flags & BIT(4) == BIT(4))
    par['CanSupportUMIMethod2'] = (flags & BIT(3) == BIT(3))
    par['CanSupportXPC'] = (flags & BIT(2) == BIT(2))

    return par, ''


# v1.1:17.3.1.1.1 C1G2LLRPCapabilities
Param_struct['C1G2LLRPCapabilities'] = {
    'type': 327,
    'fields': [
        'CanSupportBlockErase',
        'CanSupportBlockWrite',
        'CanSupportBlockPermalock',
        'CanSupportTagRecommissioning',
        'CanSupportUMIMethod2',
        'CanSupportXPC',
        'MaxNumSelectFiltersPerQuery'
    ],
    'decode': decode_C1G2LLRPCapabilities
}


# v1.1:17.3.1.1.2 UHFC1G2RFModeTable
Param_struct['UHFC1G2RFModeTable'] = {
    'type': 328,
    'fields': [
    ],
    'n_fields': [
        'UHFC1G2RFModeTableEntry'
    ],
    'decode': decode_all_parameters
}


# v1.1:17.3.1.1.3 UHFC1G2RFModeTableEntry
mode_table_entry_unpack = struct.Struct('!IBBBBIIIII').unpack

def decode_UHFC1G2RFModeTableEntry(data, name=None):
    logger.debugfast('decode_UHFC1G2RFModeTableEntry')
    par = {}

    # Decode fields
    (par['ModeIdentifier'],
     RC,
     par['Mod'],
     par['FLM'],
     par['M'],
     par['BDR'],
     par['PIE'],
     par['MinTari'],
     par['MaxTari'],
     par['StepTari']) = mode_table_entry_unpack(data)

    # parse RC
    par['DR'] = RC >> 7
    par['EPCHAGTCConformance'] = RC & BIT(6) == BIT(6)

    return par, ''


Param_struct['UHFC1G2RFModeTableEntry'] = {
    'type': 329,
    'fields': [
        'ModeIdentifier',
        'DR',
        'EPCHAGTCConformance',
        'Mod',
        'FLM',
        'M',
        'BDR',
        'PIE',
        'MinTari',
        'MaxTari',
        'StepTari'
    ],
    'decode': decode_UHFC1G2RFModeTableEntry
}


Param_struct['RFSurveyFrequencyCapabilities'] = {
    'type': 365,
    'fields': [
        'MinimumFrequency',
        'MaximumFrequency'
    ],
    'decode': basic_param_decode_generator(uint_uint_unpack,
                                           'MinimumFrequency',
                                           'MaximumFrequency')
}


# 16.2.3.2 LLRPCapabilities Parameter
llrp_capabilities_unpack = struct.Struct('!BBHIIIII').unpack

def decode_LLRPCapabilities(data, name=None):
    logger.debugfast('decode_LLRPCapabilities')
    par = {}

    (flags,
     par['MaxPriorityLevelSupported'],
     par['ClientRequestOpSpecTimeout'],
     par['MaxNumROSpec'],
     par['MaxNumSpecsPerROSpec'],
     par['MaxNumInventoryParametersSpecsPerAISpec'],
     par['MaxNumAccessSpec'],
     par['MaxNumOpSpecsPerAccessSpec']) = llrp_capabilities_unpack(data)

    par['CanDoRFSurvey'] = (flags & BIT(7) == BIT(7))
    par['CanReportBufferFillWarning'] = (flags & BIT(6) == BIT(6))
    par['SupportsClientRequestOpSpec'] = (flags & BIT(5) == BIT(5))
    par['CanDoTagInventoryStateAwareSingulation'] = (flags & BIT(4) == BIT(4))
    par['SupportsEventAndReportHolding'] = (flags & BIT(3) == BIT(3))

    return par, ''


Param_struct['LLRPCapabilities'] = {
    'type': 142,
    'fields': [
        'CanDoRFSurvey',
        'CanReportBufferFillWarning',
        'SupportsClientRequestOpSpec',
        'CanDoTagInventoryStateAwareSingulation',
        'SupportsEventAndReportHolding',
        'MaxPriorityLevelSupported',
        'ClientRequestOpSpecTimeout',
        'MaxNumROSpec',
        'MaxNumSpecsPerROSpec',
        'MaxNumInventoryParametersSpecsPerAISpec',
        'MaxNumAccessSpec',
        'MaxNumOpSpecsPerAccessSpec'
    ],
    'decode': decode_LLRPCapabilities
}


# 16.2.3.2 GeneralDeviceCapabilities Parameter
general_dev_capa_begin_size = struct.calcsize('!HHIIH')
general_dev_capa_begin_unpack = struct.Struct('!HHIIH').unpack

def decode_GeneralDeviceCapabilities(data, name=None):
    logger.debugfast('decode_GeneralDeviceCapabilities')
    par = {}

    # Decode fields
    (par['MaxNumberOfAntennaSupported'],
     flags,
     par['DeviceManufacturerName'],
     par['ModelName'],
     par['FirmwareVersionByteCount']) = \
         general_dev_capa_begin_unpack(data[:general_dev_capa_begin_size])

    par['CanSetAntennaProperties'] = (flags & BIT(15) == BIT(15))
    par['HasUTCClockCapability'] = (flags & BIT(14) == BIT(14))

    pastVer = general_dev_capa_begin_size + par['FirmwareVersionByteCount']
    par['ReaderFirmwareVersion'] = data[general_dev_capa_begin_size:pastVer]
    data = data[pastVer:]

    par, _ = decode_all_parameters(data, 'GeneralDeviceCapabilities', par)

    return par, ''


Param_struct['GeneralDeviceCapabilities'] = {
    'type': 137,
    'fields': [
        'MaxNumberOfAntennaSupported',
        'CanSetAntennaProperties',
        'HasUTCClockCapability',
        'DeviceManufacturerName',
        'ModelName',
        'FirmwareVersionByteCount',
        'ReaderFirmwareVersion',
        'ReceiveSensitivityTableEntry',
        'PerAntennaReceiveSensitivityRange',
        'GPIOCapabilities',
        'PerAntennaAirProtocol',
        'MaximumReceiveSensitivity'

    ],
    'o_fields': [
        'GPIOCapabilities',
        'MaximumReceiveSensitivity'
    ],
    'n_fields': [
        'ReceiveSensitivityTableEntry',
        'PerAntennaReceiveSensitivityRange',
        'PerAntennaAirProtocol',
    ],
    'decode': decode_GeneralDeviceCapabilities
}


Param_struct['MaximumReceiveSensitivity'] = {
    'type': 363,
    'fields': [
        'MaximumSensitivityValue'
    ],
    'decode': basic_param_decode_generator(ushort_unpack,
                                           'MaximumSensitivityValue')
}


Param_struct['ReceiveSensitivityTableEntry'] = {
    'type': 139,
    'fields': [
        'Index',
        'ReceiveSensitivityValue'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           'Index',
                                           'ReceiveSensitivityValue')
}


Param_struct['PerAntennaReceiveSensitivityRange'] = {
    'type': 149,
    'fields': [
        'AntennaID',
        'ReceiveSensitivityIndexMin',
        'ReceiveSensitivityIndexMax'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_ushort_unpack,
                                           'AntennaID',
                                           'ReceiveSensitivityIndexMin',
                                           'ReceiveSensitivityIndexMax')
}


def decode_PerAntennaAirProtocol(data, name=None):
    logger.debugfast('decode_PerAntennaAirProtocol')
    par = {}

    # Decode fields
    (par['AntennaID'],
     par['NumProtocols']) = ushort_ushort_unpack(data[:ushort_ushort_size])
    data = data[ushort_ushort_size:]

    num = int(par['NumProtocols'])
    if num:
        par['ProtocolID'] = []
        for i in range(num):
            par['ProtocolID'].append(ubyte_unpack(data[:ubyte_size])[0])
            data = data[ubyte_size:]

    return par, ''


Param_struct['PerAntennaAirProtocol'] = {
    'type': 140,
    'fields': [
        'AntennaID',
        'NumProtocols',
        'ProtocolID'
    ],
    'decode': decode_PerAntennaAirProtocol
}


Param_struct['GPIOCapabilities'] = {
    'type': 141,
    'fields': [
        'NumGPIs',
        'NumGPOs'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           'NumGPIs', 'NumGPOs')
}


Message_struct['ERROR_MESSAGE'] = {
    'type': 100,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.2.4.1 ROSpec Parameter (LLRP v1.1 section 17.2.4.1)
def encode_ROSpec(par, param_info):
    # Note, priority should be in 0-7.
    state = ROSpecState_Name2Type[par['CurrentState']]
    packed = uint_ubyte_ubyte_pack(par['ROSpecID'], par['Priority'], state)

    return encode_all_parameters(par, param_info, packed)


Param_struct['ROSpec'] = {
    'type': 177,
    'fields': [
        'ROSpecID',
        'Priority',
        'CurrentState',
        'ROBoundarySpec',
        'AISpec',
        'RFSurveySpec',
        'LoopSpec',
        'ROReportSpec',
    ],
    'o_fields': [
        'ROBoundarySpec',
        'ROReportSpec',
    ],
    'n_fields': [
        'AISpec',
        'RFSurveySpec',
        # Not yet implemented, llrp v1.1
        'LoopSpec',
    ],
    'encode': encode_ROSpec,
    'decode': basic_auto_param_decode_generator(
        uint_ubyte_ubyte_unpack,
        uint_ubyte_ubyte_size,
        'ROSpecID',
        'Priority',
        'CurrentState'
    )
}


# 17.2.5.1 AccessSpec
access_spec_pack = struct.Struct('!IHBBI').pack

def encode_AccessSpec(par, param_info):
    current_state = par['CurrentState'] and (1 << 7) or 0

    packed = access_spec_pack(int(par['AccessSpecID']),
                              int(par['AntennaID']),
                              par['ProtocolID'],
                              current_state,
                              par['ROSpecID'])

    return encode_all_parameters(par, param_info, packed)



# 17.2.5.1 AccessSpec
Param_struct['AccessSpec'] = {
    'type': 207,
    'fields': [
        'AccessSpecID',
        'AntennaID',
        'ProtocolID',
        'CurrentState',
        'ROSpecID',
    ],
    'o_fields': [
        'AccessSpecStopTrigger',
        'AccessCommand',
        'AccessReportSpec',
        'ImpinjAccessSpecConfiguration',
    ],
    'encode': encode_AccessSpec
}


# 17.1.21 ADD_ACCESSSPEC
Message_struct['ADD_ACCESSSPEC'] = {
    'type': 40,
    'o_fields': [
        'AccessSpec',
    ],
    'encode': encode_all_parameters
}


# 17.1.22 ADD_ACCESSSPEC_RESPONSE
Message_struct['ADD_ACCESSSPEC_RESPONSE'] = {
    'type': 50,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 17.1.23 DELETE_ACCESSSPEC
Message_struct['DELETE_ACCESSSPEC'] = {
    'type': 41,
    'fields': [
        'ID',
        'AccessSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'AccessSpecID'),
}


# 17.1.24 DELETE_ACCESSSPEC_RESPONSE
Message_struct['DELETE_ACCESSSPEC_RESPONSE'] = {
    'type': 51,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 17.1.25 ENABLE_ACCESSSPEC
Message_struct['ENABLE_ACCESSSPEC'] = {
    'type': 42,
    'fields': [
        'ID',
        'AccessSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'AccessSpecID'),
}


# 17.1.26 ENABLE_ACCESSSPEC_RESPONSE
Message_struct['ENABLE_ACCESSSPEC_RESPONSE'] = {
    'type': 52,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 17.1.27 DISABLE_ACCESSSPEC
Message_struct['DISABLE_ACCESSSPEC'] = {
    'type': 43,
    'fields': [
        'ID',
        'AccessSpecID'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'AccessSpecID'),
}


# 17.1.28 DISABLE_ACCESSSPEC_RESPONSE
Message_struct['DISABLE_ACCESSSPEC_RESPONSE'] = {
    'type': 53,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


def encode_AccessSpecStopTrigger(par):
    return ubyte_ushort_pack(int(par['AccessSpecStopTriggerType']),
                             int(par['OperationCountValue']))


Param_struct['AccessSpecStopTrigger'] = {
    'type': 208,
    'fields': [
        'AccessSpecStopTriggerType',
        'OperationCountValue'
    ],
    'encode': encode_AccessSpecStopTrigger
}


def encode_AccessCommand(par, param_info):

    # OpSpecParameter can be one of:
    # C1G2 OpSpec or a ClientRequestOpSpec or a custom parameter
    opSpecs = par['OpSpecParameter']

    data = b''
    for opName, spec_info in opSpecs:
        data += encode_param(opName, spec_info)

    return encode_all_parameters(par, param_info, data)


Param_struct['AccessCommand'] = {
    'type': 209,
    'fields': [
        # Virtual parameter to have an ordered list of OpSpec
        'OpSpecParameter'
    ],
    'o_fields': [
        'C1G2TagSpec',
    ],
    'encode': encode_AccessCommand
}


Param_struct['C1G2TagSpec'] = {
    'type': 338,
    'n_fields': [
        'C1G2TargetTag'
    ],
    'encode': encode_all_parameters
}


def encode_bitstring(bstr, length_bytes):
    padding = b'\x00' * (length_bytes - len(bstr))
    return bstr + padding


def encode_C1G2TargetTag(par, param_info):
    MB_M_byte = (int(par['MB']) << 6) | (par['M'] and (1 << 5) or 0)
    data = [ubyte_ushort_ushort_pack(MB_M_byte,
                                     int(par['Pointer']),
                                     int(par['MaskBitCount']))]
    if int(par['MaskBitCount']):
        numBytes = ((par['MaskBitCount'] - 1) // 8) + 1
        data.append(encode_bitstring(par['TagMask'], numBytes))

    data.append(ushort_pack(int(par['DataBitCount'])))
    if int(par['DataBitCount']):
        numBytes = ((par['DataBitCount'] - 1) // 8) + 1
        data.append(encode_bitstring(par['TagData'], numBytes))

    return b''.join(data)


Param_struct['C1G2TargetTag'] = {
    'type': 339,
    'fields': [
        'MB',
        'M',
        'Pointer',
        'MaskBitCount',
        'TagMask',
        'DataBitCount',
        'TagData'
    ],
    'encode': encode_C1G2TargetTag
}


# 16.2.1.3.2.2 C1G2Read
c1g2readwrite_pack = struct.Struct('!HIBHH').pack

def encode_C1G2Read(par, param_info):
    data = c1g2readwrite_pack(int(par['OpSpecID']),
                              int(par['AccessPassword']),
                              int(par['MB']) << 6,
                              int(par['WordPtr']),
                              int(par['WordCount']))
    return data


Param_struct['C1G2Read'] = {
    'type': 341,
    'fields': [
        'OpSpecID',
        'AccessPassword'
        'MB',
        'WordPtr',
        'WordCount',
    ],
    'encode': encode_C1G2Read
}


# 16.2.1.3.2.3 C1G2Write

def encode_C1G2Write(par, param_info):
    data = c1g2readwrite_pack(int(par['OpSpecID']),
                              int(par['AccessPassword']),
                              int(par['MB']) << 6,
                              int(par['WordPtr']),
                              int(par['WriteDataWordCount']))
    data += par['WriteData']

    return data


Param_struct['C1G2Write'] = {
    'type': 342,
    'fields': [
        'OpSpecID',
        'AccessPassword'
        'MB',
        'WordPtr',
        'WriteDataWordCount',
        'WriteData'
    ],
    'encode': encode_C1G2Write
}


# 16.2.1.3.2.5 C1G2Lock Parameter
def encode_C1G2Lock(par, param_info):
    packed = ushort_uint_pack(int(par['OpSpecID']), int(par['AccessPassword']))
    return encode_all_parameters(par, param_info, packed)


Param_struct['C1G2Lock'] = {
    'type': 344,
    'fields': [
        'OpSpecID',
        'AccessPassword'
    ],
    'n_fields': [
        'C1G2LockPayload',
    ],
    'encode': encode_C1G2Lock
}


# 16.2.1.3.2.5.1 C1G2LockPayload Parameter
def encode_C1G2LockPayload(par, param_info):
    return byte_ubyte_pack(int(par['Privilege']), int(par['DataField']))


Param_struct['C1G2LockPayload'] = {
    'type': 345,
    'fields': [
        'Privilege',
        'DataField',
    ],
    'encode': encode_C1G2LockPayload
}


# 16.2.1.3.2.7 C1G2BlockWrite
def encode_C1G2BlockWrite(par, param_info):
    data = c1g2readwrite_pack(int(par['OpSpecID']),
                              int(par['AccessPassword']),
                              int(par['MB']) << 6,
                              int(par['WordPtr']),
                              int(par['WriteDataWordCount']))
    data += par['WriteData']
    return data


Param_struct['C1G2BlockWrite'] = {
    'type': 347,
    'fields': [
        'OpSpecID',
        'AccessPassword'
        'MB',
        'WordPtr',
        'WriteDataWordCount',
        'WriteData'
    ],
    'encode': encode_C1G2Write
}


# TODO: Use/convert AccessReportTrigger_Name2Type
Param_struct['AccessReportSpec'] = {
    'type': 239,
    'fields': [
        'AccessReportTrigger'
    ],
    'encode': basic_param_encode_generator(ubyte_pack, 'AccessReportTrigger'),
    'decode': basic_param_decode_generator(ubyte_unpack)
}


# 16.2.4.1.1 ROBoundarySpec Parameter (LLRP v1.1 section 17.2.4.1.1)
Param_struct['ROBoundarySpec'] = {
    'type': 178,
    'o_fields': [
        'ROSpecStartTrigger',
        'ROSpecStopTrigger'
    ],
    'encode': encode_all_parameters,
    'decode': decode_all_parameters,
}


# 16.2.4.1.1.1 ROSpecStartTrigger Parameter (LLRP v1.1 section 17.2.4.1.1.1)
def encode_ROSpecStartTrigger(par, param_info):
    t_type = ROSpecStartTriggerType_Name2Type[par['ROSpecStartTriggerType']]
    packed = ubyte_pack(t_type)
    return encode_all_parameters(par, param_info, packed)


Param_struct['ROSpecStartTrigger'] = {
    'type': 179,
    'fields': [
        'ROSpecStartTriggerType',
    ],
    'o_fields': [
        'PeriodicTriggerValue',
        'GPITriggerValue'
    ],
    'encode': encode_ROSpecStartTrigger,
    'decode': basic_auto_param_decode_generator(
        ubyte_unpack,
        ubyte_size,
        'ROSpecStartTriggerType'
    )
}


# 16.2.4.1.1.1.1 PeriodicTriggerValue Parameter (LLRP v1.1 section 17.2.4.1.1.1.1)
Param_struct['PeriodicTriggerValue'] = {
    'type': 180,
    'fields': [
        'Offset',
        'Period',
    ],
    'o_fields': [
        'UTCTimestamp',
    ],
    'encode': basic_auto_param_encode_generator(
        uint_uint_pack,
        'Offset',
        'Period'
    ),
    'decode': basic_auto_param_decode_generator(
        uint_uint_unpack,
        uint_uint_size,
        'Offset',
        'Period',
    )
}


# 16.2.4.1.1.1.2 GPITriggerValue Parameter (LLRP v1.1 section 17.2.4.1.1.1.2)
def encode_GPITriggerValue(par, param_info):
    gpievent = bool(par['GPIEvent']) << 7
    data = ushort_ubyte_uint_pack(par['GPIPortNum'],
                                  gpievent,
                                  int(par['Timeout']))
    return data


def decode_GPITriggerValue(data, name=None):
    logger.debugfast('decode_GPITriggerValue')

    gpi_port_num, gpi_event, timeout = ushort_ubyte_uint_unpack(data[:ushort_ubyte_uint_size])

    par = {
        'GPIPortNum': gpi_port_num,
        'GPIEvent': gpi_event & BIT(7) == BIT(7),
        'Timeout': timeout,
    }

    return par, ''


Param_struct['GPITriggerValue'] = {
    'type': 180,
    'fields': [
        'GPIPortNum',
        'GPIEvent',
        'Timeout'
    ],
    'encode': encode_GPITriggerValue,
    'decode': decode_GPITriggerValue,
}

# 16.2.4.1.1.2 ROSpecStopTrigger Parameter (LLRP v1.1 section 17.2.4.1.1.2)
def encode_ROSpecStopTrigger(par, param_info):
    t_type = ROSpecStopTriggerType_Name2Type[par['ROSpecStopTriggerType']]
    duration = int(par['DurationTriggerValue'])
    packed = ubyte_uint_pack(t_type, duration)
    return encode_all_parameters(par, param_info, packed)


def decode_ROSpecStopTrigger(data, name=None):
    logger.debugfast("decode_ROSpecStopTrigger")

    (trigger_type, duration_trigger_value) = ubyte_uint_unpack(data[:ubyte_uint_size])

    par = {
        'ROSpecStopTriggerType': ROSpecStopTriggerType_Type2Name[trigger_type],
        'DurationTriggerValue': duration_trigger_value
    }

    data = data[ubyte_uint_size:]
    par, _ = decode_all_parameters(data, 'ROSpecStopTrigger', par)

    return par, ''


Param_struct['ROSpecStopTrigger'] = {
    'type': 182,
    'fields': [
        'ROSpecStopTriggerType',
        'DurationTriggerValue',
    ],
    'o_fields': [
        'GPITriggerValue'
    ],
    'encode': encode_ROSpecStopTrigger,
    'decode': decode_ROSpecStopTrigger
}


# 16.2.4.2 AISpec Parameter (LLRP v1.1 section 17.2.4.2)
def encode_AISpec(par, param_info):
    # Antenna count
    data = [ushort_pack(len(par['AntennaID']))]
    # List of AntennaID
    for antid in par['AntennaID']:
        data.append(ushort_pack(int(antid)))

    return encode_all_parameters(par, param_info, b''.join(data))


def decode_AISPec(data, name=None):
    logger.debugfast("decode_AISpec")

    antenna_count = ushort_unpack(data[:ushort_size])[0]

    antenna_ids_length = ushort_size * antenna_count
    antenna_ids = data[ushort_size:ushort_size + antenna_ids_length]

    par = {
        'AntennaCount': antenna_count,
        'AntennaID': [
            ushort_unpack(antenna_ids[2 * b: 2 * b + ushort_size])[0] for b in range(len(antenna_ids) // ushort_size)
        ]
    }

    data = data[ushort_size + antenna_ids_length:]
    par, _ = decode_all_parameters(data, 'AISpec', par)

    return par, ''


Param_struct['AISpec'] = {
    'type': 183,
    'fields': [
        'AntennaCount',
        'AntennaID',
    ],
    'o_fields': [
        'AISpecStopTrigger',
    ],
    'n_fields': [
        'InventoryParameterSpec'
    ],
    'encode': encode_AISpec,
    'decode': decode_AISPec,
}


# 16.2.4.2.1 AISpecStopTrigger Parameter (LLRP v1.1 section 17.2.4.2.1)
def encode_AISpecStopTrigger(par, param_info):
    t_type = AISpecStopTriggerType_Name2Type[par['AISpecStopTriggerType']]
    duration = int(par.get('DurationTriggerValue', 0))
    packed = ubyte_uint_pack(t_type, duration)
    return encode_all_parameters(par, param_info, packed)


Param_struct['AISpecStopTrigger'] = {
    'type': 184,
    'fields': [
        'AISpecStopTriggerType',
        'DurationTriggerValue',
    ],
    'o_fields': [
        'GPITriggerValue',
        'TagObservationTrigger',
    ],
    'encode': encode_AISpecStopTrigger,
    'decode': basic_auto_param_decode_generator(
        ubyte_uint_unpack,
        ubyte_uint_size,
        'AISpecStopTriggerType',
        'DurationTriggerValue',
    )
}


# 16.2.4.2.1.1 TagObservationTrigger Parameter (LLRP v1.1 section 17.2.4.2.1.1)
tagobservationtrigger_pack = struct.Struct('!BBHHHI').pack
tagobservationtrigger_unpack = struct.Struct('!BBHHHI').unpack
tagobservationtrigger_size = struct.calcsize('!BBHHHI')

def encode_TagObservationTrigger(par, param_info):
    t_type = TagObservationTrigger_Name2Type[par['TriggerType']]
    n_tags = int(par['NumberOfTags'])
    n_attempts = int(par['NumberOfAttempts'])
    t = int(par['T'])
    timeout = int(par['Timeout'])

    return tagobservationtrigger_pack(t_type,
                                      0,
                                      n_tags,
                                      n_attempts,
                                      t,
                                      timeout)


def decode_TagObservationTrigger(data, name=None):
    logger.debugfast("decode_TagObservationTrigger")

    (
        trigger_type,
        _,
        number_of_tags,
        number_of_attempts,
        t,
        timeout
    ) = tagobservationtrigger_unpack(data)

    par = {
        'TriggerType': TagObservationTrigger_Type2Name[trigger_type],
        'NumberOfTags': number_of_tags,
        'NumberOfAttempts': number_of_attempts,
        'T': t,
        'Timeout': timeout
    }

    return par, ''


Param_struct['TagObservationTrigger'] = {
    'type': 185,
    'fields': [
        'TriggerType',
        'NumberOfTags',
        'NumberOfAttempts',
        'T',
        'Timeout'
    ],
    'encode': encode_TagObservationTrigger,
    'decode': decode_TagObservationTrigger
}


# 16.2.4.2.2 InventoryParameterSpec Parameter (LLRP v1.1 section 17.2.4.2.2)

Param_struct['InventoryParameterSpec'] = {
    'type': 186,
    'fields': [
        'InventoryParameterSpecID',
        'ProtocolID',
    ],
    'n_fields': [
        'AntennaConfiguration'
    ],
    'encode': basic_auto_param_encode_generator(
        ushort_ubyte_pack,
        'InventoryParameterSpecID',
        'ProtocolID'),
    'decode': basic_auto_param_decode_generator(
        ushort_ubyte_unpack,
        ushort_ubyte_size,
        'InventoryParameterSpecID',
        'ProtocolID'),
}

# v1.1:17.2.6.1 LLRPConfigurationStateValue Parameter
Param_struct['LLRPConfigurationStateValue'] = {
    'type': 217,
    'fields': [
        'LLRPConfigurationStateValue',
    ],
    'decode': basic_param_decode_generator(uint_unpack,
                                           'LLRPConfigurationStateValue')
}


# v1.1:17.2.6.2 Identification Parameter
def decode_Identification(data, name=None):
    ret = {}
    idtype, bytecount = ubyte_ushort_unpack(data[:ubyte_ushort_size])

    idtypes = ['MAC Address', 'EPC']
    try:
        ret['IDType'] = idtypes[idtype]
    except IndexError:
        ret['IDType'] = ''

    # the remainder is ID value
    ret['ReaderID'] = hexlify(
        data[ubyte_ushort_size:ubyte_ushort_size + bytecount])

    return ret, data[ubyte_ushort_size + bytecount:]


Param_struct['Identification'] = {
    'type': 218,
    'fields': [
        'IDType',
        'ReaderID'
    ],
    'decode': decode_Identification,
}

# v1.1:17.2.6.3 GPOWriteData Parameter
def decode_GPOEvent(data, name=None):
    logger.debugfast('decode_GPOEvent')
    par = {}

    par['GPOPortNumber'], flags = ushort_ubyte_unpack(data)
    par['GPOData'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['GPOWriteData'] = {
    'type': 219,
    'fields': [
        'GPOPortNumber',
        'GPOData',
    ],
    'decode': decode_GPOEvent
}


# v1.1:17.2.6.4 KeepaliveSpec Parameter
def decode_KeepaliveSpec(data, name=None):
    logger.debugfast('decode_KeepaliveSpec')

    (trigger_type, time_interval) = ubyte_uint_unpack(data)

    par = {
        'KeepaliveTriggerType': KeepaliveTriggerType_Type2Name[trigger_type],
        'TimeInterval': time_interval
    }
    return par, ''


Param_struct['KeepaliveSpec'] = {
    'type': 220,
    'fields': [
        'KeepaliveTriggerType',
        'TimeInterval',
    ],
    'decode': decode_KeepaliveSpec,
    'encode': basic_auto_param_encode_generator(ubyte_uint_pack,
                                                'KeepaliveTriggerType',
                                                'TimeInterval')
}


# v1.1:17.2.6.5 AntennaProperties Parammeter
def decode_AntennaProperties(data, name=None):
    logger.debugfast('decode_AntennaProperties')
    par = {}

    (flags,
     par['AntennaID'],
     par['AntennaGain']) = ubyte_ushort_short_unpack(data)
    par['AntennaConnected'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['AntennaProperties'] = {
    'type': 221,
    'fields': [
        'Type',
        'AntennaConnected',
        'AntennaID',
        'AntennaGain',
    ],
    'decode': decode_AntennaProperties
}


# 16.2.6.6 AntennaConfiguration Parameter
Param_struct['AntennaConfiguration'] = {
    'type': 222,
    'fields': [
        'AntennaID',
    ],
    'o_fields': [
        'RFReceiver',
        'RFTransmitter',
    ],
    'n_fields': [
        # AirProtocolInventoryCommandSettings:
        'C1G2InventoryCommand'
    ],
    'encode': basic_auto_param_encode_generator(ushort_pack, 'AntennaID'),
    'decode': basic_auto_param_decode_generator(ushort_unpack, ushort_size,
                                                'AntennaID')

}


# 16.2.6.7 RFReceiver Parameter
Param_struct['RFReceiver'] = {
    'type': 223,
    'fields': [
        'ReceiverSensitivity',
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'ReceiverSensitivity'),
    'decode': basic_param_decode_generator(ushort_unpack,
                                           'ReceiverSensitivity')
}


# V1.1:16.2.6.8 RFTransmitter Parameter
Param_struct['RFTransmitter'] = {
    'type': 224,
    'fields': [
        'HopTableId',
        'ChannelIndex',
        'TransmitPower',
    ],
    'encode': basic_param_encode_generator(ushort_ushort_ushort_pack,
                                           'HopTableId',
                                           'ChannelIndex',
                                           'TransmitPower'),
    'decode': basic_param_decode_generator(ushort_ushort_ushort_unpack,
                                           'HopTableId',
                                           'ChannelIndex',
                                           'TransmitPower')
}


# V1.1:17.2.6.9 GPOWriteData Parameter
def decode_GPIPortCurrentState(data, name=None):
    logger.debugfast('decode_GPIPortCurrentState')
    par = {}

    par['GPIPortNum'], flags, par['GPIState'] = ushort_ubyte_ubyte_unpack(data)
    par['GPIConfig'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['GPIPortCurrentState'] = {
    'type': 225,
    'fields': [
        'GPIPortNum',
        'GPIConfig',
        'GPIState'
    ],
    'decode': decode_GPIPortCurrentState
}


# V1.1:17.2.6.10 EventsAndReports Parameter
def decode_EventsAndReports(data, name=None):
    logger.debugfast('decode_GPOEvent')

    flags = ubyte_unpack(data)[0]
    par = {
        'HoldEventsAndReportsUponReconnect': flags & BIT(7) == BIT(7)
    }

    return par, ''


Param_struct['EventsAndReports'] = {
    'type': 226,
    'fields': [
        'HoldEventsAndReportsUponReconnect',
    ],
    'decode': decode_EventsAndReports
}


# 16.3.1.2.1 C1G2InventoryCommand Parameter
def encode_C1G2InventoryCommand(par, param_info):
    packed = ubyte_pack((par['TagInventoryStateAware'] and 1 or 0) << 7)
    return encode_all_parameters(par, param_info, packed)


def decode_C1G2InventoryCommand(data, name=None):
    logger.debugfast('decode_C1G2InventoryCommand')
    par = {}

    flags = ubyte_unpack(data[:ubyte_size])[0]
    par['TagInventoryStateAware'] = (flags & BIT(7) == BIT(7))

    par, _ = decode_all_parameters(data[ubyte_size:], 'C1G2InventoryCommand',
                                   par)

    return par, ''


Param_struct['C1G2InventoryCommand'] = {
    'type': 330,
    'fields': [
        'TagInventoryStateAware',
        'C1G2Filter',
        'C1G2RFControl',
        'C1G2SingulationControl',
        'ImpinjInventoryConfiguration',
        'ImpinjInventorySearchMode',
        'ImpinjIntelligentAntennaManagement',
        'ImpinjFixedFrequencyList',
        'ImpinjReducedPowerFrequencyList',
        'ImpinjLowDutyCycle',
        'ImpinjRFPowerSweep'
    ],
    'o_fields': [
        'C1G2RFControl',
        'C1G2SingulationControl',
        'ImpinjInventoryConfiguration',
        'ImpinjInventorySearchMode',
        'ImpinjIntelligentAntennaManagement',
        'ImpinjFixedFrequencyList',
        'ImpinjReducedPowerFrequencyList',
        'ImpinjLowDutyCycle',
        'ImpinjRFPowerSweep'
    ],
    'n_fields': [
        'C1G2Filter',
    ],
    'encode': encode_C1G2InventoryCommand,
    'decode': decode_C1G2InventoryCommand
}


# 16.3.1.2.1.1 C1G2Filter Parameter
def encode_C1G2Filter(par, param_info):
    # T: truncation (0: Reader decide, 1: Do not truncate, 2: Truncate)
    t = int(par.get('T', 0))
    packed = ubyte_pack((t & 0x03) << 6)
    return encode_all_parameters(par, param_info, packed)


Param_struct['C1G2Filter'] = {
    'type': 331,
    'fields': [
        'T',
    ],
    'o_fields': [
        'C1G2TagInventoryMask',
        # TODO: To be implemented:
        'C1G2TagInventoryStateAwareFilterAction',
        'C1G2TagInventoryStateUnawareFilterAction',
    ],
    'encode': encode_C1G2Filter
}

# 16.3.1.2.1.1.1 C1G2TagInventoryMask Parameter
def encode_C1G2TagInventoryMask(par, param_info):
    tag_mask = par['TagMask']
    maskbitcount = len(tag_mask) * 4
    # check for odd numbered length hexstring
    if len(tag_mask) % 2 != 0:
        # pad with zero
        tag_mask += '0'

    data = ubyte_ushort_ushort_pack(par['MB'] << 6,
                                    par['Pointer'],
                                    maskbitcount)
    if maskbitcount:
        data += unhexlify(tag_mask)
    return data

Param_struct['C1G2TagInventoryMask'] = {
    'type': 332,
    'fields': [
        'MB',
        'Pointer',
        'TagMask',
        'MaskBitCount',
    ],
    'encode': encode_C1G2TagInventoryMask
}

# 16.3.1.2.1.2 C1G2RFControl Parameter
Param_struct['C1G2RFControl'] = {
    'type': 335,
    'fields': [
        'ModeIndex',
        'Tari',
    ],
    'encode': basic_param_encode_generator(ushort_ushort_pack,
                                           'ModeIndex',
                                           'Tari'),
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           'ModeIndex', 'Tari')
}


# 16.3.1.2.1.3 C1G2SingulationControl Parameter
def encode_C1G2SingulationControl(par, param_info):
    return ubyte_ushort_uint_pack(par['Session'] << 6,
                                  par['TagPopulation'],
                                  par['TagTransitTime'])


def decode_C1G2SingulationControl(data, name=None):
    logger.debugfast('decode_FrequencyInformation')
    par = {}

    (bitfield,
     par['TagPopulation'],
     par['TagTransitTime']) = ubyte_ushort_uint_unpack(
        data[:ubyte_ushort_uint_size])

    par['Session'] = int(bitfield >> 6)

    data = data[ubyte_ushort_uint_size:]
    par, _ = decode_all_parameters(data, 'C1G2SingulationControl', par)

    return par, ''


Param_struct['C1G2SingulationControl'] = {
    'type': 336,
    'fields': [
        'Session',
        'TagPopulation',
        'TagTransitTime',
    ],
    'o_fields': [
        'C1G2TagInventoryStateAwareSingulationAction',
    ],
    'encode': encode_C1G2SingulationControl,
    'decode': decode_C1G2SingulationControl
}


def decode_C1G2TagInventoryStateAwareSingulationAction(data, name=None):
    logger.debugfast('decode_C1G2TagInventoryStateAwareSingulationAction')
    par = {}

    ISA = ubyte_unpack(data)[0]
    par['I'] = (ISA >> 7) and 'State_B' or 'State_A'
    par['S'] = ((ISA >> 6) & 1) and 'Not_SL' or 'SL'
    par['A'] = ((ISA >> 5) & 1) and 'All' or 'No'

    return par, ''


Param_struct['C1G2TagInventoryStateAwareSingulationAction'] = {
    'type': 337,
    'fields': [
        'I',
        'S',
        'A',
    ],
    'decode': decode_C1G2TagInventoryStateAwareSingulationAction
}


# 16.2.7.1 ROReportSpec Parameter
def encode_ROReportSpec(par, param_info):
    roReportTrigger = ROReportTrigger_Name2Value[par['ROReportTrigger']]
    n = int(par['N'])

    packed = ubyte_ushort_pack(roReportTrigger, n)
    return encode_all_parameters(par, param_info, packed)


def decode_ROReportSpec(data, name=None):
    logger.debugfast('decode_ROReportSpec')
    par = {}

    trigger_type, par['N'] = ubyte_ushort_unpack(data[:ubyte_ushort_size])
    par['ROReportTrigger'] = ROReportTrigger_Value2Name[trigger_type]

    par, _ = decode_all_parameters(data[ubyte_ushort_size:], 'ROReportSpec',
                                   par)
    return par, ''

Param_struct['ROReportSpec'] = {
    'type': 237,
    'fields': [
        'ROReportTrigger',
        'N',
    ],
    'o_fields': [
        'TagReportContentSelector',
        'ImpinjTagReportContentSelector',
    ],
    'encode': encode_ROReportSpec,
    'decode': decode_ROReportSpec
}


def encode_ReaderEventNotificationSpec(par, param_info):

    states = par['EventNotificationState']

    data = b''
    for ev_type, flag in states.items():
        if ev_type not in EventState_Name2Value:
            logger.warning('Unknown event name %s', ev_type)
            continue
        eventstate_par = {'EventType': ev_type,
                          'NotificationState': flag}
        data += encode_param('EventNotificationState', eventstate_par)
    return data


Param_struct['ReaderEventNotificationSpec'] = {
    'type': 244,
    'n_fields': [
        'EventNotificationState',
    ],
    'encode': encode_ReaderEventNotificationSpec,
    'decode': decode_all_parameters
}


#TODO: TO BE IMPROVED
def encode_EventNotificationState(par, param_info):
    event_type = EventState_Name2Value[par['EventType']]
    enabled = (bool(par['NotificationState']) << 7) & 0xff
    return ushort_ubyte_pack(event_type, enabled)


def decode_EventNotificationState(data, name=None):
    logger.debugfast('decode_EventNotificationState')
    par = {}

    event_type, flags = ushort_ubyte_unpack(data)
    par = {
        'EventType': EventState_Value2Name[event_type],
        'NotificationState': flags & BIT(7) == BIT(7)
    }

    return par, ''


Param_struct['EventNotificationState'] = {
    'type': 245,
    'fields': [
        'EventType',
        'NotificationState'
    ],
    'encode': encode_EventNotificationState,
    'decode': decode_EventNotificationState
}


# 16.2.7.1 TagReportContentSelector Parameter
def encode_TagReportContentSelector(par, param_info):
    flags = 0
    i = 15
    for field in param_info['fields']:
        if field in ['C1G2EPCMemorySelector', 'CustomParameter']:
            continue
        if par.get(field, False):
            flags = flags | (1 << i)
        i = i - 1
    packed = ushort_pack(flags)
    return encode_all_parameters(par, param_info, packed)


def decode_TagReportContentSelector(data, name=None):
    logger.debugfast('decode_TagReportContentSelector')
    par = {}

    flags = ushort_unpack(data[:ushort_size])[0]
    i = 15
    for field in Param_struct['TagReportContentSelector']['fields']:
        if field in ['C1G2EPCMemorySelector', 'CustomParameter']:
            continue
        par[field] = (flags & BIT(i) == BIT(i))
        i = i - 1

    data = data[ushort_size:]
    par, _ = decode_all_parameters(data, 'TagReportContentSelector', par)
    return par, ''


Param_struct['TagReportContentSelector'] = {
    'type': 238,
    'fields': [
        'EnableROSpecID',
        'EnableSpecIndex',
        'EnableInventoryParameterSpecID',
        'EnableAntennaID',
        'EnableChannelIndex',
        'EnablePeakRSSI',
        'EnableFirstSeenTimestamp',
        'EnableLastSeenTimestamp',
        'EnableTagSeenCount',
        'EnableAccessSpecID',
    ],
    'o_fields': [
        'C1G2EPCMemorySelector',
    ],
    'encode': encode_TagReportContentSelector,
    'decode': decode_TagReportContentSelector,
}


# 15.2.1.5.1 C1G2EPCMemorySelector Parameter
def encode_C1G2EPCMemorySelector(par, param_info):
    flags = 0
    i = 7
    for field in param_info['fields']:
        if field == 'CustomParameter':
            continue
        if field in par and par[field]:
            flags = flags | (1 << i)
        i = i - 1
    return ubyte_pack(flags)


def decode_C1G2EPCMemorySelector(data, name=None):
    logger.debugfast('decode_C1G2EPCMemorySelector')

    flags = ubyte_unpack(data)[0]
    par = {
        'EnableCRC': flags & BIT(7) == BIT(7),
        'EnablePCBits': flags & BIT(6) == BIT(6),
        'EnableXPCBits': flags & BIT(5) == BIT(5)
    }

    return par, ''


Param_struct['C1G2EPCMemorySelector'] = {
    'type': 348,
    'fields': [
        'EnableCRC',
        'EnablePCBits',
        # New in protocol v2 (llrp 1_1)
        'EnableXPCBits'
    ],
    'encode': encode_C1G2EPCMemorySelector,
    'decode': decode_C1G2EPCMemorySelector,
}


# 16.2.7.3 TagReportData Parameter
def decode_TagReportData(data, name=None):
    par, _ = decode_all_parameters(data, 'TagReportData')

    # EPC-96 is just a protocol optimization for EPCData but was not supposed
    # to be exposed to higher level
    # Keep it here for the moment, because a lof of clients use it directly
    # but only the umbrella "EPC" should be used in the future
    if 'EPC-96' in par:
        par['EPC'] = par['EPC-96']

    #logger.debugfast('par=%s', par)
    return par, ''


Param_struct['TagReportData'] = {
    'type': 240,
    'o_fields': [
        'EPC',
        'EPC-96',
        'ROSpecID',
        'SpecIndex',
        'InventoryParameterSpecID',
        'AntennaID',
        'PeakRSSI',
        'ChannelIndex',
        'FirstSeenTimestampUTC',
        'FirstSeenTimestampUptime',
        'LastSeenTimestampUTC',
        'LastSeenTimestampUptime',
        'TagSeenCount',
        # AirProtocolTagDataParameter
        'C1G2CRC',
        'C1G2PC',
        # protocol v2 (llrp 1_1)
        'C1G2XPCW1',
        'C1G2XPCW2',
        # End of AirProtocolTagDataParameter
        'AccessSpecID',
        'C1G2ReadOpSpecResult',
        'C1G2WriteOpSpecResult',
        'C1G2KillOpSpecResult',
        'C1G2RecommissionOpSpecResult',
        'C1G2LockOpSpecResult',
        'C1G2BlockEraseOpSpecResult',
        'C1G2BlockWriteOpSpecResult',
        'C1G2BlockPermalockOpSpecResult',
        'C1G2GetBlockPermalockStatusOpSpecResult',
        ## Custom parameters:
        'ImpinjRFPhaseAngle',
        'ImpinjPeakRSSI',
        'ImpinjRFDopplerFrequency',
        'ImpinjSerializedTID',
        'ImpinjGPSCoordinates',
        'ImpinjTxPower',
    ],
    'decode': decode_TagReportData
}


# handle any of the C1G2*OpSpecResult types

def decode_basic_OpSpecResult(data, name=None):
    par = {}
    if name:
        logger.debugfast('decode_%s', name)

    # all OpSpecResults begin with Result and OpSpecID
    par['Result'], par['OpSpecID'] = \
        ubyte_ushort_unpack(data[:ubyte_ushort_size])
    data = data[ubyte_ushort_size:]
    return par, data


def decode_C1G2ReadOpSpecResult(data, name=None):
    par, data = decode_basic_OpSpecResult(data, 'C1G2ReadOpSpecResult')

    wordcnt = ushort_unpack(data[:ushort_size])[0]
    par['ReadDataWordCount'] = wordcnt
    end = ushort_size + (wordcnt * 2)
    par['ReadData'] = data[ushort_size:end]

    return par, ''


def decode_C1G2WriteOpSpecResult(data, name=None):
    par, data = decode_basic_OpSpecResult(data, 'C1G2WriteOpSpecResult')

    par['NumWordsWritten'] = ushort_unpack(data[:ushort_size])[0]

    return par, ''


def decode_C1G2GetBlockPermalockStatusOpSpecResult(data, name=None):
    par, data = decode_basic_OpSpecResult(
        data, 'C1G2GetBlockPermalockStatusOpSpecResult')

    wordcnt = ushort_unpack(data[:ushort_size])[0]
    par['StatusWordCount'] = wordcnt
    end = ushort_size + (wordcnt * 2)
    par['PermalockStatus'] = data[ushort_size:end]

    return par, ''


Param_struct['C1G2ReadOpSpecResult'] = {
    'type': 349,
    'fields': [
        'Result',
        'OpSpecID',
        'ReadDataWordCount',
        'ReadData'
    ],
    'decode': decode_C1G2ReadOpSpecResult
}

Param_struct['C1G2WriteOpSpecResult'] = {
    'type': 350,
    'fields': [
        'Result',
        'OpSpecID',
        'NumWordsWritten'
    ],
    'decode': decode_C1G2WriteOpSpecResult
}

Param_struct['C1G2KillOpSpecResult'] = {
    'type': 351,
    'fields': [
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2RecommissionOpSpecResult'] = {
    'type': 360,
    'fields': [
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2LockOpSpecResult'] = {
    'type': 352,
    'fields': [
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2BlockEraseOpSpecResult'] = {
    'type': 353,
    'fields': [
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2BlockWriteOpSpecResult'] = {
    'type': 354,
    'fields': [
        'Result',
        'OpSpecID',
        'NumWordsWritten'
    ],
    'decode': decode_C1G2WriteOpSpecResult
}

Param_struct['C1G2BlockPermalockOpSpecResult'] = {
    'type': 361,
    'fields': [
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2GetBlockPermalockStatusOpSpecResult'] = {
    'type': 362,
    'fields': [
        'Result',
        'OpSpecID',
        'StatusWordCount',
        'PermalockStatus'
    ],
    'decode': decode_C1G2GetBlockPermalockStatusOpSpecResult
}


# 16.2.7.3.1 EPCData Parameter
def decode_EPCData(data, name=None):
    #EPC_length_bits = ushort_unpack(data[0:ushort_size])[0]
    # Skip length
    return hexlify(data[ushort_size:]), ''


Param_struct['EPC'] = {
    'type': 241,
    'fields': [
    ],
    'decode': decode_EPCData
}


# 16.2.7.3.2 EPC-96 Parameter
def decode_EPC96(data, name=None):
    # (EPC-96 bits) (96 // 8) = 12 bytes
    data = data[:12]
    return hexlify(data), ''


Param_struct['EPC-96'] = {
    'type': 13,
    'tv_encoded': True,
    'fields': [
    ],
    'decode': decode_EPC96,
}


Param_struct['C1G2SingulationDetails'] = {
    'type': 18,
    'tv_encoded': True,
    'fields': [
        'NumCollisionSlots',
        'NumEmptySlots',
    ],
    'encode': basic_param_encode_generator(ushort_ushort_pack,
                                           'NumCollisionSlots',
                                           'NumEmptySlots'),
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           'NumCollisionSlots',
                                           'NumEmptySlots')
}


# 16.2.7.6.1 HoppingEvent Parameter
Param_struct['HoppingEvent'] = {
    'type': 247,
    'fields': [
        'HopTableID',
        'NextChannelIndex'
    ],
    'encode': basic_param_encode_generator(ushort_ushort_pack,
                                           'HopTableID', 'NextChannelIndex'),
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           'HopTableID', 'NextChannelIndex')
}


# 16.2.7.6.2 GPIEvent Parameter
def encode_GPIEvent(par, param_info):
    gpievent = (par['GPIEvent'] and 1 or 0) << 7
    return ushort_ubyte_pack(par['GPIPortNumber'], gpievent)


# 16.2.7.6.2 GPIEvent Parameter
def decode_GPIEvent(data, name=None):
    logger.debugfast('decode_GPIEvent')
    par = {}

    par['GPIPortNumber'], flags = ushort_ubyte_unpack(data)
    par['GPIEvent'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['GPIEvent'] = {
    'type': 248,
    'fields': [
        'GPIPortNumber',
        'GPIEvent'
    ],
    'encode': encode_GPIEvent,
    'decode': decode_GPIEvent
}


# 16.2.7.6.3 ROSpecEvent Parameter
def encode_ROSpecEvent(par, param_info):
    events = {'Start_of_ROSpec': 0, 'End_of_ROSpec': 1, 'Preemption_of_ROSpec': 2}
    event_type = events.get(par['EventType'])
    if event_type is None:
        raise LLRPError('Error encode_ROSpecEvent unknown value for EventType')
    return ubyte_uint_uint_pack(event_type, par['ROSpecID'], par['PreemptingROSpecID'])


# 16.2.7.6.3 ROSpecEvent Parameter
def decode_ROSpecEvent(data, name=None):
    logger.debugfast('decode_ROSpecEvent')
    par = {}

    (event_type,
     par['ROSpecID'],
     par['PreemptingROSpecID']) = ubyte_uint_uint_unpack(data)

    if event_type == 0:
        par['EventType'] = 'Start_of_ROSpec'
    elif event_type == 1:
        par['EventType'] = 'End_of_ROSpec'
    else:
        par['EventType'] = 'Preemption_of_ROSpec'

    return par, ''


Param_struct['ROSpecEvent'] = {
    'type': 249,
    'fields': [
        'EventType',
        'ROSpecID',
        'PreemptingROSpecID'
    ],
    'encode': encode_ROSpecEvent,
    'decode': decode_ROSpecEvent
}


Param_struct['ReportBufferLevelWarning'] = {
    'type': 250,
    'fields': [
        'ReportBufferPercentageFull'
    ],
    'encode': basic_param_encode_generator(ubyte_pack,
                                           'ReportBufferPercentageFull'),
    'decode': basic_param_decode_generator(ubyte_unpack,
                                           'ReportBufferPercentageFull')
}


Param_struct['ReportBufferOverflowErrorEvent'] = {
    'type': 251,
    'fields': [
    ],
    'encode': basic_param_encode_generator(),
    'decode': decode_all_parameters
}


def encode_ReaderExceptionEvent(par, param_info):
    message = par['Message']
    # Message is expected to already be a "byte" string
    data = ushort_pack(len(message))
    data += par['Message']
    return encode_all_parameters(par, param_info, data)


def decode_ReaderExceptionEvent(data, name=None):
    logger.debugfast('decode_ReaderExceptionEvent')

    offset = ushort_size
    msg_bytecount = ushort_unpack(data[:offset])[0]
    par = {
        'Message': data[offset:offset + msg_bytecount]
    }
    data = data[offset + msg_bytecount:]

    par, _ = decode_all_parameters(data, 'ReaderExceptionEvent', par)
    return par, ''


Param_struct['ReaderExceptionEvent'] = {
    'type': 252,
    'fields': [
        'MessageByteCount',
        'Message',
    ],
    'o_fields': [
        'ROSpecID',
        'SpecIndex',
        'InventoryParameterSpec',
        'AntennaID',
        'AccessSpecID',
        'OpSpecID',
        # Optional N custom parameters after
        'ImpinjHubConfiguration'
    ],
    'encode': encode_ReaderExceptionEvent,
    'decode': decode_ReaderExceptionEvent
}


def encode_RFSurveyEvent(par, param_info):
    events = {'Start_of_RFSurvey': 0, 'End_of_RFSurvey': 1}
    event_type = events.get(par['EventType'])
    if event_type is None:
        raise LLRPError('Error encode_RFSurveyEvent unknown value for EventType')
    return ubyte_uint_ushort_pack(event_type, par['ROSpecID'], par['SpecIndex'])


def decode_RFSurveyEvent(data, name=None):
    logger.debugfast('decode_RFSurveyEvent')
    par = {}

    (event_type,
     par['ROSpecID'],
     par['SpecIndex']) = ubyte_uint_ushort_unpack(data)

    if event_type == 0:
        par['EventType'] = 'Start_of_RFSurvey'
    else:
        par['EventType'] = 'End_of_RFSurvey'

    return par, ''


Param_struct['RFSurveyEvent'] = {
    'type': 253,
    'fields': [
        'EventType',
        'ROSpecID',
        'SpecIndex'
    ],
    'encode': encode_RFSurveyEvent,
    'decode': decode_RFSurveyEvent
}


def encode_AISpecEvent(par, param_info):
    # Ignore EventType and hardcode it to 0 as "End_of_AISpec" is the only
    # possible event.
    data = ubyte_uint_ushort_pack(0, par['ROSpecID'], par['SpecIndex'])
    return encode_all_parameters(par, param_info, data)


def decode_AISpecEvent(data, name=None):
    logger.debugfast('decode_AISpecEvent')
    par = {}

    (_,
     par['ROSpecID'],
     par['SpecIndex']) = ubyte_uint_ushort_unpack(data)
    offset = ubyte_uint_ushort_size
    data = data[offset:]

    # first parameter (event_type) is ignored as just a single value is
    # possible.
    par['EventType'] = 'End_of_AISpec'

    par, _ = decode_all_parameters(data, 'AISpecEvent', par)

    return par, ''


Param_struct['AISpecEvent'] = {
    'type': 254,
    'fields': [
        'EventType',
        'ROSpecID',
        'SpecIndex',
    ],
    'o_fields': [
        'C1G2SingulationDetails'
    ],
    'encode': encode_AISpecEvent,
    'decode': decode_AISpecEvent
}


# 16.2.7.6.9 AntennaEvent Parameter
def encode_AntennaEvent(par, param_info):
    events = {'Disconnected': 0, 'Connected': 1}
    event_type = events.get(par['EventType'])
    if event_type is None:
        raise LLRPError('Error encode_AntennaEvent unknown value for EventType')
    return ubyte_ushort_pack(event_type, par['AntennaID'])


# 16.2.7.6.9 AntennaEvent Parameter
def decode_AntennaEvent(data, name=None):
    logger.debugfast('decode_AntennaEvent')
    par = {}

    event_type, par['AntennaID'] = ubyte_ushort_unpack(data)
    par['EventType'] = event_type and 'Connected' or 'Disconnected'

    return par, ''


Param_struct['AntennaEvent'] = {
    'type': 255,
    'fields': [
        'EventType',
        'AntennaID'
    ],
    'encode': encode_AntennaEvent,
    'decode': decode_AntennaEvent
}


# 16.2.7.6.10 ConnectionAttemptEvent Parameter
def encode_ConnectionAttemptEvent(par, param_info):
    status = ConnEvent_Name2Type[par['Status']]
    return ushort_pack(status)


# 16.2.7.6.10 ConnectionAttemptEvent Parameter
def decode_ConnectionAttemptEvent(data, name=None):
    logger.debugfast('decode_ConnectionAttemptEvent')
    par = {}

    # Decode fields
    status = ushort_unpack(data)[0]
    par['Status'] = ConnEvent_Type2Name[status]

    return par, ''


Param_struct['ConnectionAttemptEvent'] = {
    'type': 256,
    'fields': [
        'Status'
    ],
    'encode': encode_ConnectionAttemptEvent,
    'decode': decode_ConnectionAttemptEvent
}


Param_struct['ConnectionCloseEvent'] = {
    'type': 257,
    'fields': [
    ],
    'encode': basic_param_encode_generator(),
    'decode': decode_all_parameters
}


# Only available with protocol v2 (llrp 1_1)
Param_struct['SpecLoopEvent'] = {
    'type': 356,
    'fields': [
        'ROSpecID',
        'LoopCount'
    ],
    'encode': basic_param_encode_generator(uint_uint_pack,
                                           'ROSpecID', 'LoopCount'),
    'decode': basic_param_decode_generator(uint_uint_unpack,
                                           'ROSpecID', 'LoopCount')
}


# 16.2.7.6 ReaderEventNotificationData Parameter

Param_struct['ReaderEventNotificationData'] = {
    'type': 246,
    'o_fields': [
        'UTCTimestamp', # Either UTCTimestamp or Uptime but not both at the same time
        'Uptime',
        'HoppingEvent',
        'GPIEvent',
        'ROSpecEvent',
        'ReportBufferLevelWarningEvent',
        'ReportBufferOverflowErrorEvent',
        'ReaderExceptionEvent',
        'RFSurveyEvent',
        'AISpecEvent',
        'AntennaEvent',
        'ConnectionAttemptEvent',
        'ConnectionCloseEvent',
        'SpecLoopEvent',
        'ImpinjAntennaAttemptEvent',
    ],
    'encode': encode_all_parameters,
    'decode': decode_all_parameters
}


# 16.2.8.1 LLRPStatus Parameter
def decode_LLRPStatus(data, name=None):
    #if is_general_debug_enabled():
    #    logger.debugfast('decode_LLRPStatus: %s', hexlify(data))
    par = {}

    offset = ushort_ushort_size
    code, n = ushort_ushort_unpack(data[:offset])
    try:
        par['StatusCode'] = Error_Type2Name[code]
    except KeyError:
        logger.warning('Unknown Status code %s', code)
    par['ErrorDescription'] = data[offset:offset + n]

    data = data[offset + n:]
    par, _ = decode_all_parameters(data, 'LLRPStatus', par)

    return par, ''


Param_struct['LLRPStatus'] = {
    'type': 287,
    'fields': [
        'StatusCode',
        'ErrorDescription',
    ],
    'o_fields':  [
        'FieldError',
        'ParameterError'
    ],
    'decode': decode_LLRPStatus
}


# 16.2.8.1.1 FieldError Parameter
def decode_FieldError(data, name=None):
    field_num, err_code = ushort_ushort_unpack(data)

    par = {'FieldNum': field_num}

    try:
        par['ErrorCode'] = Error_Type2Name[int(err_code)]
    except KeyError:
        logger.warning('Unknown Error code %s', err_code)
        par['ErrorCode'] = err_code

    return par, ''

Param_struct['FieldError'] = {
    'type': 288,
    'fields': [
        'FieldNum',
        'ErrorCode',
    ],
    'decode': decode_FieldError
}


# 16.2.8.1.2 ParameterError Parameter
def decode_ParameterError(data, name=None):
    par = {}
    par_type, par_errcode = ushort_ushort_unpack(data[:ushort_ushort_size])

    # Param type that caused this error 0 - 1023.
    # Custom params are ignored by the spec, they will have type 1023
    if par_type != 1023:
        par['ParameterType'] = Param_Type2Name.get((par_type, 0, 0), par_type)
    else:
        par['ParameterType'] = 'CustomParameter'

    try:
        par['ErrorCode'] = Error_Type2Name[int(par_errcode)]
    except KeyError:
        logger.warning('Unknown Error code %s', par_errcode)
        par['ErrorCode'] = par_errcode

    data = data[ushort_ushort_size:]
    if data:
        par, _ = decode_all_parameters(data, 'ParameterError', par)
    return par, ''

Param_struct['ParameterError'] = {
    'type': 289,
    'fields': [
        'ParameterType',
        'ErrorCode',
    ],
    'o_fields': [
        'FieldError',
        'ParameterError'
    ],
    'decode': decode_ParameterError
}


def encode_CustomMessage(msg, param_info):
    # To encode a custom_message directly, data in bytesstring is expected
    # directly as Payload
    data = msg.get('Payload', b'')
    if is_general_debug_enabled():
        logger.debugfast('Encoding custom message data: %s', hexlify(data))
    return data


Message_struct['CUSTOM_MESSAGE'] = {
    'type': TYPE_CUSTOM,
    'fields': [
        'ID',
        'VendorID',
        'Subtype',
        'Payload',
    ],
    'encode': encode_CustomMessage,
    'decode': decode_generic_message
}


def encode_CustomParameter(par, param_info):
    # To encode a CustomParameter directly, data in bytesstring is expected
    # directly as Payload
    data = par.get('Payload', b'')
    if is_general_debug_enabled():
        logger.debugfast('Encoding custom parameter data: %s', hexlify(data))
    return data


Param_struct['CustomParameter'] = {
    'type': TYPE_CUSTOM,
    'fields': [
        'VendorID',
        'Subtype',
        'Payload'
    ],
    'encode': encode_CustomParameter
}


#
# Vendor custom parameters and messages
#


def encode_ImpinjEnableExtensions(msg, msg_info):
    # There is a 32bits reserved field for this message payload
    return uint_pack(0)


Message_struct['IMPINJ_ENABLE_EXTENSIONS'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 21,
    'fields': [
        'reserved',
    ],
    'encode': encode_ImpinjEnableExtensions
}


Param_struct['ImpinjRequestedData'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 21,
    'fields': [
        'RequestedData'
    ],
    'encode': basic_param_encode_generator(uint_pack, 'RequestedData')
}

Message_struct['IMPINJ_ENABLE_EXTENSIONS_RESPONSE'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 22,
    'fields': [
        'ID',
    ],
    'o_fields': [
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


Param_struct['ImpinjSubRegulatoryRegion'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 22,
    'fields': [
        'RegulatoryRegion',
    ],
    'decode': basic_param_decode_generator(ushort_unpack,
                                           'RegulatoryRegion')
}


Param_struct['ImpinjInventorySearchMode'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 23,
    'fields': [
        'InventorySearchMode'
    ],
    'encode': basic_auto_param_encode_generator(ushort_pack,
                                                'InventorySearchMode'),
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ushort_size,
                                                'InventorySearchMode')
}


def encode_ImpinjFixedFrequencyList(par, param_info):
    channel_list = par.get('ChannelList', [])
    count = len(channel_list)

    # Real parameters are:
    # FixedFrequencyMode, Reserved, ChannelListCount, ChannelListIndex #n
    data = [ushort_ushort_ushort_pack(par['FixedFrequencyMode'], 0, count)]

    for index in channel_list:
        data.append(ushort_pack(index))
    return encode_all_parameters(par, param_info, b''.join(data))


def decode_ImpinjFixedFrequencyList(data, name=None):
    logger.debugfast('decode_ImpinjFixedFrequencyList')
    par = {}

    (par['FixedFrequencyMode'], _, channel_count) = \
        ushort_ushort_ushort_unpack(data[:ushort_ushort_ushort_size])

    channel_count = int(channel_count)
    par['ChannelList'] = []
    for x in range(0, channel_count):
        start_pos = ushort_ushort_ushort_size + x * ushort_size
        par['ChannelListIndex'].append(
            ushort_unpack(data[start_pos:start_pos + ushort_size])[0])

    return par, ''


Param_struct['ImpinjFixedFrequencyList'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 26,
    'fields': [
        'FixedFrequencyMode',
        'Reserved',
        'ChannelList'
    ],
    'encode': encode_ImpinjFixedFrequencyList,
    'decode': decode_ImpinjFixedFrequencyList
}


def decode_ImpinjReducedPowerFrequencyList(data, name=None):
    logger.debugfast('decode_ImpinjReducedPowerFrequencyList')
    par = {}

    (par['ReducedPowerMode'], _, channel_count) = \
        ushort_ushort_ushort_unpack(data[:ushort_ushort_ushort_size])

    channel_count = int(channel_count)
    par['ReducedPowerChannelList'] = []

    for x in range(0, channel_count):
        start_pos = ushort_ushort_ushort_size + x * ushort_size
        par['ReducedPowerChannelList'].append(
            ushort_unpack(data[start_pos:start_pos + ushort_size])[0])

    return par, ''


Param_struct['ImpinjReducedPowerFrequencyList'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 27,
    'fields': [
        'ReducedPowerMode',
        'ReducedPowerChannelList',
    ],
    'decode': decode_ImpinjReducedPowerFrequencyList
}


Param_struct['ImpinjLowDutyCycle'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 28,
    'fields': [
        'LowDutyCycleMode',
        'EmptyFieldTimeout',
        'FieldPingInterval'
    ],
    'decode': basic_auto_param_decode_generator(ushort_ushort_ushort_unpack,
                                                ushort_ushort_ushort_size,
                                                'LowDutyCycleMode',
                                                'EmptyFieldTimeout',
                                                'FieldPingInterval')
}


def decode_ImpinjDetailedVersion(data, name=None):
    logger.debugfast('decode_ImpinjDetailedVersion')
    par = {}

    offset = 0
    for field in ['ModelName', 'SerialNumber', 'SoftwareVersion',
                  'FirmwareVersion', 'FPGAVersion', 'PCBAVersion']:
        byte_count = ushort_unpack(data[offset:offset + ushort_size])[0]
        offset += ushort_size
        par[field] = data[offset:offset + byte_count]
        offset += byte_count

    data = data[offset:]
    par, _ = decode_all_parameters(data, 'ImpinjDetailedVersion', par)
    return par, ''


Param_struct['ImpinjDetailedVersion'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 29,
    'fields': [
        'ModelName',
        'SerialNumber',
        'SoftwareVersion',
        'FirmwareVersion',
        'FPGAVersion',
        'PCBAVersion',
    ],
    'o_fields': [
        'ImpinjHubVersions',
        'ImpinjArrayVersion',
        'ImpinjBLEVersion',
    ],
    'decode': decode_ImpinjDetailedVersion
}


def decode_ImpinjFrequencyCapabilities(data, name=None):
    logger.debugfast('decode_ImpinjFrequencyCapabilities')
    par = {
        'NumFrequencies': int(ushort_unpack(data[:ushort_size])[0]),
        'FrequencyList': [],
    }

    for x in range(0, par['NumFrequencies']):
        start_pos = ushort_size + x * ushort_size
        par['FrequencyList'].append(
            uint_unpack(data[start_pos:start_pos + uint_size])[0])

    return par, ''


Param_struct['ImpinjFrequencyCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 30,
    'fields': [
        'NumFrequencies',
        'FrequencyList'
    ],
    'decode': decode_ImpinjFrequencyCapabilities
}


Param_struct['ImpinjGPIDebounceConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 36,
    'fields': [
        'GPIPortNum',
        'GPIDebounceTimerMSec',
    ],
    'decode': basic_param_decode_generator(ushort_uint_unpack,
                                           'GPIPortNum',
                                           'GPIDebounceTimerMSec')
}

Param_struct['ImpinjReaderTemperature'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 37,
    'fields': [
        'Temperature',
    ],
    'decode': basic_auto_param_decode_generator(short_unpack,
                                                short_size,
                                                'Temperature')
}


Param_struct['ImpinjLinkMonitorConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 38,
    'fields': [
        'LinkMonitorMode',
        'LinkDownThreshold'
    ],
    'decode': basic_auto_param_decode_generator(ushort_ushort_unpack,
                                                ushort_ushort_size,
                                                'LinkMonitorMode',
                                                'LinkDownThreshold')
}


Param_struct['ImpinjReportBufferConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 39,
    'fields': [
        'ReportBufferMode',
    ],
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ushort_size,
                                                'ReportBufferMode')
}


Param_struct['ImpinjAccessSpecConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 40,
    'o_fields': [
        'ImpinjBlockWriteWordCount',
        'ImpinjOpSpecRetryCount',
        'ImpinjAccessSpecOrdering'
    ],
    'decode': decode_all_parameters
}


Param_struct['ImpinjBlockWriteWordCount'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 41,
    'fields': [
        'WordCount',
    ],
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ushort_size,
                                                'WordCount')
}


Param_struct['ImpinjTagReportContentSelector'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 50,
    'o_fields': [
        'ImpinjEnableSerializedTID',
        'ImpinjEnableRFPhaseAngle',
        'ImpinjEnablePeakRSSI',
        'ImpinjEnableGPSCoordinates',
        'ImpinjEnableOptimizedRead',
        'ImpinjEnableRFDopplerFrequency',
        'ImpinjEnableTxPower'
    ],
    'encode': encode_all_parameters,
    'decode': decode_all_parameters,
}

Param_struct['ImpinjEnableSerializedTID'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 51,
    'fields': [
        'SerializedTIDMode'
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'SerializedTIDMode'),
    'decode': basic_param_decode_generator(ushort_unpack, 'SerializedTIDMode')
}

Param_struct['ImpinjEnableRFPhaseAngle'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 52,
    'fields': [
        'RFPhaseAngleMode'
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'RFPhaseAngleMode'),
    'decode': basic_param_decode_generator(ushort_unpack, 'RFPhaseAngleMode')
}


Param_struct['ImpinjEnablePeakRSSI'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 53,
    'fields': [
        'PeakRSSIMode'
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'PeakRSSIMode'),
    'decode': basic_param_decode_generator(ushort_unpack, 'PeakRSSIMode')
}


Param_struct['ImpinjEnableGPSCoordinates'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 54,
    'fields': [
        'GPSCoordinatesMode'
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'GPSCoordinatesMode'),
    'decode': basic_param_decode_generator(ushort_unpack, 'GPSCoordinatesMode')
}


def decode_ImpinjSerializedTID(data, name=None):
    logger.debugfast('decode_ImpinjSerializedTID')
    par = {
        'TIDWordCount': ushort_unpack(data[:ushort_size])[0]
    }

    wordcnt = int(par['TIDWordCount'])
    if wordcnt:
        par['TID'] = data[ushort_size:ushort_size + (wordcnt * 2)]

    data = data[ushort_size + (wordcnt * 2):]
    par, _ = decode_all_parameters(data, 'ImpinjSerializedTID', par)

    return par, ''


Param_struct['ImpinjSerializedTID'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 55,
    'fields': [
        'TIDWordCount',
        'TID'
    ],
    'decode': decode_ImpinjSerializedTID
}


Param_struct['ImpinjRFPhaseAngle'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 56,
    'fields': [],
    'decode': basic_param_decode_generator(ushort_unpack)
}


Param_struct['ImpinjPeakRSSI'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 57,
    'fields': [],
    'decode': basic_param_decode_generator(short_unpack)
}


Param_struct['ImpinjGPSCoordinates'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 58,
    'fields': [
        'Latitude',
        'Longitude'
    ],
    'decode': basic_auto_param_decode_generator(uint_uint_unpack,
                                                uint_uint_size,
                                                'Latitude', 'Longitude')
}


Param_struct['ImpinjGPSNMEASentences'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 60,
    'o_fields': [
        'ImpinjGGASentence',
        'ImpinjRMCSentence'
    ],
    'decode': decode_all_parameters
}


def decode_ImpinjGGASentence(data, name=None):
    logger.debugfast('decode_ImpinjGGASentence')

    byte_count = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]
    par = {
        'GGASentence': data[ushort_size:ushort_size + byte_count]
    }
    data = data[ushort_size + byte_count:]
    par, _ = decode_all_parameters(data, 'ImpinjGGASentence', par)
    return par, ''


Param_struct['ImpinjGGASentence'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 61,
    'fields': [
        'GGASentence',
    ],
    'decode': decode_ImpinjGGASentence
}


def decode_ImpinjRMCSentence(data, name=None):
    logger.debugfast('decode_ImpinjRMCSentence')

    byte_count = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]
    par = {
        'RMCSentence': data[ushort_size:ushort_size + byte_count]
    }
    data = data[ushort_size + byte_count]
    par, _ = decode_all_parameters(data, 'ImpinjRMCSentence', par)

    return par, ''


Param_struct['ImpinjRMCSentence'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 62,
    'fields': [
        'RMCSentence'
    ],
    'decode': decode_ImpinjRMCSentence
}


Param_struct['ImpinjOpSpecRetryCount'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 63,
    'fields': [
        'RetryCount',
    ],
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ushort_size,
                                                'RetryCount')
}


Param_struct['ImpinjAdvancedGPOConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 64,
    'fields': [
        'GPOPortNum',
        'GPOMode',
        'GPOPulseDurationMSec'
    ],
    'decode': basic_auto_param_decode_generator(ushort_ushort_uint_unpack,
                                                ushort_ushort_uint_size,
                                                'GPOPortNum',
                                                'GPOMode',
                                                'GPOPulseDurationMSec')
}


Param_struct['ImpinjEnableOptimizedRead'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 65,
    'fields': [
        'OptimizedReadMode',
    ],
    'n_fields': [
        'C1G2Read'
    ],
    'encode': basic_auto_param_encode_generator(ushort_pack,
                                                'OptimizedReadMode'),
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ushort_size,
                                                'OptimizedReadMode')
}


# Note: values: 0: FIFO, 1: Ascending
Param_struct['ImpinjAccessSpecOrdering'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 66,
    'fields': [
        'OrderingMode',
    ],
    'decode': basic_param_decode_generator(ushort_unpack, 'OrderingMode')
}


Param_struct['ImpinjEnableRFDopplerFrequency'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 67,
    'fields': [
        'RFDopplerFrequencyMode'
    ],
    'encode': basic_param_encode_generator(ushort_pack,
                                           'RFDopplerFrequencyMode'),
    'decode': basic_param_decode_generator(ushort_unpack,
                                           'RFDopplerFrequencyMode')
}


Param_struct['ImpinjRFDopplerFrequency'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 68,
    'fields': [],
    'decode': basic_param_decode_generator(short_unpack)
}


def decode_ImpinjInventoryConfiguration(data, name=None):
    logger.debugfast('decode_ImpinjInventoryConfiguration')

    flags = ubyte_unpack(data[:ubyte_size])[0]
    par = {
        'EnableAntDwellTimeLimit': flags & BIT(7) == BIT(7),
        'EnableSelectGapClose': flags & BIT(6) == BIT(6)
    }

    data = data[ubyte_size:]
    par, _ = decode_all_parameters(data, 'ImpinjInventoryConfiguration', par)

    return par, ''


Param_struct['ImpinjInventoryConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 69,
    'fields': [
        'EnableAntDwellTimeLimit',
        'EnableSelectGapClose'
    ],
    'decode': decode_ImpinjInventoryConfiguration
}


Param_struct['ImpinjEnableTxPower'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 72,
    'fields': [
        'TxPowerMode'
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'TxPowerMode'),
    'decode': basic_param_decode_generator(ushort_unpack, 'TxPowerMode')
}


Param_struct['ImpinjTxPower'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 73,
    'fields': [],
    'decode': basic_param_decode_generator(ushort_unpack)
}


def decode_ImpinjArrayVersion(data, name=None):
    logger.debugfast('decode_ImpinjArrayVersion')
    par = {}

    offset = 0
    for field in ['SerialNumber', 'FirmwareVersion', 'PCBAVersion']:
        byte_count = ushort_unpack(data[offset:offset + ushort_size])[0]
        offset += ushort_size
        par[field] = data[offset:offset + byte_count]
        offset += byte_count

    data = data[offset:]
    par, _ = decode_all_parameters(data, 'ImpinjArrayVersion', par)
    return par, ''


Param_struct['ImpinjArrayVersion'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1520,
    'fields': [
        'SerialNumber',
        'FirmwareVersion',
        'PCBAVersion',
    ],
    'decode': decode_ImpinjArrayVersion
}


Param_struct['ImpinjAntennaConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1524,
    'o_fields': [
        'ImpinjAntennaEventConfiguration',
        'ImpinjAntennaEventHysteresis',
    ],
    'encode': encode_all_parameters,
    'decode': decode_all_parameters
}


Param_struct['ImpinjAntennaEventHysteresis'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1526,
    'fields': [
        'AntennaEventConnected',
        'AntennaEventDisconnected',
    ],
    'encode': basic_auto_param_encode_generator(ulonglong_ulonglong_pack,
                                                'AntennaEventConnected',
                                                'AntennaEventDisconnected'),
    'decode': basic_auto_param_decode_generator(ulonglong_ulonglong_unpack,
                                                ulonglong_ulonglong_size,
                                                'AntennaEventConnected',
                                                'AntennaEventDisconnected')
}


Param_struct['ImpinjHubVersions'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1537,
    'n_fields': [
        'ImpinjArrayVersion',
    ],
    'encode': encode_all_parameters,
    'decode': decode_all_parameters
}


ImpinjHubConnectedType = {
    0: 'Unknown',
    1: 'Disconnected',
    2: 'Connected'
}


ImpinjHubFaultType = {
    0: 'No_Fault',
    1: 'RF_Power',
    2: 'RF_Power_On_Hub_1',
    3: 'RF_Power_On_Hub_2',
    4: 'RF_Power_On_Hub_3',
    5: 'RF_Power_On_Hub_4',
    6: 'No_Init',
    7: 'Serial_Overflow',
    8: 'Disconnected'
}


def decode_ImpinjHubConfiguration(data, name=None):
    logger.debugfast('decode_ImpinjHubConfiguration')
    par = {}

    par['HubID'], connected, fault = ushort_ushort_ushort_unpack(
        data[:ushort_ushort_ushort_size])

    par['Connected'] = ImpinjHubConnectedType.get(connected,
                                                  ImpinjHubConnectedType[0])
    par['Fault'] = ImpinjHubFaultType.get(fault, ImpinjHubFaultType[0])
    return par, ''


Param_struct['ImpinjHubConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1538,
    'fields': [
        'HubID',
        'Connected',
        'Fault'
    ],
    'decode': decode_ImpinjHubConfiguration
}


def encode_ImpinjIntelligentAntennaManagement(par, param_info):

    enabled_flags = (int(bool(par)) << 7) & 0xff
    return ubyte_pack(enabled_flags)


def decode_ImpinjIntelligentAntennaManagement(data, name=None):
    logger.debugfast('decode_ImpinjIntelligentAntennaManagement')

    flags = ubyte_unpack(data)[0]
    par = {
        'ManagementEnabled': flags & BIT(7) == BIT(7)
    }

    return par, ''


Param_struct['ImpinjIntelligentAntennaManagement'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1554,
    'fields': [
        'ManagementEnabled'
    ],
    'encode': encode_ImpinjIntelligentAntennaManagement,
    'decode': decode_ImpinjIntelligentAntennaManagement
}


def decode_ImpinjTIDParity(data, name=None):
    logger.debugfast('decode_ImpinjTIDParity')

    flags = ushort_unpack(data[:ushort_size])[0]
    par = {
        'ParityError': flags & BIT(15) == BIT(15),
    }

    return par, ''


Param_struct['ImpinjTIDParity'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1566,
    'fields': [
        'ParityError'
    ],
    'decode': decode_ImpinjTIDParity
}


def encode_ImpinjAntennaEventConfiguration(par, param_info):
    enabled_flags = (int(bool(par)) << 7) & 0xff
    return ubyte_pack(enabled_flags)


def decode_ImpinjAntennaEventConfiguration(data, name=None):
    logger.debugfast('decode_ImpinjAntennaEventConfiguration')

    flags = ubyte_unpack(data[:ubyte_size])[0]
    par = {
        'EnableAntennaAttemptNotification': flags & BIT(7) == BIT(7)
    }

    data = data[ubyte_size:]
    par, _ = decode_all_parameters(data, 'ImpinjAntennaEventConfiguration',
                                   par)

    return par, ''


Param_struct['ImpinjAntennaEventConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1576,
    'fields': [
        'EnableAntennaAttemptNotification'
    ],
    'encode': encode_ImpinjAntennaEventConfiguration,
    'decode': decode_ImpinjAntennaEventConfiguration
}


# Missing from the documentation, Impinj Custom Antenna Event Since Octane 5.8
# Fired each time there is an attempt to use an antenna during the inventory
Param_struct['ImpinjAntennaAttemptEvent'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1577,
    'fields': [
        'AntennaID'
    ],
    'encode': basic_param_encode_generator(ushort_pack, 'AntennaID'),
    'decode': basic_param_decode_generator(ushort_unpack, 'AntennaID')
}


def decode_ImpinjBLEVersion(data, name=None):
    logger.debugfast('decode_ImpinjBLEVersion')
    par = {}

    byte_count = ushort_unpack(data[:ushort_size])[0]
    par['FirmwareVersion'] = data[ushort_size:ushort_size + byte_count]
    data = data[ushort_size + byte_count:]

    par, _ = decode_all_parameters(data, 'ImpinjBLEVersion', par)
    return par, ''


Param_struct['ImpinjBLEVersion'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1580,
    'fields': [
        'FirmwareVersion',
    ],
    'decode': decode_ImpinjBLEVersion
}


def decode_ImpinjRFPowerSweep(data, name=None):
    logger.debugfast('decode_ImpinjRFPowerSweep')
    par = {}

    (flags,
     par['MinimumPowerLevel'],
     par['PowerLevelStepSize']) = ubyte_ushort_ushort_unpack(data)
    par['EnableRFPowerSweep'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['ImpinjRFPowerSweep'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1582,
    'fields': [
        'EnableRFPowerSweep',
        'MinimumPowerLevel',
        'PowerLevelStepSize'
    ],
    'decode': decode_ImpinjRFPowerSweep
}


# Custom Zebra Parameters
def decode_MotoGeneralCapabilities(data, name=None):
    logger.debugfast('decode_MotoGeneralCapabilities')

    version, flags = uint_ubyte_unpack(data[:uint_ubyte_size])
    par = {
        'Version': version,
        'CanGetGeneralParams': flags & BIT(7) == BIT(7),
        'CanReportPartNumber': flags & BIT(6) == BIT(6),
        'CanReportRadioVersion': flags & BIT(5) == BIT(5),
        'CanSupportRadioPowerState': flags & BIT(4) == BIT(4),
        'CanSupportRadioTransmitDelay': flags & BIT(3) == BIT(3),
        'CanSupportZebraTrigger': flags & BIT(2) == BIT(2),
    }

    return par, ''


Param_struct['MotoGeneralCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 1,
    'fields': [
        'Version',
        'CanGetGeneralParams',
        'CanReportPartNumber',
        'CanReportRadioVersion',
        'CanSupportRadioPowerState',
        'CanSupportRadioTransmitDelay',
        'CanSupportZebraTrigger',
    ],
    'decode': decode_MotoGeneralCapabilities
}


def decode_MotoAutonomousCapabilities(data, name=None):
    logger.debugfast('decode_MotoAutonomousCapabilities')
    version, flags = uint_ubyte_unpack(data[:uint_ubyte_size])
    par = {
        'Version': version,
        'CanSupportAutonomousMode': flags & BIT(7) == BIT(7)
    }

    return par, ''


Param_struct['MotoAutonomousCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 100,
    'fields': [
        'Version',
        'CanSupportAutonomousMode'
    ],
    'decode': decode_MotoAutonomousCapabilities
}


def decode_MotoAutonomousState(data, name=None):
    logger.debugfast('decode_MotoAutonomousState')

    flags = ubyte_unpack(data[:ubyte_size])[0]
    par = {
        'AutonomousModeState': flags & BIT(7) == BIT(7),
    }

    return par, ''


Param_struct['MotoAutonomousState'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 101,
    'fields': [
        'AutonomousModeState',
    ],
    'decode': decode_MotoAutonomousState
}


def decode_MotoDefaultSpec(data, name=None):
    logger.debugfast('decode_MotoDefaultSpec')

    flags = ubyte_unpack(data[:ubyte_size])[0]

    par = {
        'UseDefaultSpecForAutoMode': flags & BIT(7) == BIT(7),
    }

    par, _ = decode_all_parameters(data[ubyte_size:], 'MotoDefaultSpec', par)
    return par, ''


Param_struct['MotoDefaultSpec'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 102,
    'fields': [
        'UseDefaultSpecForAutoMode',
    ],
    'o_fields': [
        'ROSpec',
    ],
    'n_fields': [
        'AccessSpec'
    ],
    'decode': decode_MotoDefaultSpec
}


def decode_MotoTagEventsGenerationCapabilities(data, name=None):
    logger.debugfast('decode_MotoTagEventsGenerationCapabilities')

    version, flags = uint_ubyte_unpack(data[:uint_ubyte_size])
    par = {
        'Version': version,
        'CanSelectTagEvents': flags & BIT(7) == BIT(7),
        'CanSelectTagReportingFormat': flags & BIT(6) == BIT(6),
        'CanSelectMovingEvent': flags & BIT(5) == BIT(5),
    }

    return par, ''


Param_struct['MotoTagEventsGenerationCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 120,
    'fields': [
        'Version',
        'CanSelectTagEvents',
        'CanSelectTagReportingFormat',
        'CanSelectMovingEvent',
    ],
    'decode': decode_MotoTagEventsGenerationCapabilities
}


# MotoTagEventSelector
mtes_size = struct.calcsize('!BHBHBH')
mtes_unpack = struct.Struct('!BHBHBH').unpack

MotoTagEventSelector_Name2Type = {
    'Never': 0,
    'Immediate': 1,
    'Moderate': 2,
}

MotoTagEventSelector_Type2Name = reverse_dict(MotoTagEventSelector_Name2Type)


def decode_MotoTagEventSelector(data, name=None):
    logger.debugfast("decode_MotoTagEventSelector")

    (
        report_new_tag_event,
        new_tag_event_timeout,
        report_tag_inv_event,
        tag_inv_event_timeout,
        report_tag_visibility_change_event,
        tag_visibility_change_event_timeout,
    ) = mtes_unpack(data[:mtes_size])

    par = {
        'ReportNewTagEvent': MotoTagEventSelector_Type2Name[report_new_tag_event],
        'NewTagEventModeratedTimeout': new_tag_event_timeout,
        'ReportTagInvisibleEvent': MotoTagEventSelector_Type2Name[report_tag_inv_event],
        'TagInvisibleEventModeratedTimeout': tag_inv_event_timeout,
        'ReportTagVisibilityChangeEvent': MotoTagEventSelector_Type2Name[report_tag_visibility_change_event],
        'TagVisibilityChangeEventModeratedTimeout': tag_visibility_change_event_timeout
    }
    return par, ''


Param_struct['MotoTagEventSelector'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 121,
    'fields': [
        'ReportNewTagEvent',
        'NewTagEventModeratedTimeout',
        'ReportTagInvisibleEvent',
        'TagInvisibleEventModeratedTimeout',
        'ReportTagVisibilityChangeEvent',
        'TagVisibilityChangeEventModeratedTimeout',
    ],
    'decode': decode_MotoTagEventSelector
}


def decode_MotoTagEventSelector(data, name=None):
    logger.debugfast("decode_MotoTagEventSelector")

    (
        report_new_tag_event,
        new_tag_event_timeout,
        report_tag_inv_event,
        tag_inv_event_timeout,
        report_tag_visibility_change_event,
        tag_visibility_change_event_timeout,
    ) = mtes_unpack(data[:mtes_size])

    par = {
        'ReportNewTagEvent': MotoTagEventSelector_Type2Name[report_new_tag_event],
        'NewTagEventModeratedTimeout': new_tag_event_timeout,
        'ReportTagInvisibleEvent': MotoTagEventSelector_Type2Name[report_tag_inv_event],
        'TagInvisibleEventModeratedTimeout': tag_inv_event_timeout,
        'ReportTagVisibilityChangeEvent': MotoTagEventSelector_Type2Name[report_tag_visibility_change_event],
        'TagVisibilityChangeEventModeratedTimeout': tag_visibility_change_event_timeout
    }
    return par, ''


# MotoTagReportMode
MotoTagReportMode_Name2Type = {
    'No reporting': 0,
    'Report Notification': 1,
    'Report events': 2,
}

MotoTagReportMode_Type2Name = reverse_dict(MotoTagReportMode_Name2Type)


def decode_MotoTagReportMode(data, name=None):
    logger.debugfast("decode_MotoTagReportMode")

    report_format = ubyte_unpack(data[:ubyte_size])[0]

    par = {
        'ReportFormat': MotoTagReportMode_Type2Name[report_format]
    }

    return par, ''


Param_struct['MotoTagReportMode'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 122,
    'fields': [
        'ReportFormat',
    ],
    'decode': decode_MotoTagReportMode,
}


# MotoFilterCapabilities
def decode_MotoFilterCapabilities(data, name=None):
    logger.debugfast('decode_MotoFilterCapabilities')

    version, flags = uint_ubyte_unpack(data[:uint_ubyte_size])
    par = {
        'Version': version,
        'CanFilterTagsBasedOnRSSI': flags & BIT(7) == BIT(7),
        'CanFilterTagsBasedOnTimeOfDay': flags & BIT(6) == BIT(6),
        'CanFilterTagsBasedOnUTCTimeStamp': flags & BIT(5) == BIT(5),
    }

    return par, ''


Param_struct['MotoFilterCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 200,
    'fields': [
        'Version',
        'CanFilterTagsBasedOnRSSI',
        'CanFilterTagsBasedOnTimeOfDay',
        'CanFilterTagsBasedOnUTCTimeStamp',
    ],
    'decode': decode_MotoFilterCapabilities
}


# MotoFilterList
Param_struct['MotoUTCTimestamp'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 250,
    'fields': [
        'Microseconds',
    ],
    'decode': basic_auto_param_decode_generator(
        ulonglong_unpack,
        ulonglong_size,
        'Microseconds'
    )
}


Param_struct['MotoFilterTimeOfDay'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 251,
    'fields': [
        'Microseconds',
    ],
    'decode': basic_auto_param_decode_generator(
        ulonglong_unpack,
        ulonglong_size,
        'Microseconds'
    )
}

Match_Name2Type = {
    'Within range': 0,
    'Outside range': 1,
    'Greater than lower limit': 2,
    'Lower than upper limit': 3,
}

Match_Type2Name = reverse_dict(Match_Name2Type)


def decode_MotoFilterTimeRange(data, name=None):
    logger.debugfast('decode_MotoFilterTimeRange')

    time_format, match = ubyte_ubyte_unpack(data[:ubyte_ubyte_size])

    par = {
        'TimeFormat': time_format,
        'Match': Match_Type2Name[match]
    }

    par, _ = decode_all_parameters(data[ubyte_ubyte_size:], 'MotoFilterTimeRange', par)
    return par, ''


Param_struct['MotoFilterTimeRange'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 252,
    'fields': [
        'TimeFormat',
        'Match'
    ],
    'n_fields': [
        'MotoFilterTimeFormatChoice'
    ],
    'decode': decode_MotoFilterTimeRange
}


def decode_MotoFilterRSSIRange(data, name=None):
    logger.debugfast("decode_MotoFilterRSSIRange")

    match = ushort_unpack(data[:ushort_size])[0]

    par = {
        'Match': Match_Type2Name[match]
    }

    par, _ = decode_all_parameters(data[ushort_size:], 'MotoFilterRSSIRange', par)
    return par, ''


Param_struct['MotoFilterRSSIRange'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 253,
    'fields': [
        'Match'
    ],
    'n_fields': [
        'PeakRSSI',
    ],
    'decode': decode_MotoFilterRSSIRange
}


RuleType_Name2Type = {
    'Inclusive': 0,
    'Exclusive': 1,
    'Continue': 2,
}

RuleType_Type2Name = reverse_dict(RuleType_Name2Type)


def decode_MotoFilterRule(data, name=None):
    logger.debugfast('decode_MotoFilterRule')

    rule_type = ubyte_unpack(data[:ubyte_size])[0]

    par = {
        'RuleType': RuleType_Type2Name[rule_type],
    }

    par, _ = decode_all_parameters(data[ubyte_size:], 'MotoFilterRule', par)
    return par, ''

Param_struct['MotoFilterRule'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 254,
    'fields': [
        'RuleType',
    ],
    'o_fields': [
        'MotoFilterRSSIRange',
        'MotoFilterTimeRange',
    ],
    'n_fields': [
        'MotoFilterTagList'
    ],
    'decode': decode_MotoFilterRule
}


def decode_MotoFilterList(data, name=None):
    logger.debugfast('decode_MotoFilterList')

    use_filter = uint_unpack(data[:uint_size])[0]

    par = {
        'UseFilter': use_filter & BIT(31) == BIT(31)
    }

    par, _ = decode_all_parameters(data[uint_size:], 'MotoFilterList', par)
    return par, ''


Param_struct['MotoFilterList'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 255,
    'fields': [
        'UseFilter'
    ],
    'n_fields': [
        'MotoFilterRule',
    ],
    'decode': decode_MotoFilterList
}


def decode_MotoFilterTagList(data, name=None):
    logger.debugfast('decode_MotoFilterTagList')

    match = ubyte_unpack(data[:ubyte_size])[0]

    par = {
        'Match': RuleType_Type2Name[match]
    }

    par, _ = decode_all_parameters(data[ubyte_size:], 'MotoFilterTagList', par)
    return par, ''


Param_struct['MotoFilterTagList'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 258,
    'fields': [
        'Match',
    ],
    'n_fields': [
        'EPCData'
    ],
    'decode': decode_all_parameters
}


def decode_MotoPersistenceCapabilities(data, name=None):
    logger.debugfast('decode_MotoPersistenceCapabilities')

    version, flags = uint_ubyte_unpack(data[:uint_ubyte_size])
    par = {
        'Version': version,
        'CanSaveConfiguration': flags & BIT(7) == BIT(7),
        'CanSaveTags': flags & BIT(6) == BIT(6),
        'CanSaveEvents': flags & BIT(5) == BIT(5),
    }

    return par, ''


Param_struct['MotoPersistenceCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 300,
    'fields': [
        'Version',
        'CanSaveConfiguration',
        'CanSaveTags',
        'CanSaveEvents',
    ],
    'decode': decode_MotoPersistenceCapabilities
}


def decode_MotoPersistenceSaveParams(data, name=None):
    logger.debugfast('decode_MotoPersistenceSaveParams')

    flags = ubyte_unpack(data[:ubyte_size])[0]
    par = {
        'SaveConfiguration': flags & BIT(7) == BIT(7),
        'SaveTagData': flags & BIT(6) == BIT(6),
        'SaveTagEventData': flags & BIT(5) == BIT(5),
    }

    return par, ''


Param_struct['MotoPersistenceSaveParams'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 350,
    'fields': [
        'SaveConfiguration',
        'SaveTagData',
        'SaveTagEventData',
    ],
    'decode': decode_MotoPersistenceSaveParams
}


def decode_MotoC1G2LLRPCapabilities(data, name=None):
    logger.debugfast('decode_MotoC1G2LLRPCapabilities')

    version, flags = uint_ubyte_unpack(data[:uint_ubyte_size])
    par = {
        'Version': version,
        'CanSupportBlockPermalock': flags & BIT(7) == BIT(7),
        'CanSupportRecommissioning': flags & BIT(6) == BIT(6),
        'CanWriteUMI': flags & BIT(5) == BIT(5),
        'CanSupportNXPCuxtomCommands': flags & BIT(4) == BIT(4),
        'CanSupportFujitsuCuxtomCommands': flags & BIT(3) == BIT(3),
        'CanSupportG2V2Commands': flags & BIT(2) == BIT(2),
    }

    return par, ''


Param_struct['MotoC1G2LLRPCapabilities'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 400,
    'fields': [
        'Version',
        'CanSupportBlockPermalock',
        'CanSupportRecommissioning',
        'CanWriteUMI',
        'CanSupportNXPCuxtomCommands',
        'CanSupportFujitsuCuxtomCommands',
        'CanSupportG2V2Commands ',
    ],
    'decode': decode_MotoC1G2LLRPCapabilities
}


def decode_MotoCustomCommandOptions(data, name=None):
    logger.debugfast('decode_MotoCustomCommandOptions')

    flags = uint_unpack(data[:uint_size])[0]

    par = {
        'EnableNXPSetAndResetQuietCommands': flags & BIT(31) == BIT(31),
    }

    return par, ''


Param_struct['MotoCustomCommandOptions'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_MOTOROLA,
    'subtype': 466,
    'fields': [
        'EnableNXPSetAndResetQuietCommands ',
    ],
    'decode': decode_MotoCustomCommandOptions
}


def llrp_data2xml(msg):
    if not msg:
        return ''

    def __llrp_data2xml(msg, name, level=0):
        tabs = '\t' * level

        msg_param_struct = Param_struct.get(name)
        if msg_param_struct is None:
            msg_param_struct = Message_struct.get(name)

        # Case 1 - it is asked to decode an unknown or error field
        if msg_param_struct is None:
            ret = ''
            sub = msg
            if not isinstance(sub, list) or not sub or not isinstance(sub[0],
                                                                      dict):
                sub = [sub]
            for e in sub:
                tabs1 = tabs + '\t'
                sub_name = e.get('Name', name)
                decode_error_reason = e.get('DecodeError')
                ret += tabs + '<%s>\n' % DECODE_ERROR_PARNAME
                if sub_name:
                    ret += tabs1 + '<Name>%s</Name>\n' % sub_name
                for k in ('DecodeError', 'Type', 'Data', 'VendorID', 'Subtype'):
                    if k not in e:
                        continue
                    ret += tabs1 + '<%s>%s</%s>\n' % (k, e[k], k)
                ret += tabs + '</%s>\n' % DECODE_ERROR_PARNAME
            return ret


        # Case 2 - The message or param is known
        ret = tabs + '<%s>\n' % name

        fields = msg_param_struct.get('fields', []) + [DECODE_ERROR_PARNAME]
        for p in fields:
            try:
                sub = msg[p]
            except KeyError:
                continue

            if isinstance(sub, dict):
                ret += __llrp_data2xml(sub, p, level + 1)
            elif isinstance(sub, list) and sub and isinstance(sub[0], dict):
                for e in sub:
                    ret += __llrp_data2xml(e, p, level + 1)
            else:
                ret += tabs + '\t<%s>%r</%s>\n' % (p, sub, p)

        ret += tabs + '</%s>\n' % name

        # To check for fields missing in parameter field lists:
        #if is_general_debug_enabled():
        #    for k in msg:
        #        if k in fields:
        #            continue
        #        ret += tabs + '<MissingParameter>%s</MissingParameter>\n' % k

        return ret

    ans = ''
    for name, sub in msg.items():
        if not isinstance(sub, list) or not sub or not isinstance(sub[0], dict):
            sub = [sub]
        for e in sub:
            ans += __llrp_data2xml(e, name)
    return ans[:-1]


class LLRPROSpec(dict):
    def __init__(self, reader_mode, rospecid, priority=0, state='Disabled',
                 antennas=(1,), tx_power=0, duration_sec=None,
                 report_every_n_tags=None, report_timeout_ms=0,
                 tag_content_selector=None, tari=None,
                 session=2, tag_population=4, tag_filter_mask=[],
                 impinj_search_mode=None, impinj_tag_content_selector=None,
                 frequencies=None):
        # Sanity checks
        if rospecid <= 0:
            raise LLRPError('invalid ROSpec message ID {} (need >0)'\
                .format(rospecid))
        if priority < 0 or priority > 7:
            raise LLRPError('invalid ROSpec priority {} (need [0-7])'\
                .format(priority))
        if state not in ROSpecState_Name2Type:
            raise LLRPError('invalid ROSpec state {} (need [{}])'\
                .format(state, ','.join(ROSpecState_Name2Type.keys())))
        # backward compatibility: allow integer tx_power
        if isinstance(tx_power, int):
            tx_power = {antenna: tx_power for antenna in antennas}
        elif isinstance(tx_power, dict):
            # all antennas must be accounted for in tx_power dict
            if set(antennas) != set(tx_power.keys()):
                raise LLRPError('Must set tx_power for all antennas')
        else:
            raise LLRPError('tx_power must be dictionary or integer')

        if frequencies is None:
            frequencies = {}

        # if reader mode settings are specified, pepper them into this ROSpec
        override_tari = None
        if reader_mode is not None:
            if tari is not None and tari < reader_mode['MaxTari']:
                override_tari = tari

            # BUG: Impinj Speedway Revolution readers, and possibly others,
            # seem to want a ModeIdentifier value for the ModeIndex parameter
            # rather than an actual index into the array of modes.
            # https://github.com/ransford/sllurp/issues/63
            mode_index = reader_mode['ModeIdentifier']

        tagReportContentSelector = {
            'EnableROSpecID': True,
            'EnableSpecIndex': False,
            'EnableInventoryParameterSpecID': False,
            'EnableAntennaID': True,
            'EnableChannelIndex': False,
            'EnablePeakRSSI': True,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': False,
            'C1G2EPCMemorySelector': {
                'EnableCRC': False,
                'EnablePCBits': False,
            }
        }
        if tag_content_selector:
            tagReportContentSelector.update(tag_content_selector)

        self.update({
            'ROSpecID': rospecid,
            'Priority': priority,
            'CurrentState': state,
            'ROBoundarySpec': {
                'ROSpecStartTrigger': {
                    'ROSpecStartTriggerType': 'Immediate',
                },
                'ROSpecStopTrigger': {
                    'ROSpecStopTriggerType': 'Null',
                    'DurationTriggerValue': 0,
                },
            },
            'AISpec': [{
                'AntennaID': antennas,
                'AISpecStopTrigger': {
                    'AISpecStopTriggerType': 'Null',
                    'DurationTriggerValue': 0,
                },
                'InventoryParameterSpec': [{
                    'InventoryParameterSpecID': 1,
                    'ProtocolID': AirProtocol['EPCGlobalClass1Gen2'],
                    'AntennaConfiguration': [],
                }],
            }],
            'ROReportSpec': {
                'ROReportTrigger': 'Upon_N_Tags_Or_End_Of_AISpec',
                'TagReportContentSelector': tagReportContentSelector,
                'N': 0,
            },
        })

        if impinj_tag_content_selector:
            self['ROReportSpec']\
                ['ImpinjTagReportContentSelector'] = {
                    'ImpinjEnableRFPhaseAngle': {
                        'RFPhaseAngleMode':
                            impinj_tag_content_selector['EnableRFPhaseAngle'],
                    },
                    'ImpinjEnablePeakRSSI': {
                        'PeakRSSIMode':
                            impinj_tag_content_selector['EnablePeakRSSI'],
                    },
                    'ImpinjEnableRFDopplerFrequency': {
                        'RFDopplerFrequencyMode':
                            impinj_tag_content_selector['EnableRFDopplerFrequency'],
                    },
                }

        ips = self['AISpec'][0]['InventoryParameterSpec'][0]

        freq_channel_list = frequencies.get('ChannelList',
                                            [DEFAULT_CHANNEL_INDEX])
        # patch up per-antenna config
        for antid in antennas:
            transmit_power = tx_power[antid]
            antconf = {
                'AntennaID': antid,
                'RFTransmitter': {
                    'HopTableId': frequencies.get('HopTableId',
                                                  DEFAULT_HOPTABLE_INDEX),
                    'ChannelIndex': freq_channel_list[0],
                    'TransmitPower': transmit_power,
                },
                'C1G2InventoryCommand': [{
                    'TagInventoryStateAware': False,
                    'C1G2SingulationControl': {
                        'Session': session,
                        'TagPopulation': tag_population,
                        'TagTransitTime': 0
                    },
                }]
            }

            # apply one or more tag filters
            tag_filters = []
            # Transform list to set for optimization. So, not setting multiple
            # times the same filter.
            # Note: using more filters than supported by the reader will result
            # in an Overflow error. (Example: 2 filters max with Impinj)
            for tfm in set(tag_filter_mask):
                tag_filters.append({
                    'C1G2TagInventoryMask': {
                        'MB': 1,    # EPC bank
                        'Pointer': 0x20,    # Third word starts the EPC ID
                        'TagMask': tfm
                    }
                })
            if tag_filters:
                antconf['C1G2InventoryCommand'][0]['C1G2Filter'] = tag_filters

            if reader_mode:
                rfcont = {
                    'ModeIndex': mode_index,
                    'Tari': override_tari if override_tari else 0,
                }
                antconf['C1G2InventoryCommand'][0]['C1G2RFControl'] = rfcont

            # impinj extension: single mode or dual mode (XXX others?)
            if impinj_search_mode is not None:
                antconf['C1G2InventoryCommand'][0]\
                    ['ImpinjInventorySearchMode'] = {
                        'InventorySearchMode': int(impinj_search_mode)
                    }

            if frequencies.get('Automatic', False):
                antconf['C1G2InventoryCommand'][0]\
                    ['ImpinjFixedFrequencyList'] = {
                        'FixedFrequencyMode': 1,
                        'ChannelList': []
                    }
            elif len(freq_channel_list) > 1:
                antconf['C1G2InventoryCommand'][0]\
                    ['ImpinjFixedFrequencyList'] = {
                        'FixedFrequencyMode': 2,
                        'ChannelList': freq_channel_list
                    }

            ips['AntennaConfiguration'].append(antconf)

        if duration_sec is not None:
            self['ROBoundarySpec']['ROSpecStopTrigger'] = {
                'ROSpecStopTriggerType': 'Duration',
                'DurationTriggerValue': int(duration_sec * 1000)
            }
            self['AISpec'][0]['AISpecStopTrigger'] = {
                'AISpecStopTriggerType': 'Duration',
                'DurationTriggerValue': int(duration_sec * 1000)
            }

        if report_every_n_tags is not None:
            if report_timeout_ms:
                logger.info('will report every ~N=%d tags or %d ms',
                            report_every_n_tags, report_timeout_ms)
            else:
                logger.info('will report every ~N=%d tags',
                            report_every_n_tags)
            self['AISpec'][0]['AISpecStopTrigger'].update({
                'AISpecStopTriggerType': 'Tag observation',
                'TagObservationTrigger': {
                    'TriggerType': 'UponNTags',
                    'NumberOfTags': report_every_n_tags,
                    'NumberOfAttempts': 0,
                    'T': 0,
                    'Timeout': report_timeout_ms,  # milliseconds
                },
            })

    def __repr__(self):
        return llrp_data2xml({'ROSpec': self})


class LLRPMessageDict(dict):
    def __repr__(self):
        return llrp_data2xml(self)



## Post processing on Message_struct and Param_struct

# Post-processing and Reverse dictionary for Message_struct types
Message_Type2Name = {}
Param_Type2Name = {}
for source_struct, dest_dict, obj_name in [
        (Message_struct, Message_Type2Name, 'Message_struct'),
        (Param_struct, Param_Type2Name, 'Param_struct')]:
    for msgname, msgstruct in iteritems(source_struct):
        vendorid = msgstruct.get('vendorid', 0)
        subtype = msgstruct.get('subtype', 0)

        try:
            msgtype = msgstruct['type']
        except KeyError:
            logger.warning('Pseudo-warning: %s type %s lacks "type" field',
                           obj_name, msgname)
            continue

        if msgtype == TYPE_CUSTOM and (not vendorid or not subtype) \
           and msgname not in ['CUSTOM_MESSAGE', 'CustomParameter']:
            logger.warning('Pseudo-warning: %s type %s lacks "vendorid" or '
                           '"subtype" fields', obj_name, msgname)
            continue

        # Add optional and multiple fields to the full fields list
        fields = msgstruct.setdefault('fields', [])
        # Optional fields:
        o_fields = msgstruct.setdefault('o_fields', [])
        # Multiple entries fields
        n_fields = msgstruct.setdefault('n_fields', [])

        n_fields.append('CustomParameter')

        # fields = fields + optional + multiples
        # if fields = fields + o_fields + n_fields
        fields.extend([x for x in o_fields if x not in fields])
        fields.extend([x for x in n_fields if x not in fields])

        # Field order might be important for some readers
        o_n_ordered_fields = []
        for entry in fields:
            if entry in o_fields:
                o_n_ordered_fields.append((entry, False))
            elif entry in n_fields:
                o_n_ordered_fields.append((entry, True))
        msgstruct['auto_fields'] = o_n_ordered_fields

        # Fill reverse dict
        dest_dict[(msgtype, vendorid, subtype)] = msgname
