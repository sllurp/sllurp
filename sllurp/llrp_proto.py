#!/usr/bin/env python

# llrp_proto.py - LLRP protocol client support
#
# Copyright (C) 2009 Rodolfo Giometti <giometti@linux.it>
# Copyright (C) 2009 CAEN RFID <support.rfid@caen.it>
# Copyright (C) 2013, 2014 Benjamin Ransford <ransford@cs.washington.edu>
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
from .llrp_decoder import (msg_header_decode, param_header_decode,
                           par_vendor_subtype_size, par_vendor_subtype_unpack,
                           TVE_PARAM_FORMATS, TVE_PARAM_TYPE_MAX, TYPE_CUSTOM,
                           VENDOR_ID_IMPINJ)
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
    "msg_header_decode",
    "Param_struct",
]

logger = get_logger(__name__)

#
# Local functions
#


def decode(data):
    """Decode Parameter"""
    return Param_struct[data]['decode']



def encode(data):
    """Encode Parameter"""
    return Param_struct[data]['encode']


#
# LLRP defines & structs
#


VER_PROTO_V1 = 1

DEFAULT_CHANNEL_INDEX = 1
DEFAULT_HOPTABLE_INDEX = 1

DECODE_ERROR_PARNAME = "SllurpDecodeError"


msg_header = '!HII'
msg_header_len = struct.calcsize(msg_header)
msg_header_unpack = struct.Struct(msg_header).unpack

par_header = '!HH'
par_header_len = struct.calcsize(par_header)
par_header_unpack = struct.Struct(par_header).unpack
tve_header = '!B'
tve_header_len = struct.calcsize(tve_header)
tve_header_unpack = struct.Struct(tve_header).unpack

# Common types unpacks
short_size = struct.calcsize('!h')
ubyte_size = struct.calcsize('!B')
ushort_size = struct.calcsize('!H')
uint_size = struct.calcsize('!I')
ubyte_ushort_size = struct.calcsize('!BH')
ubyte_uint_size = struct.calcsize('!BI')
ushort_ubyte_size = struct.calcsize('!HB')
ushort_ushort_size = struct.calcsize('!HH')
ushort_uint_size = struct.calcsize('!HI')
uint_ubyte_size = struct.calcsize('!IB')
uint_uint_size = struct.calcsize('!II')
ubyte_ubyte_ushort_size = struct.calcsize('!BBH')
ubyte_ushort_ushort_size = struct.calcsize('!BHH')
ubyte_ushort_short_size = struct.calcsize('!BHh')
ubyte_ushort_uint_size = struct.calcsize('!BHI')
ubyte_uint_ushort_size = struct.calcsize('!BIH')
ubyte_uint_uint_size = struct.calcsize('!BII')
ushort_ubyte_ubyte_size = struct.calcsize('!HBB')
ushort_ushort_ushort_size = struct.calcsize('!HHH')
ushort_ushort_uint_size = struct.calcsize('!HHI')

short_unpack = struct.Struct('!h').unpack
ubyte_unpack = struct.Struct('!B').unpack
ushort_unpack = struct.Struct('!H').unpack
uint_unpack = struct.Struct('!I').unpack
ulonglong_unpack = struct.Struct('!Q').unpack
ubyte_ushort_unpack = struct.Struct('!BH').unpack
ubyte_uint_unpack = struct.Struct('!BI').unpack
ushort_ubyte_unpack = struct.Struct('!HB').unpack
ushort_ushort_unpack = struct.Struct('!HH').unpack
ushort_uint_unpack = struct.Struct('!HI').unpack
uint_ubyte_unpack = struct.Struct('!IB').unpack
uint_uint_unpack = struct.Struct('!II').unpack
ubyte_ubyte_ushort_unpack = struct.Struct('!BBH').unpack
ubyte_ushort_ushort_unpack = struct.Struct('!BHH').unpack
ubyte_ushort_short_unpack = struct.Struct('!BHh').unpack
ubyte_ushort_uint_unpack = struct.Struct('!BHI').unpack
ubyte_uint_ushort_unpack = struct.Struct('!BIH').unpack
ubyte_uint_uint_unpack = struct.Struct('!BII').unpack
ushort_ubyte_ubyte_unpack = struct.Struct('!HBB').unpack
ushort_ushort_ushort_unpack = struct.Struct('!HHH').unpack
ushort_ushort_uint_unpack = struct.Struct('!HHI').unpack

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
StartTrigger_Name2Type = {
    'Null':                 0,
    'Immediate':                1,
    'Periodic':             2,
    'GPI':                  3
}

StartTrigger_Type2Name = reverse_dict(StartTrigger_Name2Type)

# 10.2.1.1.2 ROSpec Stop trigger
StopTrigger_Name2Type = {
    'Null':                 0,
    'Duration':             1,
    'GPI with timeout':         2,
    'Tag observation':          3
}

StopTrigger_Type2Name = reverse_dict(StopTrigger_Name2Type)

TagObservationTrigger_Name2Type = {
    'UponNTags': 0,
    'UponSilenceMs': 1,
    'UponNAttempts': 2,
    'UponNUniqueTags': 3,
    'UponUniqueSilenceMs': 4,
}

AccessReportTrigger_Name2Type = {
    'Upon_ROReport': 0,
    'Upon_End_Of_AccessSpec': 1
}

AccessReportTrigger_Type2Name = reverse_dict(AccessReportTrigger_Name2Type)

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

for p_type, p_format in iteritems(TVE_PARAM_FORMATS):
    p_name = p_format[0]
    p_unpack_func = p_format[1].unpack
    if not p_name:
        logging.warning('Name is missing for TVE Param %d', p_type)
        continue
    def local_decode(data, p_unpack_func=p_unpack_func):
        return p_unpack_func(data)[0], ''
    p_struct = {
        'type': p_type,
        'tv_encoded': True,
        #'decode': lambda data: (p_unpack_func(data)[0], '')
        'decode': local_decode
    }
    Param_struct[p_name] = p_struct


# Global helpers


def basic_param_decode_generator(unpack_func, sub_list=None):
    """Generate a decode function for simple parameters"""
    if sub_list is None:
        def generated_func(data, name=None):
            unpacked = unpack_func(data)
            return unpacked[0], ''
    else:
        if not isinstance(sub_list, list):
            sub_list = [sub_list]

        def generated_func(data, name=None):
            unpacked = unpack_func(data)
            return dict(zip(sub_list, unpacked)), ''
    return generated_func


def basic_auto_param_decode_generator(unpack_func, unpack_sub_list, unpack_size):
    """Generate a decode function for simple parameters with auto decode

    Generate a function that decode first a set of fixed parameters of size
    unpack_size, using the unpack_func function and then, try to automatically
    decode remaining dynamic parameter objects.
    """
    if not isinstance(unpack_sub_list, list):
            unpack_sub_list = [unpack_sub_list]

    def generated_func(data, name=None):
        unpacked = unpack_func(data[:unpack_size])
        par = dict(zip(unpack_sub_list, unpacked))
        data = data[unpack_size:]
        if data:
            par, _ = decode_all_parameters(data, name, par)
        return par, ''

    return generated_func


def get_message_name_from_type(msgtype, vendorid=0, subtype=0):
    name = Message_Type2Name[(msgtype, vendorid, subtype)]
    return name


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
    decode_func = None

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
            ret, _ = Param_struct[param_name]['decode'](pardata)
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

    return param_name, ret, data[full_length:]


def decode_all_parameters(data, par_name=None, par_dict=None):
    if par_dict is None:
        par_dict = {}
    if par_name:
        logger.debugfast('decode_%s', par_name)

    body = data
    prev_bodylen = len(body)
    while body:
        parname, ret, body = decode_param(body)
        if not parname:
            if ret is None:
                raise LLRPError('Error decoding param. Invalid byte stream.')
            parname = DECODE_ERROR_PARNAME
        prev_val = par_dict.get(parname)
        if prev_val is None:
            par_dict[parname] = ret
        elif isinstance(prev_val, list):
            prev_val.append(ret)
        else:
            par_dict[parname] = [prev_val, ret]

        bodylen = len(body)
        if bodylen >= prev_bodylen:
            logger.error('Loop in parameter body decoding (%d bytes left)',
                         bodylen)
            break

    return par_dict, body


def decode_generic_message(data, msg_name=None, msg=None):
    """Auto decode a standard LLRP message without 'individual' modification"""
    if msg is None:
        msg = LLRPMessageDict()
    msg, _ = decode_all_parameters(data, msg_name, msg)
    return msg


def decode_generic_message_with_status_check(data, msg_name=None):
    """Auto decode a standard LLRP message with check for LLRPStatus"""
    msg = decode_generic_message(data, msg_name)
    if 'LLRPStatus' not in msg:
        raise LLRPError('Missing or invalid LLRPStatus parameter')
    return msg


# 16.1.1 GET_READER_CAPABILITIES
def encode_GetReaderCapabilities(msg):
    req = msg['RequestedData']
    return struct.pack('!B', req)


Message_struct['GET_READER_CAPABILITIES'] = {
    'type': 1,
    'fields': [
        'Ver', 'Type', 'ID',
        'RequestedData'
    ],
    'encode': encode_GetReaderCapabilities
}


# 16.1.2 GET_READER_CAPABILITIES_RESPONSE
Message_struct['GET_READER_CAPABILITIES_RESPONSE'] = {
    'type': 11,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
        'GeneralDeviceCapabilities',
        'LLRPCapabilities',
        'RegulatoryCapabilities',
        'C1G2LLRPCapabilities',
        'ImpinjDetailedVersion',
        'ImpinjFrequencyCapabilities',
        'ImpinjAntennaCapabilities',
        # Decoder not yet implemented:
        'ImpinjxArrayCapabilities'
    ],
    'decode': decode_generic_message_with_status_check
}


# GET_READER_CONFIG
def encode_GetReaderConfig(msg):
    req = msg['RequestedData']
    ant = msg.get('AntennaID', 0)
    gpipn = msg.get('GPIPortNum', 0)
    gpopn = msg.get('GPOPortNum', 0)
    data = struct.pack('!BHHH', req, ant, gpipn, gpopn)

    params = msg.get('CustomParameters', [])
    for param in params:
        data += encode('CustomParameter')(param)

    return data


Message_struct['GET_READER_CONFIG'] = {
    'type': 2,
    'fields': [
        'Ver', 'Type', 'ID',
        'RequestedData',
        'AntennaID',
        'GPIPortNum',
        'GPOPortNum'
    ],
    'encode': encode_GetReaderConfig
}


Message_struct['GET_READER_CONFIG_RESPONSE'] = {
    'type': 12,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
        'Identification',
        'AntennaProperties',
        'AntennaConfiguration',
        'ReaderEventNotificationSpec',
        'ROReportSpec',
        'AccessReportSpec',
        'LLRPConfigurationStateValue',
        'KeepaliveSpec',
        'GPIPortCurrentState',
        'GPOWriteData',
        'EventsAndReports',
        # Optional N custom parameters after
        'ImpinjHubConfiguration',
        'ImpinjLinkMonitorConfiguration',
        'ImpinjSubRegulatoryRegion',
        'ImpinjAdvancedGPOConfiguration',
        'ImpinjAntennaConfiguration',
        'ImpinjAccessSpecConfiguration',
        'ImpinjGPSNMEASentences',
        'ImpinjGPIDebounceConfiguration',
        'ImpinjReaderTemperature',
        'ImpinjReportBufferConfiguration',
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
    'decode': decode_generic_message_with_status_check
}


# SET_READER_CONFIG
def encode_SetReaderConfig(msg):
    reset_flag = int(msg.get('ResetToFactoryDefaults', False))
    reset = (reset_flag << 7) & 0xff
    data = struct.pack('!B', reset)
    if 'ROReportSpec' in msg:
        data += encode('ROReportSpec')(msg['ROReportSpec'])
    if 'ReaderEventNotificationSpec' in msg:
        data += encode('ReaderEventNotificationSpec')(
            msg['ReaderEventNotificationSpec'])
    if 'ImpinjAntennaConfiguration' in msg:
        data += encode('ImpinjAntennaConfiguration')(
            msg['ImpinjAntennaConfiguration'])
    # XXX other params
    return data


Message_struct['SET_READER_CONFIG'] = {
    'type': 3,
    'fields': [
        'Ver', 'Type', 'ID',
        'ResetToFactoryDefaults',
        'ReaderEventNotificationSpec',
        'AntennaProperties',
        'AntennaConfiguration',
        'ROReportSpec',
        'AccessReportSpec',
        'KeepaliveSpec',
        'GPOWriteData',
        'GPIPortCurrentState',
        'EventsAndReports',
        'ImpinjAntennaConfiguration',
    ],
    'encode': encode_SetReaderConfig,
}


Message_struct['SET_READER_CONFIG_RESPONSE'] = {
    'type': 13,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


# ENABLE_EVENTS_AND_REPORTS
def encode_EnableEventsAndReports(msg):
    return b''


Message_struct['ENABLE_EVENTS_AND_REPORTS'] = {
    'type': 64,
    'fields': [
        'Ver', 'Type', 'ID',
    ],
    'encode': encode_EnableEventsAndReports
}


# 16.1.3 ADD_ROSPEC
def encode_AddROSpec(msg):
    return encode('ROSpec')(msg['ROSpec'])


Message_struct['ADD_ROSPEC'] = {
    'type': 20,
    'fields': [
        'Ver', 'Type', 'ID',
        'ROSpec'
    ],
    'encode': encode_AddROSpec
}


# 16.1.4 ADD_ROSPEC_RESPONSE
Message_struct['ADD_ROSPEC_RESPONSE'] = {
    'type': 30,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.5 DELETE_ROSPEC
def encode_DeleteROSpec(msg):
    msgid = msg['ROSpecID']

    return struct.pack('!I', msgid)


Message_struct['DELETE_ROSPEC'] = {
    'type': 21,
    'fields': [
        'Ver', 'Type', 'ID',
        'ROSpecID'
    ],
    'encode': encode_DeleteROSpec
}


# 16.1.6 DELETE_ROSPEC_RESPONSE
Message_struct['DELETE_ROSPEC_RESPONSE'] = {
    'type': 31,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.7 START_ROSPEC
def encode_StartROSpec(msg):
    msgid = msg['ROSpecID']

    return struct.pack('!I', msgid)


Message_struct['START_ROSPEC'] = {
    'type': 22,
    'fields': [
        'Ver', 'Type', 'ID',
        'ROSpecID'
    ],
    'encode': encode_StartROSpec
}


# 16.1.8 START_ROSPEC_RESPONSE
Message_struct['START_ROSPEC_RESPONSE'] = {
    'type': 32,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.9 STOP_ROSPEC
def encode_StopROSpec(msg):
    msgid = msg['ROSpecID']

    return struct.pack('!I', msgid)


Message_struct['STOP_ROSPEC'] = {
    'type': 23,
    'fields': [
        'Ver', 'Type', 'ID',
        'ROSpecID'
    ],
    'encode': encode_StopROSpec
}


# 16.1.10 STOP_ROSPEC_RESPONSE
Message_struct['STOP_ROSPEC_RESPONSE'] = {
    'type': 33,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
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
        'Ver', 'Type', 'ID',
        'ROSpecID'
    ],
    'encode': encode_EnableROSpec
}


# 16.1.12 ENABLE_ROSPEC_RESPONSE
Message_struct['ENABLE_ROSPEC_RESPONSE'] = {
    'type': 34,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.1.13 DISABLE_ROSPEC
def encode_DisableROSpec(msg):
    msgid = msg['ROSpecID']

    return struct.pack('!I', msgid)


Message_struct['DISABLE_ROSPEC'] = {
    'type': 25,
    'fields': [
        'Ver', 'Type', 'ID',
        'ROSpecID'
    ],
    'encode': encode_DisableROSpec
}


# 16.1.14 DISABLE_ROSPEC_RESPONSE
Message_struct['DISABLE_ROSPEC_RESPONSE'] = {
    'type': 35,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


def decode_ROAccessReport(data, msg_name=None):
    msg = LLRPMessageDict()
    # Ensure that there is always a TagReportData, even empty
    msg['TagReportData'] = []
    msg = decode_generic_message(data, msg_name, msg)
    return msg

Message_struct['RO_ACCESS_REPORT'] = {
    'type': 61,
    'fields': [
        'Ver', 'Type', 'ID',
        'TagReportData',
    ],
    'decode': decode_ROAccessReport
}


# 16.1.35 KEEPALIVE
Message_struct['KEEPALIVE'] = {
    'type': 62,
    'fields': [
        'Ver', 'Type', 'ID',
    ],
    'decode': decode_generic_message
}


# 16.1.36 KEEPALIVE_ACK
def encode_KeepaliveAck(msg):
    return b''


Message_struct['KEEPALIVE_ACK'] = {
    'type': 72,
    'fields': [
        'Ver', 'Type', 'ID',
    ],
    'encode': encode_KeepaliveAck
}


# 16.1.33 READER_EVENT_NOTIFICATION
Message_struct['READER_EVENT_NOTIFICATION'] = {
    'type': 63,
    'fields': [
        'Ver', 'Type', 'ID',
        'ReaderEventNotificationData'
    ],
    'decode': decode_generic_message
}


# 16.1.40 CLOSE_CONNECTION
def encode_CloseConnection(msg):
    return b''


Message_struct['CLOSE_CONNECTION'] = {
    'type': 14,
    'fields': [
        'Ver', 'Type', 'ID',
    ],
    'encode': encode_CloseConnection
}


# 16.1.41 CLOSE_CONNECTION_RESPONSE
Message_struct['CLOSE_CONNECTION_RESPONSE'] = {
    'type': 4,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.2.2.1 UTCTimestamp Parameter

def encode_UTCTimestamp(par):
    msgtype = Param_struct['UTCTimestamp']['type']
    msg = '!HHQ'
    msg_len = struct.calcsize(msg_header)
    data = struct.pack(msg, msgtype, msg_len, par['Microseconds'])
    return data


Param_struct['UTCTimestamp'] = {
    'type': 128,
    'fields': [
        'Type',
        'Microseconds'
    ],
    'decode': basic_param_decode_generator(ulonglong_unpack, ['Microseconds']),
    'encode': encode_UTCTimestamp,
}


Param_struct['RegulatoryCapabilities'] = {
    'type': 143,
    'fields': [
        'Type',
        'CountryCode',
        'CommunicationsStandard',
        'UHFBandCapabilities'
    ],
    'decode': basic_auto_param_decode_generator(ushort_ushort_unpack,
                                                ['CountryCode',
                                                 'CommunicationsStandard'],
                                                ushort_ushort_size)
}


Param_struct['UHFBandCapabilities'] = {
    'type': 144,
    'fields': [
        'Type',
        'TransmitPowerLevelTableEntry',
        'FrequencyInformation',
        'UHFC1G2RFModeTable',
        'RFSurveyFrequencyCapabilities'
    ],
    'decode': decode_all_parameters
}


Param_struct['TransmitPowerLevelTableEntry'] = {
    'type': 145,
    'fields': [
        'Type',
        'Index',
        'TransmitPowerValue'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['Index', 'TransmitPowerValue'])
}


def decode_FrequencyInformation(data):
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
        'Type',
        'Hopping',
        'FrequencyHopTable',
        'FixedFrequencyTable'
    ],
    'decode': decode_FrequencyInformation
}


def decode_FrequencyHopTable(data):
    logger.debugfast('decode_FrequencyHopTable')
    par = {}

    # Decode fields
    par['HopTableId'], flags, par['NumHops'] = \
        ubyte_ubyte_ushort_unpack(data[:ubyte_ubyte_ushort_size])
    data = data[ubyte_ubyte_ushort_size:]

    num = int(par['NumHops'])
    for _ in range(1, num + 1):
        par['Frequency'] = uint_unpack(data[:uint_size])[0]
        data = data[uint_size:]

    return par, ''


Param_struct['FrequencyHopTable'] = {
    'type': 147,
    'fields': [
        'Type',
        'HopTableId',
        'NumHops',
        'Frequency'
    ],
    'decode': decode_FrequencyHopTable
}


def decode_FixedFrequencyTable(data):
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
        'Type',
        'NumFrequencies',
        'Frequency'
    ],
    'decode': decode_FixedFrequencyTable
}


def decode_C1G2LLRPCapabilities(data):
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
        'Type',
        'UHFC1G2RFModeTableEntry'
    ],
    'decode': decode_all_parameters
}


# v1.1:17.3.1.1.3 UHFC1G2RFModeTableEntry
mode_table_entry_unpack = struct.Struct('!IBBBBIIIII').unpack

def decode_UHFC1G2RFModeTableEntry(data):
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
        'Type',
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
        'Type',
        'MinimumFrequency',
        'MaximumFrequency'
    ],
    'decode': basic_param_decode_generator(uint_uint_unpack,
                                           ['MinimumFrequency',
                                            'MaximumFrequency'])
}


# 16.2.3.2 LLRPCapabilities Parameter
llrp_capabilities_unpack = struct.Struct('!BBHIIIII').unpack

def decode_LLRPCapabilities(data):
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
        'Type',
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

def decode_GeneralDeviceCapabilities(data):
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
        'Type',
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
    'decode': decode_GeneralDeviceCapabilities
}


Param_struct['MaximumReceiveSensitivity'] = {
    'type': 363,
    'fields': [
        'Type',
        'MaximumSensitivityValue'
    ],
    'decode': basic_param_decode_generator(ushort_unpack,
                                           ['MaximumSensitivityValue'])
}


Param_struct['ReceiveSensitivityTableEntry'] = {
    'type': 139,
    'fields': [
        'Type',
        'Index',
        'ReceiveSensitivityValue'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['Index',
                                            'ReceiveSensitivityValue'])
}


Param_struct['PerAntennaReceiveSensitivityRange'] = {
    'type': 149,
    'fields': [
        'Type',
        'AntennaID',
        'ReceiveSensitivityIndexMin',
        'ReceiveSensitivityIndexMax'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_ushort_unpack,
                                           ['AntennaID',
                                            'ReceiveSensitivityIndexMin',
                                            'ReceiveSensitivityIndexMax'])
}


def decode_PerAntennaAirProtocol(data):
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
        'Type',
        'AntennaID',
        'NumProtocols',
        'ProtocolID'
    ],
    'decode': decode_PerAntennaAirProtocol
}


Param_struct['GPIOCapabilities'] = {
    'type': 141,
    'fields': [
        'Type',
        'NumGPIs',
        'NumGPOs'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['NumGPIs', 'NumGPOs'])
}


Message_struct['ERROR_MESSAGE'] = {
    'type': 100,
    'fields': [
        'Type',
        'MessageLength',
        'MessageID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 16.2.4.1 ROSpec Parameter
def encode_ROSpec(par):
    msgtype = Param_struct['ROSpec']['type']
    msgid = par['ROSpecID'] & BITMASK(10)
    priority = par['Priority'] & BITMASK(7)
    state = ROSpecState_Name2Type[par['CurrentState']] & BITMASK(7)

    msg_header = '!HHIBB'
    msg_header_len = struct.calcsize(msg_header)

    data = encode('ROBoundarySpec')(par['ROBoundarySpec'])
    data += encode('AISpec')(par['AISpec'])
    data += encode('ROReportSpec')(par['ROReportSpec'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len,
                       msgid, priority, state) + data

    return data


Param_struct['ROSpec'] = {
    'type': 177,
    'fields': [
        'Type',
        'ROSpecID',
        'Priority',
        'CurrentState',
        'ROBoundarySpec',
        'AISpec',
        'RFSurveySpec',
        'ROReportSpec'
    ],
    'encode': encode_ROSpec
}


# 17.2.5.1 AccessSpec
def encode_AccessSpec(par):
    msgtype = Param_struct['AccessSpec']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!I', int(par['AccessSpecID']))
    data += struct.pack('!H', int(par['AntennaID']))
    data += struct.pack('!B', par['ProtocolID'])
    data += struct.pack('!B', par['CurrentState'] and (1 << 7) or 0)
    data += struct.pack('!I', par['ROSpecID'])

    data += encode('AccessSpecStopTrigger')(par['AccessSpecStopTrigger'])
    data += encode('AccessCommand')(par['AccessCommand'])
    if 'AccessReportSpec' in par:
        data += encode('AccessReportSpec')(par['AccessReportSpec'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


# 17.2.5.1 AccessSpec
Param_struct['AccessSpec'] = {
    'type': 207,
    'fields': [
        'Type',
        'AccessSpecID',
        'AntennaID',
        'ProtocolID',
        'CurrentState',
        'ROSpecID',
        'AccessSpecStopTrigger',
        'AccessCommand',
        'AccessReportSpec',
        'ImpinjAccessSpecConfiguration',
    ],
    'encode': encode_AccessSpec
}


# 17.1.21 ADD_ACCESSSPEC
def encode_AddAccessSpec(msg):
    return encode('AccessSpec')(msg['AccessSpec'])


# 17.1.21 ADD_ACCESSSPEC
Message_struct['ADD_ACCESSSPEC'] = {
    'type': 40,
    'fields': [
        'Type',
        'AccessSpec',
    ],
    'encode': encode_AddAccessSpec
}


# 17.1.22 ADD_ACCESSSPEC_RESPONSE
Message_struct['ADD_ACCESSSPEC_RESPONSE'] = {
    'type': 50,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 17.1.23 DELETE_ACCESSSPEC
def encode_DeleteAccessSpec(msg):
    return struct.pack('!I', msg['AccessSpecID'])


# 17.1.23 DELETE_ACCESSSPEC
Message_struct['DELETE_ACCESSSPEC'] = {
    'type': 41,
    'fields': [
        'Ver', 'Type', 'ID',
        'AccessSpecID'
    ],
    'encode': encode_DeleteAccessSpec
}


# 17.1.24 DELETE_ACCESSSPEC_RESPONSE
Message_struct['DELETE_ACCESSSPEC_RESPONSE'] = {
    'type': 51,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 17.1.25 ENABLE_ACCESSSPEC
def encode_EnableAccessSpec(msg):
    return struct.pack('!I', msg['AccessSpecID'])


# 17.1.25 ENABLE_ACCESSSPEC
Message_struct['ENABLE_ACCESSSPEC'] = {
    'type': 42,
    'fields': [
        'Ver', 'Type', 'ID',
        'AccessSpecID'
    ],
    'encode': encode_EnableAccessSpec
}


# 17.1.26 ENABLE_ACCESSSPEC_RESPONSE
Message_struct['ENABLE_ACCESSSPEC_RESPONSE'] = {
    'type': 52,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


# 17.1.27 DISABLE_ACCESSSPEC
def encode_DisableAccessSpec(msg):
    return struct.pack('!I', msg['AccessSpecID'])


# 17.1.27 DISABLE_ACCESSSPEC
Message_struct['DISABLE_ACCESSSPEC'] = {
    'type': 43,
    'fields': [
        'Ver', 'Type', 'ID',
        'AccessSpecID'
    ],
    'encode': encode_DisableAccessSpec
}


# 17.1.28 DISABLE_ACCESSSPEC_RESPONSE
Message_struct['DISABLE_ACCESSSPEC_RESPONSE'] = {
    'type': 53,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_generic_message_with_status_check
}


def encode_AccessSpecStopTrigger(par):
    msgtype = Param_struct['AccessSpecStopTrigger']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', int(par['AccessSpecStopTriggerType']))
    data += struct.pack('!H', int(par['OperationCountValue']))

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Param_struct['AccessSpecStopTrigger'] = {
    'type': 208,
    'fields': [
        'Type',
        'AccessSpecStopTriggerType',
        'OperationCountValue'
    ],
    'encode': encode_AccessSpecStopTrigger
}


def encode_AccessCommand(par):
    msgtype = Param_struct['AccessCommand']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = encode_C1G2TagSpec(par['TagSpecParameter'])

    if 'WriteData' in par['OpSpecParameter']:
        if par['OpSpecParameter']['WriteDataWordCount'] > 1:
            data += encode_C1G2BlockWrite(par['OpSpecParameter'])
        else:
            data += encode_C1G2Write(par['OpSpecParameter'])
    elif 'LockPayload' in par['OpSpecParameter']:
        data += encode_C1G2Lock(par['OpSpecParameter'])
    else:
        data += encode_C1G2Read(par['OpSpecParameter'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Param_struct['AccessCommand'] = {
    'type': 209,
    'fields': [
        'Type',
        'TagSpecParameter',
        'OpSpecParameter'
    ],
    'encode': encode_AccessCommand
}


def encode_C1G2TagSpec(par):
    msgtype = Param_struct['C1G2TagSpec']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    targets = par['C1G2TargetTag']
    if not isinstance(targets, list):
        targets = (targets,)
    for target in targets:
        data = encode_C1G2TargetTag(target)

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2TagSpec'] = {
    'type': 338,
    'fields': [
        'Type',
        'C1G2TargetTag'
    ],
    'encode': encode_C1G2TagSpec
}


def encode_bitstring(bstr, length_bytes):
    padding = b'\x00' * (length_bytes - len(bstr))
    return bstr + padding


def encode_C1G2TargetTag(par):
    msgtype = Param_struct['C1G2TargetTag']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', ((int(par['MB']) << 6) |
                              (par['M'] and (1 << 5) or 0)))
    data += struct.pack('!H', int(par['Pointer']))
    data += struct.pack('!H', int(par['MaskBitCount']))
    if int(par['MaskBitCount']):
        numBytes = ((par['MaskBitCount'] - 1) // 8) + 1
        data += encode_bitstring(par['TagMask'], numBytes)

    data += struct.pack('!H', int(par['DataBitCount']))
    if int(par['DataBitCount']):
        numBytes = ((par['DataBitCount'] - 1) // 8) + 1
        data += encode_bitstring(par['TagData'], numBytes)

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2TargetTag'] = {
    'type': 339,
    'fields': [
        'Type',
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
def encode_C1G2Read(par):
    msgtype = Param_struct['C1G2Read']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)
    data = struct.pack('!H', int(par['OpSpecID']))
    data += struct.pack('!I', int(par['AccessPassword']))
    data += struct.pack('!B', int(par['MB']) << 6)
    data += struct.pack('!H', int(par['WordPtr']))
    data += struct.pack('!H', int(par['WordCount']))

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2Read'] = {
    'type': 341,
    'fields': [
        'Type',
        'OpSpecID',
        'MB',
        'WordPtr',
        'WordCount',
        'AccessPassword'
    ],
    'encode': encode_C1G2Read
}


# 16.2.1.3.2.3 C1G2Write
def encode_C1G2Write(par):
    msgtype = Param_struct['C1G2Write']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!H', int(par['OpSpecID']))
    data += struct.pack('!I', int(par['AccessPassword']))
    data += struct.pack('!B', int(par['MB']) << 6)
    data += struct.pack('!H', int(par['WordPtr']))
    data += struct.pack('!H', int(par['WriteDataWordCount']))
    data += par['WriteData']

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2Write'] = {
    'type': 342,
    'fields': [
        'Type',
        'OpSpecID',
        'MB',
        'WordPtr',
        'AccessPassword'
        'WriteDataWordCount',
        'WriteData'
    ],
    'encode': encode_C1G2Write
}


# 16.2.1.3.2.5 C1G2Lock Parameter
def encode_C1G2Lock(par):
    msgtype = Param_struct['C1G2Lock']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!H', int(par['OpSpecID']))
    data += struct.pack('!I', int(par['AccessPassword']))
    for payload in par['LockPayload']:
        data += encode_C1G2LockPayload(payload)

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2Lock'] = {
    'type': 344,
    'fields': [
        'Type',
        'OpSpecID',
        'LockCommandPayloadList',
        'AccessPassword'
    ],
    'encode': encode_C1G2Lock
}


# 16.2.1.3.2.5.1 C1G2LockPayload Parameter
def encode_C1G2LockPayload(par):
    msgtype = Param_struct['C1G2LockPayload']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', int(par['Privilege']))
    data += struct.pack('!b', int(par['DataField']))

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2LockPayload'] = {
    'type': 345,
    'fields': [
        'Type',
        'OpSpecID',
        'Privilege',
        'DataField',
    ],
    'encode': encode_C1G2LockPayload
}


# 16.2.1.3.2.7 C1G2BlockWrite
def encode_C1G2BlockWrite(par):
    msgtype = Param_struct['C1G2BlockWrite']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!H', int(par['OpSpecID']))
    data += struct.pack('!I', int(par['AccessPassword']))
    data += struct.pack('!B', int(par['MB']) << 6)
    data += struct.pack('!H', int(par['WordPtr']))
    data += struct.pack('!H', int(par['WriteDataWordCount']))
    data += par['WriteData']

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['C1G2BlockWrite'] = {
    'type': 347,
    'fields': [
        'Type',
        'OpSpecID',
        'MB',
        'WordPtr',
        'AccessPassword'
        'WriteDataWordCount',
        'WriteData'
    ],
    'encode': encode_C1G2Write
}


def encode_AccessReportSpec(par):
    msgtype = Param_struct['AccessReportSpec']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', par['AccessReportTrigger'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


# TODO: Use/convert AccessReportTrigger_Name2Type
Param_struct['AccessReportSpec'] = {
    'type': 239,
    'fields': [
        'Type',
        'AccessReportTrigger'
    ],
    'encode': encode_AccessReportSpec,
    'decode': basic_param_decode_generator(ubyte_unpack)
}


# 16.2.4.1.1 ROBoundarySpec Parameter
def encode_ROBoundarySpec(par):
    msgtype = Param_struct['ROBoundarySpec']['type']

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = encode('ROSpecStartTrigger')(par['ROSpecStartTrigger'])
    data += encode('ROSpecStopTrigger')(par['ROSpecStopTrigger'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Param_struct['ROBoundarySpec'] = {
    'type': 178,
    'fields': [
        'Type',
        'ROSpecStartTrigger',
        'ROSpecStopTrigger'
    ],
    'encode': encode_ROBoundarySpec
}


# 16.2.4.1.1.1 ROSpecStartTrigger Parameter
def encode_ROSpecStartTrigger(par):
    msgtype = Param_struct['ROSpecStartTrigger']['type']
    t_type = StartTrigger_Name2Type[par['ROSpecStartTriggerType']]

    msg_header = '!HHB'
    msg_header_len = struct.calcsize(msg_header)

    data = b''
    if par['ROSpecStartTriggerType'] == 'Periodic':
        data += encode('PeriodicTriggerValue')(par['PeriodicTriggerValue'])
    elif par['ROSpecStartTriggerType'] == 'GPI':
        data += encode('GPITriggerValue')(par['GPITriggerValue'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len, t_type) + data

    return data


Param_struct['ROSpecStartTrigger'] = {
    'type': 179,
    'fields': [
        'Type',
        'ROSpecStartTriggerType',
        'PeriodicTriggerValue',
        'GPITriggerValue'
    ],
    'encode': encode_ROSpecStartTrigger
}


def encode_PeriodicTriggerValue(par):
    msgtype = Param_struct['PeriodicTriggerValue']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!I', par['Offset'])
    data += struct.pack('!I', par['Period'])
    if 'UTCTimestamp' in par:
        data += encode('UTCTimestamp')(par['UTCTimestamp'])

    data = struct.pack(msg_header, msgtype, len(data) + msg_header_len) + data
    return data


# 16.2.4.1.1.1 PeriodicTriggerValue Parameter
Param_struct['PeriodicTriggerValue'] = {
    'type': 180,
    'fields': [
        'Type',
        'Offset',
        'Period',
        'UTCTimestamp'
    ],
    'encode': encode_PeriodicTriggerValue
}


# 16.2.4.1.1.2 ROSpecStopTrigger Parameter
def encode_ROSpecStopTrigger(par):
    msgtype = Param_struct['ROSpecStopTrigger']['type']
    t_type = StopTrigger_Name2Type[par['ROSpecStopTriggerType']]
    duration = par['DurationTriggerValue']

    msg_header = '!HHBI'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack(msg_header, msgtype, msg_header_len, t_type, duration)
    return data


Param_struct['ROSpecStopTrigger'] = {
    'type': 182,
    'fields': [
        'Type',
        'ROSpecStopTriggerType',
        'DurationTriggerValue',
        'GPITriggerValue'
    ],
    'encode': encode_ROSpecStopTrigger
}


# 16.2.4.2 AISpec Parameter
def encode_AISpec(par):
    msgtype = Param_struct['AISpec']['type']

    msg_header = '!HHH'
    msg_header_len = struct.calcsize(msg_header)
    data = b''

    antid = par['AntennaIDs']
    antennas = []
    if isinstance(antid, str):
        antennas = antid.split()
    else:
        antennas.extend(antid)
    for a in antennas:
        data += struct.pack('!H', int(a))

    data += encode('AISpecStopTrigger')(par['AISpecStopTrigger'])
    data += encode('InventoryParameterSpec')(par['InventoryParameterSpec'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len, len(antennas)) + data

    return data


Param_struct['AISpec'] = {
    'type': 183,
    'fields': [
        'Type',
        'AntennaCount',
        'AntennaIDs',
        'AISpecStopTrigger',
        'InventoryParameterSpec'
    ],
    'encode': encode_AISpec
}


# 16.2.4.2.1 AISpecStopTrigger Parameter
def encode_AISpecStopTrigger(par):
    msgtype = Param_struct['AISpecStopTrigger']['type']
    t_type = StopTrigger_Name2Type[par['AISpecStopTriggerType']]
    duration = int(par['DurationTriggerValue'])

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', t_type)
    data += struct.pack('!I', int(duration))
    if 'GPITriggerValue' in par:
        # TODO implement GPITriggerValue Param_struct
        data += encode('GPITriggerValue')(par['GPITriggerValue'])
    if 'TagObservationTrigger' in par:
        data += encode('TagObservationTrigger')(par['TagObservationTrigger'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Param_struct['AISpecStopTrigger'] = {
    'type': 184,
    'fields': [
        'Type',
        'AISpecStopTriggerType',
        'DurationTriggerValue',
        'GPITriggerValue',
        'TagObservationTrigger'
    ],
    'encode': encode_AISpecStopTrigger
}


# 17.2.4.2.1.1
def encode_TagObservationTrigger(par):
    msgtype = Param_struct['TagObservationTrigger']['type']
    t_type = TagObservationTrigger_Name2Type[par['TriggerType']]
    n_tags = int(par['NumberOfTags'])
    n_attempts = int(par['NumberOfAttempts'])
    t = int(par['T'])
    timeout = int(par['Timeout'])

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', t_type)
    data += struct.pack('!B', 0)
    data += struct.pack('!H', n_tags)
    data += struct.pack('!H', n_attempts)
    data += struct.pack('!H', t)
    data += struct.pack('!I', timeout)

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Param_struct['TagObservationTrigger'] = {
    'type': 185,
    'fields': [
        'Type',
        'TriggerType',
        'NumberOfTags',
        'NumberOfAttempts',
        'T',
        'Timeout'
    ],
    'encode': encode_TagObservationTrigger
}


# 16.2.4.2.2 InventoryParameterSpec Parameter
def encode_InventoryParameterSpec(par):
    msgtype = Param_struct['InventoryParameterSpec']['type']

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)
    data = struct.pack('!H', par['InventoryParameterSpecID'])
    data += struct.pack('!B', par['ProtocolID'])

    for antconf in par['AntennaConfiguration']:
        logger.debugfast('encoding AntennaConfiguration: %s', antconf)
        data += encode('AntennaConfiguration')(antconf)

    data = struct.pack(msg_header, msgtype,
                       msg_header_len + len(data)) + data

    return data


Param_struct['InventoryParameterSpec'] = {
    'type': 186,
    'fields': [
        'Type',
        'InventoryParameterSpecID',
        'ProtocolID',
        'AntennaConfiguration'
    ],
    'encode': encode_InventoryParameterSpec
}

# v1.1:17.2.6.1 LLRPConfigurationStateValue Parameter
Param_struct['LLRPConfigurationStateValue'] = {
    'type': 217,
    'fields': [
        'Type',
        'LLRPConfigurationStateValue',
    ],
    'decode': basic_param_decode_generator(uint_unpack,
                                           ['LLRPConfigurationStateValue'])
}


# v1.1:17.2.6.2 Identification Parameter
def decode_Identification(data):
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
def decode_GPOEvent(data):
    logger.debugfast('decode_GPOEvent')
    par = {}

    par['GPOPortNumber'], flags = ushort_ubyte_unpack(data)
    par['GPOData'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['GPOWriteData'] = {
    'type': 219,
    'fields': [
        'Type',
        'GPOPortNumber',
        'GPOData',
    ],
    'decode': decode_GPOEvent
}


# v1.1:17.2.6.4 KeepaliveSpec Parameter
Param_struct['KeepaliveSpec'] = {
    'type': 220,
    'fields': [
        'Type',
        'KeepaliveTriggerType',
        'TimeInterval',
    ],
    'decode': basic_param_decode_generator(ubyte_uint_unpack,
                                           ['KeepaliveTriggerType',
                                            'TimeInterval'])
}


# v1.1:17.2.6.5 AntennaProperties Parammeter
def decode_AntennaProperties(data):
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
def encode_AntennaConfiguration(par):
    msgtype = Param_struct['AntennaConfiguration']['type']
    msg_header = '!HH'
    data = struct.pack('!H', int(par['AntennaID']))
    if 'RFReceiver' in par:
        data += encode('RFReceiver')(par['RFReceiver'])
    if 'RFTransmitter' in par:
        data += encode('RFTransmitter')(par['RFTransmitter'])
    if 'C1G2InventoryCommand' in par:
        data += encode('C1G2InventoryCommand')(par['C1G2InventoryCommand'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Param_struct['AntennaConfiguration'] = {
    'type': 222,
    'fields': [
        'Type',
        'AntennaID',
        'RFReceiver',
        'RFTransmitter',
        # XXX handle AirProtocolInventoryCommandSettings params other than
        # C1G2InventoryCommand?
        'C1G2InventoryCommand'
    ],
    'encode': encode_AntennaConfiguration,
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ['AntennaID'],
                                                ushort_size)

}


# 16.2.6.7 RFReceiver Parameter
def encode_RFReceiver(par):
    msgtype = Param_struct['RFReceiver']['type']
    msg_header = '!HH'
    data = struct.pack('!H', par['ReceiverSensitivity'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Param_struct['RFReceiver'] = {
    'type': 223,
    'fields': [
        'Type',
        'ReceiverSensitivity',
    ],
    'encode': encode_RFReceiver,
    'decode': basic_param_decode_generator(ushort_unpack,
                                           ['ReceiverSensitivity'])
}


# V1.1:16.2.6.8 RFTransmitter Parameter
def encode_RFTransmitter(par):
    msgtype = Param_struct['RFTransmitter']['type']
    msg_header = '!HH'
    data = struct.pack('!H', par['HopTableId'])
    data += struct.pack('!H', par['ChannelIndex'])
    data += struct.pack('!H', par['TransmitPower'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Param_struct['RFTransmitter'] = {
    'type': 224,
    'fields': [
        'Type',
        'HopTableId',
        'ChannelIndex',
        'TransmitPower',
    ],
    'encode': encode_RFTransmitter,
    'decode': basic_param_decode_generator(ushort_ushort_ushort_unpack,
                                           ['HopTableId',
                                            'ChannelIndex',
                                            'TransmitPower'])
}


# V1.1:17.2.6.9 GPOWriteData Parameter
def decode_GPIPortCurrentState(data):
    logger.debugfast('decode_GPIPortCurrentState')
    par = {}

    par['GPIPortNum'], flags, par['GPIState'] = ushort_ubyte_ubyte_unpack(data)
    par['GPIConfig'] = flags & BIT(7) == BIT(7)

    return par, ''


Param_struct['GPIPortCurrentState'] = {
    'type': 225,
    'fields': [
        'Type',
        'GPIPortNum',
        'GPIConfig',
        'GPIState'
    ],
    'decode': decode_GPIPortCurrentState
}


# V1.1:17.2.6.10 EventsAndReports Parameter
def decode_EventsAndReports(data):
    logger.debugfast('decode_GPOEvent')

    flags = ubyte_unpack(data)[0]
    par = {
        'HoldEventsAndReportsUponReconnect': flags & BIT(7) == BIT(7)
    }

    return par, ''


Param_struct['EventsAndReports'] = {
    'type': 226,
    'fields': [
        'Type',
        'HoldEventsAndReportsUponReconnect',
    ],
    'decode': decode_EventsAndReports
}


# 16.3.1.2.1 C1G2InventoryCommand Parameter
def encode_C1G2InventoryCommand(par):
    msgtype = Param_struct['C1G2InventoryCommand']['type']
    msg_header = '!HH'
    data = struct.pack('!B', (par['TagInventoryStateAware'] and 1 or 0) << 7)
    if 'C1G2Filter' in par:
        filters = par['C1G2Filter']
        if isinstance(filters, list):
            for filt in filters:
                data += encode('C1G2Filter')(filt)
        else: # only one filter
            data += encode('C1G2Filter')(filters)
    if 'C1G2RFControl' in par:
        data += encode('C1G2RFControl')(par['C1G2RFControl'])
    if 'C1G2SingulationControl' in par:
        data += encode('C1G2SingulationControl')(par['C1G2SingulationControl'])
    if 'ImpinjInventorySearchMode' in par:
        data += encode('ImpinjInventorySearchMode')(
            par['ImpinjInventorySearchMode'])
    if 'ImpinjIntelligentAntennaManagement' in par:
        data += encode('ImpinjIntelligentAntennaManagement')(
            par['ImpinjIntelligentAntennaManagement'])
    if 'ImpinjFixedFrequencyList' in par:
        data += encode('ImpinjFixedFrequencyList')(
            par['ImpinjFixedFrequencyList'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


def decode_C1G2InventoryCommand(data):
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
        # XXX custom parameters
        'ImpinjInventoryConfiguration',
        'ImpinjInventorySearchMode',
        'ImpinjIntelligentAntennaManagement',
        'ImpinjFixedFrequencyList',
        'ImpinjReducedPowerFrequencyList',
        'ImpinjLowDutyCycle',
        'ImpinjRFPowerSweep'
    ],
    'encode': encode_C1G2InventoryCommand,
    'decode': decode_C1G2InventoryCommand
}


# 16.3.1.2.1.1 C1G2Filter Parameter
def encode_C1G2Filter(par):
    msgtype = Param_struct['C1G2Filter']['type']
    msg_header = '!HH'
    data = struct.pack('!B', Param_struct['C1G2Filter']['T'] << 6) # XXX: hardcoded trucation for now
    if 'C1G2TagInventoryMask' in par:
        data += encode('C1G2TagInventoryMask')(
            par['C1G2TagInventoryMask'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Param_struct['C1G2Filter'] = {
    'type': 331,
    'T': 0,
    'fields': [
        'C1G2TagInventoryMask'
    ],
    'encode': encode_C1G2Filter
}

# 16.3.1.2.1.1.1 C1G2TagInventoryMask Parameter
def encode_C1G2TagInventoryMask(par):
    msgtype = Param_struct['C1G2TagInventoryMask']['type']
    msg_header = '!HH'
    maskbitcount = len(par['TagMask'])*4
    if len(par['TagMask']) % 2 != 0:    # check for odd numbered length hexstring
        par['TagMask'] += '0'           # pad with zero
    data = struct.pack('!B', par['MB'] << 6)
    data += struct.pack('!H', par['Pointer'])
    if maskbitcount:
        data += struct.pack('!H', maskbitcount)
        data += unhexlify(par['TagMask'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data

Param_struct['C1G2TagInventoryMask'] = {
    'type': 332,
    'fields': [
        'MB',
        'Pointer',
        'TagMask'
    ],
    'encode': encode_C1G2TagInventoryMask
}

# 16.3.1.2.1.2 C1G2RFControl Parameter
def encode_C1G2RFControl(par):
    msgtype = Param_struct['C1G2RFControl']['type']
    msg_header = '!HH'
    data = struct.pack('!H', par['ModeIndex'])
    data += struct.pack('!H', par['Tari'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Param_struct['C1G2RFControl'] = {
    'type': 335,
    'fields': [
        'ModeIndex',
        'Tari',
    ],
    'encode': encode_C1G2RFControl,
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['ModeIndex', 'Tari'])
}


# 16.3.1.2.1.3 C1G2SingulationControl Parameter
def encode_C1G2SingulationControl(par):
    msgtype = Param_struct['C1G2SingulationControl']['type']
    msg_header = '!HH'
    data = struct.pack('!B', par['Session'] << 6)
    data += struct.pack('!H', par['TagPopulation'])
    data += struct.pack('!I', par['TagTransitTime'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


def decode_C1G2SingulationControl(data):
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
        'C1G2TagInventoryStateAwareSingulationAction'
    ],
    'encode': encode_C1G2SingulationControl,
    'decode': decode_C1G2SingulationControl
}


def decode_C1G2TagInventoryStateAwareSingulationAction(data):
    logger.debugfast('decode_C1G2TagInventoryStateAwareSingulationAction')
    par = {}

    ISA = ubyte_unpack(data)
    par['I'] = (RC >> 7) and 'State_B' or 'State_A'
    par['S'] = ((RC >> 6) & 1) and 'Not_SL' or 'SL'
    par['A'] = ((RC >> 5) & 1) and 'All' or 'No'

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
def encode_ROReportSpec(par):
    msgtype = Param_struct['ROReportSpec']['type']
    n = int(par['N'])
    roReportTrigger = ROReportTrigger_Name2Value[par['ROReportTrigger']]

    msg_header = '!HHBH'
    msg_header_len = struct.calcsize(msg_header)

    data = encode('TagReportContentSelector')(par['TagReportContentSelector'])
    if 'ImpinjTagReportContentSelector' in par:
        data += encode('ImpinjTagReportContentSelector')(
            par['ImpinjTagReportContentSelector'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len,
                       roReportTrigger, n) + data

    return data


def decode_ROReportSpec(data):
    logger.debugfast('decode_C1G2InventoryCommand')
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
        'TagReportContentSelector',
        'ImpinjTagReportContentSelector',
    ],
    'encode': encode_ROReportSpec,
    'decode': decode_ROReportSpec
}


def encode_ReaderEventNotificationSpec(par):
    msgtype = Param_struct['ReaderEventNotificationSpec']['type']
    states = par['EventNotificationState']

    data = b''
    for ev_type, flag in states.items():
        if ev_type not in EventState_Name2Value:
            logger.warning('Unknown event name %s', ev_type)
            continue
        parlen = struct.calcsize('!HHHB')
        data += struct.pack('!HHHB', 245, parlen,
                            EventState_Name2Value[ev_type],
                            (int(bool(flag)) << 7) & 0xff)

    data = struct.pack('!HH', msgtype,
                       len(data) + struct.calcsize('!HH')) + data
    return data


Param_struct['ReaderEventNotificationSpec'] = {
    'type': 244,
    'fields': [
        'EventNotificationState',
    ],
    'encode': encode_ReaderEventNotificationSpec,
    'decode': decode_all_parameters
}


def decode_EventNotificationState(data):
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
    'decode': decode_EventNotificationState
}


# 16.2.7.1 TagReportContentSelector Parameter
def encode_TagReportContentSelector(par):
    msgtype = Param_struct['TagReportContentSelector']['type']

    msg_header = '!HH'

    flags = 0
    i = 15
    for field in Param_struct['TagReportContentSelector']['fields']:
        if field == 'C1G2EPCMemorySelector':
            continue
        if field in par and par[field]:
            flags = flags | (1 << i)
        i = i - 1
    data = struct.pack('!H', flags)

    if 'C1G2EPCMemorySelector' in par:
        data += encode('C1G2EPCMemorySelector')(par['C1G2EPCMemorySelector'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data

    return data


def decode_TagReportContentSelector(data):
    logger.debugfast('decode_TagReportContentSelector')
    par = {}

    flags = ushort_unpack(data[:ushort_size])[0]
    i = 15
    for field in Param_struct['TagReportContentSelector']['fields']:
        if field == 'C1G2EPCMemorySelector':
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
        'C1G2EPCMemorySelector'
    ],
    'encode': encode_TagReportContentSelector,
    'decode': decode_TagReportContentSelector,
}


# 15.2.1.5.1 C1G2EPCMemorySelector Parameter
def encode_C1G2EPCMemorySelector(par):
    msgtype = Param_struct['C1G2EPCMemorySelector']['type']
    msg_header = '!HH'

    flags = 0
    i = 7
    for field in Param_struct['C1G2EPCMemorySelector']['fields']:
        if field in par and par[field]:
            flags = flags | (1 << i)
        i = i - 1

    data = struct.pack('!B', flags)
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data

    return data


def decode_C1G2EPCMemorySelector(data):
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
def decode_TagReportData(data):
    logger.debugfast('decode_TagReportData')
    par = {}

    # Decode parameters
    par, _ = decode_all_parameters(data, 'TagReportData', par)

    # EPC-96 is just a protocol optimization for EPCData but was not supposed
    # to be exposed to higher level
    # Keep it here for the moment, because a lof of clients use it directly
    # but only the umbrella "EPC" should be used in the future
    if 'EPC-96' in par:
        par['EPC'] = par['EPC-96']

    logger.debugfast('par=%s', par)
    return par, ''


Param_struct['TagReportData'] = {
    'type': 240,
    'fields': [
        'Type',
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
        'ImpinjRFDopplerFrequency'
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


def decode_C1G2ReadOpSpecResult(data):
    par, data = decode_basic_OpSpecResult(data, 'C1G2ReadOpSpecResult')

    wordcnt = ushort_unpack(data[:ushort_size])[0]
    par['ReadDataWordCount'] = wordcnt
    end = ushort_size + (wordcnt * 2)
    par['ReadData'] = data[ushort_size:end]

    return par, ''


def decode_C1G2WriteOpSpecResult(data):
    par, data = decode_basic_OpSpecResult(data, 'C1G2WriteOpSpecResult')

    par['NumWordsWritten'] = ushort_unpack(data[:ushort_size])[0]

    return par, ''


def decode_C1G2GetBlockPermalockStatusOpSpecResult(data):
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
        'Type',
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
        'Type',
        'Result',
        'OpSpecID',
        'NumWordsWritten'
    ],
    'decode': decode_C1G2WriteOpSpecResult
}

Param_struct['C1G2KillOpSpecResult'] = {
    'type': 351,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2RecommissionOpSpecResult'] = {
    'type': 360,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2LockOpSpecResult'] = {
    'type': 352,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2BlockEraseOpSpecResult'] = {
    'type': 353,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2BlockWriteOpSpecResult'] = {
    'type': 354,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'NumWordsWritten'
    ],
    'decode': decode_C1G2WriteOpSpecResult
}

Param_struct['C1G2BlockPermalockOpSpecResult'] = {
    'type': 361,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_basic_OpSpecResult
}

Param_struct['C1G2GetBlockPermalockStatusOpSpecResult'] = {
    'type': 362,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'StatusWordCount',
        'PermalockStatus'
    ],
    'decode': decode_C1G2GetBlockPermalockStatusOpSpecResult
}


# 16.2.7.3.1 EPCData Parameter
def decode_EPCData(data):
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
def decode_EPC96(data):
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
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['NumCollisionSlots',
                                            'NumEmptySlots'])
}


# 16.2.7.6.1 HoppingEvent Parameter

Param_struct['HoppingEvent'] = {
    'type': 247,
    'fields': [
        'Type',
        'HopTableID',
        'NextChannelIndex'
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['HopTableID', 'NextChannelIndex'])
}

# 16.2.7.6.2 GPIEvent Parameter
def decode_GPIEvent(data):
    logger.debugfast('decode_GPIEvent')
    par = {}

    par['GPIPortNumber'], flags = ushort_ubyte_unpack(data)
    par['GPIEvent'] = flags & BIT(7) == BIT(7)

    return par, ''

Param_struct['GPIEvent'] = {
    'type': 248,
    'fields': [
        'Type',
        'GPIPortNumber',
        'GPIEvent'
    ],
    'decode': decode_GPIEvent
}

# 16.2.7.6.3 ROSpecEvent Parameter
def decode_ROSpecEvent(data):
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
        'Type',
        'EventType',
        'ROSpecID',
        'PreemptingROSpecID'
    ],
    'decode': decode_ROSpecEvent
}


Param_struct['ReportBufferLevelWarning'] = {
    'type': 250,
    'fields': [
        'Type',
        'ReportBufferPercentageFull'
    ],
    'decode': basic_param_decode_generator(ubyte_unpack,
                                           ['ReportBufferPercentageFull'])
}


Param_struct['ReportBufferOverflowErrorEvent'] = {
    'type': 251,
    'fields': [
        'Type',
    ],
    'decode': decode_all_parameters
}


def decode_ReaderExceptionEvent(data):
    logger.debugfast('decode_ReaderExceptionEvent')
    par = {}

    offset = ushort_size
    msg_bytecount = ushort_unpack(data[:offset])[0]
    par['Message'] = data[offset:offset + msg_bytecount]
    data = data[offset + msg_bytecount:]

    par, _ = decode_all_parameters(data, 'ReaderExceptionEvent', par)
    return par, ''


Param_struct['ReaderExceptionEvent'] = {
    'type': 252,
    'fields': [
        'Type',
        'MessageByteCount',
        'Message',
        'ROSpecID',
        'SpecIndex',
        'InventoryParameterSpec',
        'AntennaID',
        'AccessSpecID',
        'OpSpecID',
        # Optional N custom parameters after
        'ImpinjHubConfiguration'
    ],
    'decode': decode_ReaderExceptionEvent
}


def decode_RFSurveyEvent(data):
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
        'Type',
        'EventType',
        'ROSpecID',
        'SpecIndex'
    ],
    'decode': decode_RFSurveyEvent
}


def decode_AISpecEvent(data):
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
        'Type',
        'EventType',
        'ROSpecID',
        'SpecIndex',
        'C1G2SingulationDetails'
    ],
    'decode': decode_AISpecEvent
}


# 16.2.7.6.9 AntennaEvent Parameter
def decode_AntennaEvent(data):
    logger.debugfast('decode_AntennaEvent')
    par = {}

    event_type, par['AntennaID'] = ubyte_ushort_unpack(data)
    par['EventType'] = event_type and 'Connected' or 'Disconnected'

    return par, ''


Param_struct['AntennaEvent'] = {
    'type': 255,
    'fields': [
        'Type',
        'EventType',
        'AntennaID'
    ],
    'decode': decode_AntennaEvent
}


# 16.2.7.6.10 ConnectionAttemptEvent Parameter
def decode_ConnectionAttemptEvent(data):
    logger.debugfast('decode_ConnectionAttemptEvent')
    par = {}

    # Decode fields
    status = ushort_unpack(data)[0]
    par['Status'] = ConnEvent_Type2Name[status]

    return par, ''


Param_struct['ConnectionAttemptEvent'] = {
    'type': 256,
    'fields': [
        'Type',
        'Status'
    ],
    'decode': decode_ConnectionAttemptEvent
}


Param_struct['ConnectionCloseEvent'] = {
    'type': 257,
    'fields': [
        'Type'
    ],
    'decode': decode_all_parameters
}


# Only available with protocol v2 (llrp 1_1)
Param_struct['SpecLoopEvent'] = {
    'type': 356,
    'fields': [
        'Type',
        'ROSpecID',
        'LoopCount'
    ],
    'decode': basic_param_decode_generator(uint_uint_unpack, ['ROSpecID',
                                                              'LoopCount'])
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
    'decode': basic_param_decode_generator(ushort_unpack, ['AntennaID'])
}


# 16.2.7.6 ReaderEventNotificationData Parameter

Param_struct['ReaderEventNotificationData'] = {
    'type': 246,
    'fields': [
        'Type',
        'UTCTimestamp',
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
    'decode': decode_all_parameters
}


# 16.2.8.1 LLRPStatus Parameter
def decode_LLRPStatus(data):
    #if is_general_debug_enabled():
    #    logger.debugfast('decode_LLRPStatus: %s', hexlify(data))
    par = {}

    offset = ushort_ushort_size
    code, n = ushort_ushort_unpack(data[:offset])
    try:
        par['StatusCode'] = Error_Type2Name[code]
    except KeyError:
        logger.warning('Unknown field code %s', code)
    par['ErrorDescription'] = data[offset:offset + n]

    data = data[offset + n:]
    par, _ = decode_all_parameters(data, 'LLRPStatus', par)

    return par, ''


Param_struct['LLRPStatus'] = {
    'type':   287,
    'fields': [
        'Type',
        'StatusCode',
        'ErrorDescription',
        'FieldError',
        'ParameterError'
    ],
    'decode': decode_LLRPStatus
}


# 16.2.8.1.1 FieldError Parameter

Param_struct['FieldError'] = {
    'type':   288,
    'fields': [
        'Type',
        'ErrorCode',
        'FieldNum',
    ],
    'decode': basic_param_decode_generator(ushort_ushort_unpack,
                                           ['FieldNum', 'ErrorCode'])
}


# 16.2.8.1.2 ParameterError Parameter
Param_struct['ParameterError'] = {
    'type':   289,
    'fields': [
        'Type',
        'ParameterType',
        'ErrorCode',
        'FieldError',
        'ParameterError'
    ],
    'decode': basic_auto_param_decode_generator(ushort_ushort_unpack,
                                                ['ParameterType',
                                                 'ErrorCode'],
                                                ushort_ushort_size)
}


def encode_CustomMessage(msg):
    vendor_id = msg['VendorID']
    subtype = msg['Subtype']
    payload = msg.get('Payload', struct.pack('!I', 0))
    data = struct.pack('!IB', vendor_id, subtype) + payload
    if is_general_debug_enabled():
        logger.debugfast('Encoding custom message data: %s', hexlify(data))
    return data


Message_struct['CUSTOM_MESSAGE'] = {
    'type': TYPE_CUSTOM,
    'fields': [
        'Ver', 'Type', 'ID',
        'VendorID',
        'Subtype',
        'Payload',
    ],
    'encode': encode_CustomMessage,
    'decode': decode_generic_message
}


def encode_CustomParameter(par):
    msgtype = Param_struct['CustomParameter']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!I', par['VendorID'])
    data += struct.pack('!I', par['Subtype'])
    data += par['Payload']

    header = struct.pack(msg_header, msgtype, msg_header_len + len(data))
    return header + data


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

def encode_ImpinjEnableExtensions(msg):
    vendor_id = Message_struct['IMPINJ_ENABLE_EXTENSIONS']['vendorid']
    subtype = Message_struct['IMPINJ_ENABLE_EXTENSIONS']['subtype']
    payload = msg.get('Payload', struct.pack('!I', 0))
    data = struct.pack('!IB', vendor_id, subtype) + payload
    return data


Message_struct['IMPINJ_ENABLE_EXTENSIONS'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 21,
    'encode': encode_ImpinjEnableExtensions
}


Message_struct['IMPINJ_ENABLE_EXTENSIONS_RESPONSE'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 22,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
    ],
    'decode': decode_generic_message_with_status_check
}


Param_struct['ImpinjSubRegulatoryRegion'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 22,
    'fields': [
        'ImpinjSubRegulatoryRegion',
    ],
    'decode': basic_param_decode_generator(ushort_unpack,
                                           ['ImpinjSubRegulatoryRegion'])
}


def encode_ImpinjInventorySearchMode(par):
    msg_struct_param = Param_struct['ImpinjInventorySearchMode']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)


Param_struct['ImpinjInventorySearchMode'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 23,
    'fields': [
        'InventorySearchMode'
    ],
    'encode': encode_ImpinjInventorySearchMode,
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ['InventorySearchMode'],
                                                ushort_size)
}


def encode_ImpinjFixedFrequencyList(par):
    msg_struct_param = Param_struct['ImpinjFixedFrequencyList']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype']
    }
    channellist = par.get('ChannelListIndex')
    payload = struct.pack('!H', par.get('FixedFrequencyMode'))
    payload += struct.pack('!H', 0) # Reserved space
    payload += struct.pack('!H', len(channellist))
    for index in channellist:
        payload += struct.pack('!H', index)
    custom_par['Payload'] = payload

    return encode('CustomParameter')(custom_par)


def decode_ImpinjFixedFrequencyList(data):
    logger.debugfast('decode_ImpinjFixedFrequencyList')
    par = {}

    (par['FixedFrequencyMode'], _, par['ChannelListCount']) = \
        ushort_ushort_ushort_unpack(data[:ushort_ushort_ushort_size])
    data = data[ushort_ushort_ushort_size:]

    num = int(par['ChannelListCount'])
    if num:
        par['ChannelListIndex'] = []
        for x in range(1, num + 1):
            par['ChannelListIndex'].append(
                ushort_unpack(data[:ushort_size])[0])
            data = data[ushort_size:]

    return par, ''


Param_struct['ImpinjFixedFrequencyList'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 26,
    'fields': [
        'FixedFrequencyMode',
        'Reserved',
        'ChannelListCount',
        'ChannelListIndex'
    ],
    'encode': encode_ImpinjFixedFrequencyList,
    'decode': decode_ImpinjFixedFrequencyList
}


def decode_ImpinjReducedPowerFrequencyList(data):
    logger.debugfast('decode_ImpinjReducedPowerFrequencyList')
    par = {}

    (par['ReducedPowerMode'], _, par['ReducedPowerChannelListCount']) = \
        ushort_ushort_ushort_unpack(data[:ushort_ushort_ushort_size])
    data = data[ushort_ushort_ushort_size:]

    num = int(par['ReducedPowerChannelListCount'])
    if num:
        par['ReducedPowerChannelListIndex'] = []
        for x in range(1, num + 1):
            par['ReducedPowerChannelListIndex'].append(
                ushort_unpack(data[:ushort_size])[0])
            data = data[ushort_size:]

    return par, ''


Param_struct['ImpinjReducedPowerFrequencyList'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 27,
    'fields': [
        'ReducedPowerMode',
        'ReducedPowerChannelListCount',
        'ReducedPowerChannelListIndex'
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
                                                ['LowDutyCycleMode',
                                                 'EmptyFieldTimeout',
                                                 'FieldPingInterval'],
                                                ushort_ushort_ushort_size)
}


def decode_ImpinjDetailedVersion(data):
    logger.debugfast('decode_ImpinjDetailedVersion')
    par = {}

    for field in ['ModelName', 'SerialNumber', 'SoftwareVersion',
                  'FirmwareVersion', 'FPGAVersion', 'PCBAVersion']:
        byte_count = ushort_unpack(data[:ushort_size])[0]
        data = data[ushort_size:]
        par[field] = data[:byte_count]
        data = data[byte_count:]

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
        'ImpinjHubVersions',
        'ImpinjArrayVersion',
        'ImpinjBLEVersion',
    ],
    'decode': decode_ImpinjDetailedVersion
}


def decode_ImpinjFrequencyCapabilities(data):
    logger.debugfast('decode_ImpinjFrequencyCapabilities')
    par = {}

    par['NumFrequencies'] = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]

    num = int(par['NumFrequencies'])
    if num:
        par['FrequencyList'] = []
        for x in range(1, num + 1):
            par['FrequencyList'].append(uint_unpack(data[:uint_size])[0])
            data = data[uint_size:]

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
                                           ['GPIPortNum',
                                            'GPIDebounceTimerMSec'])
}

Param_struct['ImpinjReaderTemperature'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 37,
    'fields': [
        'Temperature',
    ],
    'decode': basic_auto_param_decode_generator(short_unpack,
                                                ['Temperature'],
                                                short_size)
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
                                                ['LinkMonitorMode',
                                                 'LinkDownThreshold'],
                                                ushort_ushort_size)
}


Param_struct['ImpinjReportBufferConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 39,
    'fields': [
        'ReportBufferMode',
    ],
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ['ReportBufferMode'],
                                                ushort_size)
}


Param_struct['ImpinjAccessSpecConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 40,
    'fields': [
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
                                                ['WordCount'],
                                                ushort_size)
}


def encode_ImpinjTagReportContentSelector(par):
    msg_struct_param = Param_struct['ImpinjTagReportContentSelector']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
    }

    payload = encode('ImpinjEnableRFPhaseAngle')(
        par.get('ImpinjEnableRFPhaseAngle', False))
    payload += encode('ImpinjEnablePeakRSSI')(
        par.get('ImpinjEnablePeakRSSI', False))
    payload += encode('ImpinjEnableRFDopplerFrequency')(
        par.get('ImpinjEnableRFDopplerFrequency', False))
    custom_par['Payload'] = payload

    return encode('CustomParameter')(custom_par)


Param_struct['ImpinjTagReportContentSelector'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 50,
    'fields': [
        'ImpinjEnableSerializedTID',
        'ImpinjEnableRFPhaseAngle',
        'ImpinjEnablePeakRSSI',
        'ImpinjEnableGPSCoordinates',
        'ImpinjEnableOptimizedRead',
        'ImpinjEnableRFDopplerFrequency',
        'ImpinjEnableTxPower'
    ],
    'encode': encode_ImpinjTagReportContentSelector,
    'decode': decode_all_parameters
}

Param_struct['ImpinjEnableSerializedTID'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 51,
    'fields': [],
    'decode': basic_param_decode_generator(ushort_unpack)
}

def encode_ImpinjEnableRFPhaseAngle(par):
    msg_struct_param = Param_struct['ImpinjEnableRFPhaseAngle']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)


Param_struct['ImpinjEnableRFPhaseAngle'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 52,
    'fields': [],
    'encode': encode_ImpinjEnableRFPhaseAngle,
    'decode': basic_param_decode_generator(ushort_unpack)
}


def encode_ImpinjEnablePeakRSSI(par):
    msg_struct_param = Param_struct['ImpinjEnablePeakRSSI']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)


Param_struct['ImpinjEnablePeakRSSI'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 53,
    'fields': [],
    'encode': encode_ImpinjEnablePeakRSSI,
    'decode': basic_param_decode_generator(ushort_unpack)
}

Param_struct['ImpinjEnableGPSCoordinates'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 54,
    'fields': [],
    'decode': basic_param_decode_generator(ushort_unpack)
}


def decode_ImpinjSerializedTID(data):
    logger.debugfast('decode_ImpinjSerializedTID')
    par = {}

    par['TIDWordCount'] = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]

    wordcnt = int(par['TIDWordCount'])
    if num:
        par['TID'] = data[:wordcnt * 2]

    data = data[wordcnt * 2:]
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
                                                ['Latitude', 'Longitude'],
                                                uint_uint_size)
}


Param_struct['ImpinjGPSNMEASentences'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 60,
    'fields': [
        'ImpinjGGASentence',
        'ImpinjRMCSentence'
    ],
    'decode': decode_all_parameters
}


def decode_ImpinjGGASentence(data):
    logger.debugfast('decode_ImpinjGGASentence')

    byte_count = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]
    par = {
        'GGASentence': data[:byte_count]
    }
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


def decode_ImpinjRMCSentence(data):
    logger.debugfast('decode_ImpinjRMCSentence')

    byte_count = ushort_unpack(data[:ushort_size])[0]
    data = data[ushort_size:]
    par = {
        'RMCSentence': data[:byte_count]
    }
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
                                                ['RetryCount'],
                                                ushort_size)
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
                                                ['GPOPortNum',
                                                 'GPOMode',
                                                 'GPOPulseDurationMSec'],
                                                ushort_ushort_uint_size)
}


Param_struct['ImpinjEnableOptimizedRead'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 65,
    'fields': [
        'OptimizedReadMode',
        'C1G2Read'
    ],
    'decode': basic_auto_param_decode_generator(ushort_unpack,
                                                ['OptimizedReadMode'],
                                                ushort_size)
}


# Note: values: 0: FIFO, 1: Ascending
Param_struct['ImpinjAccessSpecOrdering'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 66,
    'fields': [
        'OrderingMode',
    ],
    'decode': basic_param_decode_generator(ushort_unpack, ['OrderingMode'])
}


def encode_ImpinjEnableRFDopplerFrequency(par):
    msg_struct_param = Param_struct['ImpinjEnableRFDopplerFrequency']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)


Param_struct['ImpinjEnableRFDopplerFrequency'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 67,
    'fields': [],
    'encode': encode_ImpinjEnableRFDopplerFrequency,
    'decode': basic_param_decode_generator(ushort_unpack)
}


Param_struct['ImpinjRFDopplerFrequency'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 68,
    'fields': [],
    'decode': basic_param_decode_generator(short_unpack)
}


def decode_ImpinjInventoryConfiguration(data):
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
    'fields': [],
    'decode': basic_param_decode_generator(ushort_unpack)
}


Param_struct['ImpinjTxPower'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 73,
    'fields': [],
    'decode': basic_param_decode_generator(ushort_unpack)
}


def encode_ImpinjAntennaConfiguration(par):
    msg_struct_param = Param_struct['ImpinjAntennaConfiguration']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
    }
    payload = encode('ImpinjAntennaEventConfiguration')(
        par.get('ImpinjAntennaEventConfiguration', True))
    custom_par['Payload'] = payload

    return encode('CustomParameter')(custom_par)


Param_struct['ImpinjAntennaConfiguration'] = {
    'type': TYPE_CUSTOM,
    'vendorid': VENDOR_ID_IMPINJ,
    'subtype': 1524,
    'fields': [
        'ImpinjAntennaEventHysteresis',
        'ImpinjAntennaEventConfiguration'
    ],
    'encode': encode_ImpinjAntennaConfiguration,
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


def decode_ImpinjHubConfiguration(data):
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


def encode_ImpinjIntelligentAntennaManagement(par):
    msg_struct_param = Param_struct['ImpinjIntelligentAntennaManagement']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
    }
    enabled_flags = (int(bool(par)) << 7) & 0xff
    data = struct.pack('!B', enabled_flags)
    custom_par['Payload'] = data

    return encode('CustomParameter')(custom_par)


def decode_ImpinjIntelligentAntennaManagement(data):
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

def decode_ImpinjTIDParity(data):
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


def encode_ImpinjAntennaEventConfiguration(par):
    msg_struct_param = Param_struct['ImpinjAntennaEventConfiguration']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
    }
    enabled_flags = (int(bool(par)) << 7) & 0xff
    data = struct.pack('!B', enabled_flags)
    custom_par['Payload'] = data

    return encode('CustomParameter')(custom_par)


def decode_ImpinjAntennaEventConfiguration(data):
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


def decode_ImpinjRFPowerSweep(data):
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


def llrp_data2xml(msg):
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
    for p in msg:
        sub = msg[p]
        if not isinstance(sub, list) or not sub or not isinstance(sub[0], dict):
            sub = [sub]
        for e in sub:
            ans += __llrp_data2xml(e, p)
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

        self['ROSpec'] = {
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
            'AISpec': {
                'AntennaIDs': antennas,
                'AISpecStopTrigger': {
                    'AISpecStopTriggerType': 'Null',
                    'DurationTriggerValue': 0,
                },
                'InventoryParameterSpec': {
                    'InventoryParameterSpecID': 1,
                    'ProtocolID': AirProtocol['EPCGlobalClass1Gen2'],
                    'AntennaConfiguration': [],
                },
            },
            'ROReportSpec': {
                'ROReportTrigger': 'Upon_N_Tags_Or_End_Of_AISpec',
                'TagReportContentSelector': tagReportContentSelector,
                'N': 0,
            },
        }

        if impinj_tag_content_selector:
            self['ROSpec']['ROReportSpec']\
                ['ImpinjTagReportContentSelector'] = {
                    'ImpinjEnableRFPhaseAngle':
                        impinj_tag_content_selector['EnableRFPhaseAngle'],
                    'ImpinjEnablePeakRSSI':
                        impinj_tag_content_selector['EnablePeakRSSI'],
                    'ImpinjEnableRFDopplerFrequency':
                        impinj_tag_content_selector['EnableRFDopplerFrequency']
                }

        ips = self['ROSpec']['AISpec']['InventoryParameterSpec']


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
                'C1G2InventoryCommand': {
                    'TagInventoryStateAware': False,
                    'C1G2SingulationControl': {
                        'Session': session,
                        'TagPopulation': tag_population,
                        'TagTransitTime': 0
                    },
                }
            }

            # apply one or more tag filters
            tag_filters = []
            for tfm in tag_filter_mask:
                tag_filters.append({
                    'C1G2TagInventoryMask': {
                        'MB': 1,    # EPC bank
                        'Pointer': 0x20,    # Third word starts the EPC ID
                        'TagMask': tfm
                    }
                })
            if tag_filters:
                antconf['C1G2InventoryCommand']['C1G2Filter'] = tag_filters

            if reader_mode:
                rfcont = {
                    'ModeIndex': mode_index,
                    'Tari': override_tari if override_tari else 0,
                }
                antconf['C1G2InventoryCommand']['C1G2RFControl'] = rfcont

            # impinj extension: single mode or dual mode (XXX others?)
            if impinj_search_mode is not None:
                logger.info('impinj_search_mode: %s', impinj_search_mode)
                antconf['C1G2InventoryCommand']\
                    ['ImpinjInventorySearchMode'] = int(impinj_search_mode)

            if frequencies.get('Automatic', False):
                antconf['C1G2InventoryCommand']\
                    ['ImpinjFixedFrequencyList'] = {
                        'FixedFrequencyMode': 1,
                        'ChannelListIndex': []
                    }
            elif len(freq_channel_list) > 1:
                antconf['C1G2InventoryCommand']\
                    ['ImpinjFixedFrequencyList'] = {
                        'FixedFrequencyMode': 2,
                        'ChannelListIndex': freq_channel_list
                    }

            ips['AntennaConfiguration'].append(antconf)

        if duration_sec is not None:
            self['ROSpec']['ROBoundarySpec']['ROSpecStopTrigger'] = {
                'ROSpecStopTriggerType': 'Duration',
                'DurationTriggerValue': int(duration_sec * 1000)
            }
            self['ROSpec']['AISpec']['AISpecStopTrigger'] = {
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
            self['ROSpec']['AISpec']['AISpecStopTrigger'].update({
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
        return llrp_data2xml(self)


class LLRPMessageDict(dict):
    def __repr__(self):
        return llrp_data2xml(self)


# Reverse dictionary for Message_struct types
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
            logging.warning('Pseudo-warning: %s type %s lacks "type" field',
                            obj_name, msgname)
            continue

        if msgtype == TYPE_CUSTOM and (not vendorid or not subtype) \
           and msgname not in ['CUSTOM_MESSAGE', 'CustomParameter']:
            logging.warning('Pseudo-warning: %s type %s lacks "vendorid" or '
                            '"subtype" fields', obj_name, msgname)
            continue

        dest_dict[(msgtype, vendorid, subtype)] = msgname

