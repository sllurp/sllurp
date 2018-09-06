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

#
# TODO: use generic functions from llrp_decoder where possible
#

from __future__ import unicode_literals
import logging
import struct
from collections import defaultdict
from binascii import hexlify, unhexlify

from .util import BIT, BITMASK, func, reverse_dict, iteritems
from . import llrp_decoder
from .llrp_errors import LLRPError
from .log import get_logger

#
# Define exported symbols
#

__all__ = [
    # Class
    "LLRPROSpec",
    "LLRPMessageDict",

    # Misc
    "func",
]

logger = get_logger(__name__)

#
# Local functions
#


def decode(data):
    return Message_struct[data]['decode']


def encode(data):
    return Message_struct[data]['encode']


#
# LLRP defines & structs
#


VER_PROTO_V1 = 1

gen_header = '!HI'
gen_header_len = struct.calcsize(gen_header)
gen_header_unpack = struct.Struct(gen_header).unpack
msg_header = '!HII'
msg_header_unpack = struct.Struct(msg_header).unpack
msg_header_len = struct.calcsize(msg_header)
par_header = '!HH'
par_header_unpack = struct.Struct(par_header).unpack
par_header_len = struct.calcsize(par_header)
tve_header = '!B'
tve_header_unpack = struct.Struct(tve_header).unpack
tve_header_len = struct.calcsize(tve_header)

# Common types unpacks
ubyte_size = struct.calcsize('!B')
ushort_size = struct.calcsize('!H')
uint_size = struct.calcsize('!I')
ubyte_ushort_size = struct.calcsize('!BH')
ushort_ubyte_size = struct.calcsize('!HB')
ushort_ushort_size = struct.calcsize('!HH')
uint_uint_size = struct.calcsize('!II')
ubyte_ubyte_ushort_size = struct.calcsize('!BBH')
ubyte_uint_ushort_size = struct.calcsize('!BIH')
ubyte_uint_uint_size = struct.calcsize('!BII')
ushort_ushort_ushort_size = struct.calcsize('!HHH')

ubyte_unpack = struct.Struct('!B').unpack
ushort_unpack = struct.Struct('!H').unpack
uint_unpack = struct.Struct('!I').unpack
ulonglong_unpack = struct.Struct('!Q').unpack
ubyte_ushort_unpack = struct.Struct('!BH').unpack
ushort_ubyte_unpack = struct.Struct('!HB').unpack
ushort_ushort_unpack = struct.Struct('!HH').unpack
uint_uint_unpack = struct.Struct('!II').unpack
ubyte_ubyte_ushort_unpack = struct.Struct('!BBH').unpack
ubyte_uint_ushort_unpack = struct.Struct('!BIH').unpack
ubyte_uint_uint_unpack = struct.Struct('!BII').unpack
ushort_ushort_ushort_unpack = struct.Struct('!HHH').unpack

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
    #'SpecLoopEvent': 9,
}

EventState_Value2Name = reverse_dict(EventState_Name2Value)

# 13.2.1 ROReportTrigger
ROReportTrigger_Name2Type = {
    'None': 0,
    'Upon_N_Tags_Or_End_Of_AISpec': 1,
    'Upon_N_Tags_Or_End_Of_ROSpec': 2,
    'Upon_N_Seconds': 3,
    'Upon_N_Seconds_Or_End_Of_ROSpec': 4,
    'Upon_N_Milliseconds': 5,
    'Upon_N_Milliseconds_Or_End_Of_ROSpec': 6,
}

# 16.2.1.1.2.1 UHFRFModeTable, to be filled in by capabilities parser
ModeIndex_Name2Type = defaultdict(int)

# 16.2.1.1.2.1
Modulation_Name2Type = {
    'FM0': 0,
    'M2': 1,
    'M4': 2,
    'M8': 3,
    'WISP5pre': 0,
    'WISP5': 0,
}

#
# LLRP Messages
#

Message_struct = {}


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
def decode_GetReaderCapabilitiesResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_GetReaderCapabilitiesResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    ret, body = decode('GeneralDeviceCapabilities')(body)
    if ret:
        msg['GeneralDeviceCapabilities'] = ret

    ret, body = decode('LLRPCapabilities')(body)
    if ret:
        msg['LLRPCapabilities'] = ret

    ret, body = decode('RegulatoryCapabilities')(body)
    if ret:
        msg['RegulatoryCapabilities'] = ret

    if len(body):
        msg['AirProtocolLLRPCapabilities'] = body

    return msg


Message_struct['GET_READER_CAPABILITIES_RESPONSE'] = {
    'type': 11,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
        'GeneralDeviceCapabilities',
        'LLRPCapabilities',
        'RegulatoryCapabilities',
        'AirProtocolLLRPCapabilities'
    ],
    'decode': decode_GetReaderCapabilitiesResponse
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


def decode_Identification(data):
    """Identification parameter (LLRP 1.1 Section 13.2.2)"""
    header_len = struct.calcsize('!HHBH')
    msgtype, msglen, idtype, bytecount = struct.unpack(
        '!HHBH', data[:header_len])
    ret = {}

    idtypes = ['MAC Address', 'EPC']
    try:
        ret['IDType'] = idtypes[idtype]
    except IndexError:
        return {'IDType': b''}, data[msglen:]

    # the remainder is ID value
    ret['ReaderID'] = data[header_len:(header_len+bytecount)]

    return ret, data[msglen:]


Message_struct['Identification'] = {
    'type': 218,
    'fields': ['IDType', 'ByteCount', 'ReaderID'],
    'decode': decode_Identification,
}


def decode_param(data):
    """Decode any parameter to a byte sequence.

    :param data: byte sequence representing an LLRP parameter.
    :returns dict, bytes: where dict is {'Type': <decoded type>, 'Data':
        <decoded data>} and bytes is the remaining bytes trailing the bytes we
        could decode.
    """
    logger.debug('decode_param data: %r', data)
    header_len = struct.calcsize('!HH')
    partype, parlen = struct.unpack('!HH', data[:header_len])

    pardata = data[header_len:parlen]
    logger.debug('decode_param pardata: %r', pardata)

    ret = {
        'Type': partype,
    }

    if partype == 1023:
        vsfmt = '!II'
        vendor, subtype = struct.unpack(vsfmt, pardata[:struct.calcsize(vsfmt)])
        ret['Vendor'] = vendor
        ret['Subtype'] = subtype
        ret['Data'] = pardata[struct.calcsize(vsfmt):]
    else:
        ret['Data'] = pardata,

    return ret, data[parlen:]


def decode_GetReaderConfigResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_GetReaderConfigResponse')

    ret, body = decode('LLRPStatus')(data)
    msg['LLRPStatus'] = ret

    logger.debugfast('TODO: decode rest of GET_READER_CONFIG_RESPONSE')
    return msg


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
    ],
    'decode': decode_GetReaderConfigResponse
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
    ],
    'encode': encode_SetReaderConfig,
}


def decode_SetReaderConfigResponse(data):
    msg = LLRPMessageDict()
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    return msg


Message_struct['SET_READER_CONFIG_RESPONSE'] = {
    'type': 13,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
    ],
    'decode': decode_SetReaderConfigResponse
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
def decode_AddROSpecResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_AddROSpecResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


Message_struct['ADD_ROSPEC_RESPONSE'] = {
    'type': 30,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_AddROSpecResponse
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
def decode_DeleteROSpecResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_DeleteROSpecResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


Message_struct['DELETE_ROSPEC_RESPONSE'] = {
    'type': 31,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_DeleteROSpecResponse
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
def decode_StartROSpecResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_StartROSpecResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


Message_struct['START_ROSPEC_RESPONSE'] = {
    'type': 32,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_StartROSpecResponse
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
def decode_StopROSpecResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_StopROSpecResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


Message_struct['STOP_ROSPEC_RESPONSE'] = {
    'type': 33,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_StopROSpecResponse
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
def decode_EnableROSpecResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_EnableROSpecResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


Message_struct['ENABLE_ROSPEC_RESPONSE'] = {
    'type': 34,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_EnableROSpecResponse
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
def decode_DisableROSpecResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_DisableROSpecResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


Message_struct['DISABLE_ROSPEC_RESPONSE'] = {
    'type': 35,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_DisableROSpecResponse
}


# 16.1.30 RO_ACCESS_REPORT
def decode_ROAccessReport(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_ROAccessReport')

    # Decode parameters
    msg['TagReportData'] = []
    while True:
        try:
            ret, data = decode('TagReportData')(data)
        except TypeError:  # XXX
            logger.error('Unable to decode TagReportData')
            break
        # print('len(ret) = {}'.format(len(ret)))
        # print('len(data) = {}'.format(len(data)))
        if ret:
            msg['TagReportData'].append(ret)
        else:
            break

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
def decode_Keepalive(msg):
    return b''


Message_struct['KEEPALIVE'] = {
    'type': 62,
    'fields': [
        'Ver', 'Type', 'ID',
    ],
    'decode': decode_Keepalive
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
def decode_ReaderEventNotification(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_ReaderEventNotification')

    # Decode parameters
    ret, body = decode('ReaderEventNotificationData')(data)
    if ret:
        msg['ReaderEventNotificationData'] = ret

    # Check the end of the message
    if len(body):
        logger.debugfast('Unprocessed bytes in READER_EVENT_NOTIFICATION: %s',
                         hexlify(body))

    return msg


Message_struct['READER_EVENT_NOTIFICATION'] = {
    'type': 63,
    'fields': [
        'Ver', 'Type', 'ID',
        'ReaderEventNotificationData'
    ],
    'decode': decode_ReaderEventNotification
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
def decode_CloseConnectionResponse(data):
    msg = LLRPMessageDict()
    logger.debugfast('decode_CloseConnectionResponse')

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return msg


# 16.1.41 CLOSE_CONNECTION_RESPONSE
Message_struct['CLOSE_CONNECTION_RESPONSE'] = {
    'type': 4,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_CloseConnectionResponse
}

# 16.2.2.1 UTCTimestamp Parameter
def decode_UTCTimestamp(data):
    logger.debugfast('decode_UTCTimestamp')
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['UTCTimestamp']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_UTCTimestamp', msgtype, length)

    # Decode fields
    par['Microseconds'] = ulonglong_unpack(body)[0]

    return par, data[length:]


def encode_UTCTimestamp(par):
    msgtype = Message_struct['UTCTimestamp']['type']
    msg = '!HHQ'
    msg_len = struct.calcsize(msg_header)
    data = struct.pack(msg, msgtype, msg_len, par['Microseconds'])
    return data


Message_struct['UTCTimestamp'] = {
    'type': 128,
    'fields': [
        'Type',
        'Microseconds'
    ],
    'decode': decode_UTCTimestamp,
    'encode': encode_UTCTimestamp,
}


def decode_RegulatoryCapabilities(data):
    logger.debugfast('decode_RegulatoryCapabilities')
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['RegulatoryCapabilities']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_RegulatoryCapabilities',
                     msgtype, length)

    # Decode fields
    par['CountryCode'], par['CommunicationsStandard'] = \
         ushort_ushort_unpack(body[:ushort_ushort_size])

    body = body[ushort_ushort_size:]
    ret, body = decode('UHFBandCapabilities')(body)
    if ret:
        par['UHFBandCapabilities'] = ret

    return par, data[length:]


Message_struct['RegulatoryCapabilities'] = {
    'type': 143,
    'fields': [
        'Type',
        'CountryCode',
        'CommunicationsStandard',
        'UHFBandCapabilities'
    ],
    'decode': decode_RegulatoryCapabilities
}


def decode_UHFBandCapabilities(data):
    logger.debugfast('decode_UHFBandCapabilities')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['UHFBandCapabilities']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_UHFBandCapabilities', msgtype,
                     length)

    # Decode fields
    i = 0
    ret, body = decode('TransmitPowerLevelTableEntry')(body)
    while ret:
        par['TransmitPowerLevelTableEntry' + str(i)] = ret
        ret, body = decode('TransmitPowerLevelTableEntry')(body)
        i += 1

    ret, body = decode('FrequencyInformation')(body)
    if ret:
        par['FrequencyInformation'] = ret

    ret, body = decode('UHFRFModeTable')(body)
    if ret:
        par['UHFRFModeTable'] = ret

    ret, body = decode('RFSurveyFrequencyCapabilities')(body)
    if ret:
        par['RFSurveyFrequencyCapabilities'] = ret
    return par, data[length:]


Message_struct['UHFBandCapabilities'] = {
    'type': 144,
    'fields': [
        'Type',
        'TransmitPowerLevelTableEntry',
        'FrequencyInformation',
        'UHFRFModeTable',
        'RFSurveyFrequencyCapabilities'
    ],
    'decode': decode_UHFBandCapabilities
}


def decode_TransmitPowerLevelTableEntry(data):
    logger.debugfast('decode_TransmitPowerLevelTableEntry')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['TransmitPowerLevelTableEntry']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_TransmitPowerLevelTableEntry',
                     msgtype, length)

    # Decode fields
    par['Index'], par['TransmitPowerValue'] = ushort_ushort_unpack(body)

    return par, data[length:]


Message_struct['TransmitPowerLevelTableEntry'] = {
    'type': 145,
    'fields': [
        'Type',
        'Index',
        'TransmitPowerValue'
    ],
    'decode': decode_TransmitPowerLevelTableEntry
}


def decode_FrequencyInformation(data):
    logger.debugfast('decode_FrequencyInformation')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['FrequencyInformation']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_FrequencyInformation', msgtype,
                     length)

    # Decode fields
    flags = ubyte_unpack(body[:ubyte_size])[0]
    par['Hopping'] = flags & BIT(7) == BIT(7)
    body = body[ubyte_size:]

    i = 0
    ret, body = decode('FrequencyHopTable')(body)
    while ret:
        par['FrequencyHopTable' + str(i)] = ret
        ret, body = decode('FrequencyHopTable')(body)
        i += 1

    ret, body = decode('FixedFrequencyTable')(body)
    if ret:
        par['FixedFrequencyTable'] = ret

    return par, data[length:]


Message_struct['FrequencyInformation'] = {
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
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['FrequencyHopTable']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_FrequencyHopTable', msgtype,
                     length)

    # Decode fields
    par['HopTableId'], flags, par['NumHops'] = \
        ubyte_ubyte_ushort_unpack(body[:ubyte_ubyte_ushort_size])
    body = body[ubyte_ubyte_ushort_size:]

    num = int(par['NumHops'])
    for x in range(1, num + 1):
        par['Frequency' + str(x)] = uint_unpack(body[:uint_size])[0]
        body = body[uint_size:]

    return par, data[length:]


Message_struct['FrequencyHopTable'] = {
    'type': 147,
    'fields': [
        'Type',
        'HopTableId',
        'NumHops',
        'Frequencies'
    ],
    'decode': decode_FrequencyHopTable
}


def decode_FixedFrequencyTable(data):
    logger.debugfast('decode_FixedFrequencyTable')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['FixedFrequencyTable']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_FixedFrequencyTable', msgtype,
                     length)

    # Decode fields
    par['NumFrequencies'] = ushort_unpack(body[:ushort_size])[0]
    body = body[ushort_size:]

    num = int(par['NumFrequencies'])
    for x in range(1, num + 1):
        par['Frequency' + str(x)] = uint_unpack(body[:uint_size])[0]
        body = body[uint_size:]

    return par, data[length:]


Message_struct['FixedFrequencyTable'] = {
    'type': 148,
    'fields': [
        'Type',
        'NumFrequencies',
        'Frequencies'
    ],
    'decode': decode_FixedFrequencyTable
}


def decode_UHFRFModeTable(data):
    logger.debugfast('decode_UHFRFModeTable')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    logger.debugfast('%s (type=%d len=%d)', 'decode_UHFRFModeTable', msgtype, length)

    if msgtype != Message_struct['UHFRFModeTable']['type']:
        return (None, data)

    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_UHFRFModeTable', msgtype,
                     length)

    # Decode fields
    i = 0
    ret, body = decode('UHFC1G2RFModeTableEntry')(body)
    while ret:
        par['UHFC1G2RFModeTableEntry' + str(i)] = ret
        ret, body = decode('UHFC1G2RFModeTableEntry')(body)
        i += 1

    return par, data[length:]


Message_struct['UHFRFModeTable'] = {
    'type': 328,
    'fields': [
        'Type',
        'UHFC1G2RFModeTableEntry'
    ],
    'decode': decode_UHFRFModeTable
}

mode_table_entry_unpack = struct.Struct('!IBBBBIIIII').unpack

def decode_UHFC1G2RFModeTableEntry(data):
    logger.debugfast('decode_UHFC1G2RFModeTableEntry')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    logger.debugfast('%s (type=%d len=%d)', 'decode_UHFC1G2RFModeTableEntry',
                     msgtype, length)

    if msgtype != Message_struct['UHFC1G2RFModeTableEntry']['type']:
        return (None, data)

    body = data[par_header_len:length]

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
     par['StepTari']) = mode_table_entry_unpack(body)

    # parse RC
    par['R'] = RC >> 7
    par['C'] = (RC >> 6) & 1

    return par, data[length:]


Message_struct['UHFC1G2RFModeTableEntry'] = {
    'type': 329,
    'fields': [
        'Type',
        'ModeIdentifier',
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


def decode_RFSurveyFrequencyCapabilities(data):
    logger.debugfast('decode_RFSurveyFrequencyCapabilities')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)

    if msgtype != Message_struct['RFSurveyFrequencyCapabilities']['type']:
        return (None, data)

    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_RFSurveyFrequencyCapabilities',
                     msgtype, length)

    # Decode fields
    (par['MinimumFrequency'],
     par['MaximumFrequency']) = uint_uint_unpack(body)

    return par, data[length:]


Message_struct['RFSurveyFrequencyCapabilities'] = {
    'type': 365,
    'fields': [
        'Type',
        'MinimumFrequency',
        'MaximumFrequency'
    ],
    'decode': decode_RFSurveyFrequencyCapabilities
}


# 16.2.3.2 LLRPCapabilities Parameter
llrp_capabilities_unpack = struct.Struct('!BBHIIIII').unpack

def decode_LLRPCapabilities(data):
    logger.debugfast('decode_LLRPCapabilities')
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['LLRPCapabilities']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_LLRPCapabilities', msgtype,
                     length)

    # Decode fields
    (flags,
     par['MaxPriorityLevelSupported'],
     par['ClientRequestOpSpecTimeout'],
     par['MaxNumROSpec'],
     par['MaxNumSpecsPerROSpec'],
     par['MaxNumInventoryParametersSpecsPerAISpec'],
     par['MaxNumAccessSpec'],
     par['MaxNumOpSpecsPerAccessSpec']) = llrp_capabilities_unpack(body)

    par['CanDoRFSurvey'] = (flags & BIT(7) == BIT(7))
    par['CanReportBufferFillWarning'] = (flags & BIT(6) == BIT(6))
    par['SupportsClientRequestOpSpec'] = (flags & BIT(5) == BIT(5))
    par['CanDoTagInventoryStateAwareSingulation'] = (flags & BIT(4) == BIT(4))
    par['SupportsEventAndReportHolding'] = (flags & BIT(3) == BIT(3))

    return par, data[length:]


Message_struct['LLRPCapabilities'] = {
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

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['GeneralDeviceCapabilities']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_GeneralDeviceCapabilities',
                     msgtype, length)

    fmt = '!HHIIH'
    fmt_len = struct.calcsize(fmt)
    # Decode fields
    (par['MaxNumberOfAntennaSupported'],
     flags,
     par['DeviceManufacturerName'],
     par['ModelName'],
     par['FirmwareVersionByteCount']) = \
         general_dev_capa_begin_unpack(body[:general_dev_capa_begin_size])

    par['CanSetAntennaProperties'] = (flags & BIT(15) == BIT(15))
    par['HasUTCClockCapability'] = (flags & BIT(14) == BIT(14))

    pastVer = general_dev_capa_begin_size + par['FirmwareVersionByteCount']
    par['ReaderFirmwareVersion'] = body[general_dev_capa_begin_size:pastVer]
    body = body[pastVer:]
    ret, body = decode('ReceiveSensitivityTableEntry')(body)
    if ret:
        par['ReceiveSensitivityTableEntry'] = ret

    ret, body = decode('PerAntennaReceiveSensitivityRange')(body)
    if ret:
        par['PerAntennaReceiveSensitivityRange'] = ret

    ret, body = decode('GPIOCapabilities')(body)
    if ret:
        par['GPIOCapabilities'] = ret

    ret, body = decode('PerAntennaAirProtocol')(body)
    if ret:
        par['PerAntennaAirProtocol'] = ret

    ret, body = decode('MaximumReceiveSensitivity')(body)
    if ret:
        par['MaximumReceiveSensitivity'] = ret

    return par, data[length:]


Message_struct['GeneralDeviceCapabilities'] = {
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


def decode_MaximumReceiveSensitivity(data):
    logger.debugfast('decode_MaximumReceiveSensitivity')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['MaximumReceiveSensitivity']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_MaximumReceiveSensitivity',
                     msgtype, length)

    # Decode fields
    par['MaximumSensitivityValue'] = ushort_unpack(body)[0]

    return par, data[length:]


Message_struct['MaximumReceiveSensitivity'] = {
    'type': 363,
    'fields': [
        'Type',
        'MaximumSensitivityValue'
    ],
    'decode': decode_MaximumReceiveSensitivity
}


def decode_ReceiveSensitivityTableEntry(data):
    logger.debugfast('decode_ReceiveSensitivityTableEntry')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ReceiveSensitivityTableEntry']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_ReceiveSensitivityTableEntry',
                     msgtype, length)

    # Decode fields
    (par['Index'],
     par['ReceiveSensitivityValue']) = ushort_ushort_unpack(body)

    return par, data[length:]


Message_struct['ReceiveSensitivityTableEntry'] = {
    'type': 139,
    'fields': [
        'Type',
        'Index',
        'ReceiveSensitivityValue'
    ],
    'decode': decode_ReceiveSensitivityTableEntry
}


def decode_PerAntennaReceiveSensitivityRange(data):
    logger.debugfast('decode_PerAntennaReceiveSensitivityRange')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['PerAntennaReceiveSensitivityRange']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('decode_PerAntennaReceiveSensitivityRange (len=%d)',
                     length)

    # Decode fields
    (par['AntennaID'],
     par['ReceiveSensitivityIndexMin'],
     par['ReceiveSensitivityIndexMax']) = ushort_ushort_ushort_unpack(body)

    return par, data[length:]


Message_struct['PerAntennaReceiveSensitivityRange'] = {
    'type': 149,
    'fields': [
        'Type',
        'AntennaID',
        'ReceiveSensitivityIndexMin',
        'ReceiveSensitivityIndexMax'
    ],
    'decode': decode_PerAntennaReceiveSensitivityRange
}


def decode_PerAntennaAirProtocol(data):
    logger.debugfast('decode_PerAntennaAirProtocol')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['PerAntennaAirProtocol']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_PerAntennaAirProtocol',
                     msgtype, length)

    # Decode fields
    (par['AntennaID'],
     par['NumProtocols']) = ushort_ushort_unpack(body[:ushort_ushort_size])
    body = body[ushort_ushort_size:]

    num = int(par['NumProtocols'])
    for i in range(num):
        par['ProtocolID{}'.format(i + 1)] = \
            ubyte_unpack(body[i:i+ubyte_size])[0]

    return par, data[length:]


Message_struct['PerAntennaAirProtocol'] = {
    'type': 140,
    'fields': [
        'Type',
        'AntennaID',
        'NumProtocols',
        'ProtocolIDs'
    ],
    'decode': decode_PerAntennaAirProtocol
}


def decode_GPIOCapabilities(data):
    logger.debugfast('decode_GPIOCapabilities')
    par = {}
    if len(data) == 0:
        return None, data
    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['GPIOCapabilities']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_GPIOCapabilities', msgtype,
                     length)

    # Decode fields
    par['NumGPIs'], par['NumGPIs'] = ushort_ushort_unpack(body)

    return par, data[length:]


Message_struct['GPIOCapabilities'] = {
    'type': 141,
    'fields': [
        'Type',
        'NumGPIs',
        'NumGPOs'
    ],
    'decode': decode_GPIOCapabilities
}


def decode_ErrorMessage(data):
    logger.debugfast('decode_ErrorMessage')
    msg = LLRPMessageDict()
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')
    return msg


Message_struct['ErrorMessage'] = {
    'type': 100,
    'fields': [
        'Type',
        'MessageLength',
        'MessageID',
        'LLRPStatus'
    ],
    'decode': decode_ErrorMessage
}


# 16.2.4.1 ROSpec Parameter
def encode_ROSpec(par):
    msgtype = Message_struct['ROSpec']['type']
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


Message_struct['ROSpec'] = {
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
    msgtype = Message_struct['AccessSpec']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!I', int(par['AccessSpecID']))
    data += struct.pack('!H', int(par['AntennaID']))
    data += struct.pack('!B', par['ProtocolID'])
    data += struct.pack('!B', par['C'] and (1 << 7) or 0)
    data += struct.pack('!I', par['ROSpecID'])

    data += encode('AccessSpecStopTrigger')(par['AccessSpecStopTrigger'])
    data += encode('AccessCommand')(par['AccessCommand'])
    if 'AccessReportSpec' in par:
        data += encode('AccessReportSpec')(par['AccessReportSpec'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


# 17.2.5.1 AccessSpec
Message_struct['AccessSpec'] = {
    'type': 207,
    'fields': [
        'Type',
        'AccessSpecID',
        'AntennaID',
        'ProtocolID',
        'C',
        'ROSpecID',
        'AccessSpecStopTrigger',
        'AccessCommand',
        'AccessReportSpec'
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
def decode_AddAccessSpecResponse(msg):
    # just an LLRPStatus wrapper, same format as ADD_ROSPEC_RESPONSE
    return decode_AddROSpecResponse(msg)


# 17.1.22 ADD_ACCESSSPEC_RESPONSE
Message_struct['ADD_ACCESSSPEC_RESPONSE'] = {
    'type': 50,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_AddAccessSpecResponse
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
def decode_DeleteAccessSpecResponse(msg):
    # just an LLRPStatus wrapper, same format as ADD_ROSPEC_RESPONSE
    return decode_DeleteROSpecResponse(msg)


# 17.1.24 DELETE_ACCESSSPEC_RESPONSE
Message_struct['DELETE_ACCESSSPEC_RESPONSE'] = {
    'type': 51,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_DeleteAccessSpecResponse
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
def decode_EnableAccessSpecResponse(msg):
    # just an LLRPStatus wrapper, same format as ADD_ROSPEC_RESPONSE
    return decode_EnableROSpecResponse(msg)


# 17.1.26 ENABLE_ACCESSSPEC_RESPONSE
Message_struct['ENABLE_ACCESSSPEC_RESPONSE'] = {
    'type': 52,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_EnableAccessSpecResponse
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
def decode_DisableAccessSpecResponse(msg):
    # just an LLRPStatus wrapper, same format as ADD_ROSPEC_RESPONSE
    return decode_DisableROSpecResponse(msg)


# 17.1.28 DISABLE_ACCESSSPEC_RESPONSE
Message_struct['DISABLE_ACCESSSPEC_RESPONSE'] = {
    'type': 53,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus'
    ],
    'decode': decode_DisableAccessSpecResponse
}


def encode_AccessSpecStopTrigger(par):
    msgtype = Message_struct['AccessSpecStopTrigger']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', int(par['AccessSpecStopTriggerType']))
    data += struct.pack('!H', int(par['OperationCountValue']))

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Message_struct['AccessSpecStopTrigger'] = {
    'type': 208,
    'fields': [
        'Type',
        'AccessSpecStopTriggerType',
        'OperationCountValue'
    ],
    'encode': encode_AccessSpecStopTrigger
}


def encode_AccessCommand(par):
    msgtype = Message_struct['AccessCommand']['type']
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


Message_struct['AccessCommand'] = {
    'type': 209,
    'fields': [
        'Type',
        'TagSpecParameter',
        'OpSpecParameter'
    ],
    'encode': encode_AccessCommand
}


def encode_C1G2TagSpec(par):
    msgtype = Message_struct['C1G2TagSpec']['type']
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


Message_struct['C1G2TagSpec'] = {
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
    msgtype = Message_struct['C1G2TargetTag']['type']
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


Message_struct['C1G2TargetTag'] = {
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
    msgtype = Message_struct['C1G2Read']['type']
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


Message_struct['C1G2Read'] = {
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
    msgtype = Message_struct['C1G2Write']['type']
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


Message_struct['C1G2Write'] = {
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
    msgtype = Message_struct['C1G2Lock']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!H', int(par['OpSpecID']))
    data += struct.pack('!I', int(par['AccessPassword']))
    for payload in par['LockPayload']:
        data += encode_C1G2LockPayload(payload)

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Message_struct['C1G2Lock'] = {
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
    msgtype = Message_struct['C1G2LockPayload']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', int(par['Privilege']))
    data += struct.pack('!b', int(par['DataField']))

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data
    return data


Message_struct['C1G2LockPayload'] = {
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
    msgtype = Message_struct['C1G2BlockWrite']['type']
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


Message_struct['C1G2BlockWrite'] = {
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
    msgtype = Message_struct['AccessReportSpec']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', par['AccessReportTrigger'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Message_struct['AccessReportSpec'] = {
    'type': 239,
    'fields': [
        'Type',
        'AccessReportTrigger'
    ],
    'encode': encode_AccessReportSpec
}


# 16.2.4.1.1 ROBoundarySpec Parameter
def encode_ROBoundarySpec(par):
    msgtype = Message_struct['ROBoundarySpec']['type']

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = encode('ROSpecStartTrigger')(par['ROSpecStartTrigger'])
    data += encode('ROSpecStopTrigger')(par['ROSpecStopTrigger'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Message_struct['ROBoundarySpec'] = {
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
    msgtype = Message_struct['ROSpecStartTrigger']['type']
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


Message_struct['ROSpecStartTrigger'] = {
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
    msgtype = Message_struct['PeriodicTriggerValue']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!I', par['Offset'])
    data += struct.pack('!I', par['Period'])
    if 'UTCTimestamp' in par:
        data += encode('UTCTimestamp')(par['UTCTimestamp'])

    data = struct.pack(msg_header, msgtype, len(data) + msg_header_len) + data
    return data


# 16.2.4.1.1.1 PeriodicTriggerValue Parameter
Message_struct['PeriodicTriggerValue'] = {
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
    msgtype = Message_struct['ROSpecStopTrigger']['type']
    t_type = StopTrigger_Name2Type[par['ROSpecStopTriggerType']]
    duration = par['DurationTriggerValue']

    msg_header = '!HHBI'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack(msg_header, msgtype, msg_header_len, t_type, duration)
    return data


Message_struct['ROSpecStopTrigger'] = {
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
    msgtype = Message_struct['AISpec']['type']

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


Message_struct['AISpec'] = {
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
    msgtype = Message_struct['AISpecStopTrigger']['type']
    t_type = StopTrigger_Name2Type[par['AISpecStopTriggerType']]
    duration = int(par['DurationTriggerValue'])

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!B', t_type)
    data += struct.pack('!I', int(duration))
    if 'GPITriggerValue' in par:
        # TODO implement GPITriggerValue Message_struct
        data += encode('GPITriggerValue')(par['GPITriggerValue'])
    if 'TagObservationTrigger' in par:
        data += encode('TagObservationTrigger')(par['TagObservationTrigger'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len) + data

    return data


Message_struct['AISpecStopTrigger'] = {
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
    msgtype = Message_struct['TagObservationTrigger']['type']
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


Message_struct['TagObservationTrigger'] = {
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
    msgtype = Message_struct['InventoryParameterSpec']['type']

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


Message_struct['InventoryParameterSpec'] = {
    'type': 186,
    'fields': [
        'Type',
        'InventoryParameterSpecID',
        'ProtocolID',
        'AntennaConfiguration'
    ],
    'encode': encode_InventoryParameterSpec
}


# 16.2.6.6 AntennaConfiguration Parameter
def encode_AntennaConfiguration(par):
    msgtype = Message_struct['AntennaConfiguration']['type']
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


Message_struct['AntennaConfiguration'] = {
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
    'encode': encode_AntennaConfiguration
}


# 16.2.6.7 RFReceiver Parameter
def encode_RFReceiver(par):
    msgtype = Message_struct['RFReceiver']['type']
    msg_header = '!HH'
    data = struct.pack('!H', par['ReceiverSensitivity'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Message_struct['RFReceiver'] = {
    'type': 223,
    'fields': [
        'Type',
        'ReceiverSensitivity',
    ],
    'encode': encode_RFReceiver
}


# 16.2.6.8 RFTransmitter Parameter
def encode_RFTransmitter(par):
    msgtype = Message_struct['RFTransmitter']['type']
    msg_header = '!HH'
    data = struct.pack('!H', par['HopTableId'])
    data += struct.pack('!H', par['ChannelIndex'])
    data += struct.pack('!H', par['TransmitPower'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Message_struct['RFTransmitter'] = {
    'type': 224,
    'fields': [
        'Type',
        'HopTableId',
        'ChannelIndex',
        'TransmitPower',
    ],
    'encode': encode_RFTransmitter
}


# 16.3.1.2.1 C1G2InventoryCommand Parameter
def encode_C1G2InventoryCommand(par):
    msgtype = Message_struct['C1G2InventoryCommand']['type']
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
    if 'ImpinjInventorySearchModeParameter' in par:
        data += encode('ImpinjInventorySearchModeParameter')(
            par['ImpinjInventorySearchModeParameter'])
    if 'ImpinjFixedFrequencyListParameter' in par:
        data += encode('ImpinjFixedFrequencyListParameter')(
            par['ImpinjFixedFrequencyListParameter'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Message_struct['C1G2InventoryCommand'] = {
    'type': 330,
    'fields': [
        'TagInventoryStateAware',
        'C1G2Filter',
        'C1G2RFControl',
        'C1G2SingulationControl',
        # XXX custom parameters
        'ImpinjInventorySearchModeParameter',
        'ImpinjFixedFrequencyListParameter'
    ],
    'encode': encode_C1G2InventoryCommand
}


# 16.3.1.2.1.1 C1G2Filter Parameter
def encode_C1G2Filter(par):
    msgtype = Message_struct['C1G2Filter']['type']
    msg_header = '!HH'
    data = struct.pack('!B', Message_struct['C1G2Filter']['T'] << 6) # XXX: hardcoded trucation for now
    if 'C1G2TagInventoryMask' in par:
        data += encode('C1G2TagInventoryMask')(
            par['C1G2TagInventoryMask'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Message_struct['C1G2Filter'] = {
    'type': 331,
    'T': 0,
    'fields': [
        'C1G2TagInventoryMask'
    ],
    'encode': encode_C1G2Filter
}

# 16.3.1.2.1.1.1 C1G2TagInventoryMask Parameter
def encode_C1G2TagInventoryMask(par):
    msgtype = Message_struct['C1G2TagInventoryMask']['type']
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

Message_struct['C1G2TagInventoryMask'] = {
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
    msgtype = Message_struct['C1G2RFControl']['type']
    msg_header = '!HH'
    data = struct.pack('!H', par['ModeIndex'])
    data += struct.pack('!H', par['Tari'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Message_struct['C1G2RFControl'] = {
    'type': 335,
    'fields': [
        'ModeIndex',
        'Tari',
    ],
    'encode': encode_C1G2RFControl
}


# 16.3.1.2.1.3 C1G2SingulationControl Parameter
def encode_C1G2SingulationControl(par):
    msgtype = Message_struct['C1G2SingulationControl']['type']
    msg_header = '!HH'
    data = struct.pack('!B', par['Session'] << 6)
    data += struct.pack('!H', par['TagPopulation'])
    data += struct.pack('!I', par['TagTransitTime'])
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data
    return data


Message_struct['C1G2SingulationControl'] = {
    'type': 336,
    'fields': [
        'Session',
        'TagPopulation',
        'TagTransitTime',
    ],
    'encode': encode_C1G2SingulationControl
}


# 16.2.7.1 ROReportSpec Parameter
def encode_ROReportSpec(par):
    msgtype = Message_struct['ROReportSpec']['type']
    n = int(par['N'])
    roReportTrigger = ROReportTrigger_Name2Type[par['ROReportTrigger']]

    msg_header = '!HHBH'
    msg_header_len = struct.calcsize(msg_header)

    data = encode('TagReportContentSelector')(par['TagReportContentSelector'])
    if 'ImpinjTagReportContentSelectorParameter' in par:
        data += encode('ImpinjTagReportContentSelectorParameter')(
            par['ImpinjTagReportContentSelectorParameter'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + msg_header_len,
                       roReportTrigger, n) + data

    return data


Message_struct['ROReportSpec'] = {
    'type': 237,
    'fields': [
        'N',
        'ROReportTrigger',
        'TagReportContentSelector',
        'ImpinjTagReportContentSelectorParameter',
    ],
    'encode': encode_ROReportSpec
}


def encode_ReaderEventNotificationSpec(par):
    msgtype = Message_struct['ReaderEventNotificationSpec']['type']
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


Message_struct['ReaderEventNotificationSpec'] = {
    'type': 244,
    'fields': [
        'EventNotificationState',
    ],
    'encode': encode_ReaderEventNotificationSpec
}


# 16.2.7.1 TagReportContentSelector Parameter
def encode_TagReportContentSelector(par):
    msgtype = Message_struct['TagReportContentSelector']['type']

    msg_header = '!HH'

    flags = 0
    i = 15
    for field in Message_struct['TagReportContentSelector']['fields']:
        if field in par and par[field]:
            flags = flags | (1 << i)
        i = i - 1
    data = struct.pack('!H', flags)

    if 'C1G2EPCMemorySelector' in par:
        data += encode('C1G2EPCMemorySelector')(par['C1G2EPCMemorySelector'])

    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data

    return data


Message_struct['TagReportContentSelector'] = {
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
        'EnableAccessSpecID'
    ],
    'encode': encode_TagReportContentSelector
}

# 15.2.1.5.1 C1G2EPCMemorySelector Parameter
def encode_C1G2EPCMemorySelector(par):
    msgtype = Message_struct['C1G2EPCMemorySelector']['type']
    msg_header = '!HH'

    flags = 0
    i = 7
    for field in Message_struct['C1G2EPCMemorySelector']['fields']:
        if field in par and par[field]:
            flags = flags | (1 << i)
        i = i - 1

    data = struct.pack('!B', flags)
    data = struct.pack(msg_header, msgtype,
                       len(data) + struct.calcsize(msg_header)) + data

    return data


Message_struct['C1G2EPCMemorySelector'] = {
    'type': 348,
    'fields': [
        'EnableCRC',
        'EnablePCBits',
        # New in protocol v2 (llrp 1_1)
        #'EnableXPCBits'
    ],
    'encode': encode_C1G2EPCMemorySelector
}

# 16.2.7.3 TagReportData Parameter
def decode_TagReportData(data):
    par = {}
    logger.debugfast('decode_TagReportData')

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['TagReportData']['type']:
        return (None, data)
    body = data[par_header_len:length]

    # Decode parameters
    ret, body = decode('EPCData')(body)
    if ret:
        logger.debugfast("got EPCData; won't try EPC-96")
        par['EPCData'] = ret
    else:
        logger.debugfast('failed to decode EPCData; trying EPC-96')
        ret, body = decode('EPC-96')(body)
        if ret:
            par['EPC-96'] = ret['EPC']
            logger.debugfast('EPC-96: %s', ret['EPC'])
        else:
            raise LLRPError('missing or invalid EPCData parameter')

    # grab TV-encoded parameters
    while body:
        ret, nbytes = llrp_decoder.decode_tve_parameter(body)
        if ret:
            par.update(ret)
            body = body[nbytes:]
        else:
            break

    ret, body = decode_OpSpecResult(body)
    if ret:
        par['OpSpecResult'] = ret

    logger.debugfast('par=%s', par)
    return par, data[length:]


Message_struct['TagReportData'] = {
    'type': 240,
    'fields': [
        'Type',
        'EPCData',
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
        'OpSpecResult',
        ## Custom parameters:
        'ImpinjPhase',
        'ImpinjPeakRSSI',
        'ImpinjRFDopplerFrequency'
    ],
    'decode': decode_TagReportData
}


def decode_OpSpecResult(data):
    # handle any of the C1G2*OpSpecResult types
    par = {}
    logger.debugfast('decode_OpSpecResult')

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    c1g2opspecresults = ('C1G2ReadOpSpecResult',
                         'C1G2WriteOpSpecResult',
                         'C1G2KillOpSpecResult',
                         'C1G2RecommissionOpSpecResult',
                         'C1G2LockOpSpecResult',
                         'C1G2BlockEraseOpSpecResult',
                         'C1G2BlockWriteOpSpecResult',
                         'C1G2BlockPermalockOpSpecResult',
                         'C1G2GetBlockPermalockStatusOpSpecResult')
    ok_types = (Message_struct[x]['type'] for x in c1g2opspecresults)
    if msgtype not in ok_types:
        return (None, data)
    body = data[par_header_len:length]

    # all OpSpecResults begin with Result and OpSpecID
    par['Result'], par['OpSpecID'] = \
        ubyte_ushort_unpack(body[:ubyte_ushort_size])
    body = body[ubyte_ushort_size:]

    if msgtype == Message_struct['C1G2ReadOpSpecResult']['type']:
        wordcnt = ushort_unpack(body[:ushort_size])[0]
        par['ReadDataWordCount'] = wordcnt
        end = ushort_size + (wordcnt * 2)
        par['ReadData'] = body[ushort_size:end]

    elif msgtype in (Message_struct['C1G2WriteOpSpecResult']['type'],
                     Message_struct['C1G2BlockWriteOpSpecResult']['type']):
        par['NumWordsWritten'] = ushort_unpack(body[:ushort_size])[0]

    psosr = Message_struct['C1G2GetBlockPermalockStatusOpSpecResult']
    if msgtype == psosr['type']:
        wordcnt = ushort_unpack(body[:ushort_size])[0]
        par['StatusWordCount'] = wordcnt
        end = ushort_size + (wordcnt * 2)
        par['PermalockStatus'] = body[ushort_size:end]

    return par, data[length:]


Message_struct['OpSpecResult'] = {
    'type': -1,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'ReadDataWordCount',
        'ReadData',
        'NumWordsWritten',
        'StatusWordCount',
        'PermalockStatus'
    ],
    'decode': lambda: None
}

Message_struct['C1G2ReadOpSpecResult'] = {
    'type': 349,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'ReadDataWordCount',
        'ReadData'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2WriteOpSpecResult'] = {
    'type': 350,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'NumWordsWritten'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2KillOpSpecResult'] = {
    'type': 351,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2RecommissionOpSpecResult'] = {
    'type': 360,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2LockOpSpecResult'] = {
    'type': 352,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2BlockEraseOpSpecResult'] = {
    'type': 353,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2BlockWriteOpSpecResult'] = {
    'type': 354,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'NumWordsWritten'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2BlockPermalockOpSpecResult'] = {
    'type': 361,
    'fields': [
        'Type',
        'Result',
        'OpSpecID'
    ],
    'decode': decode_OpSpecResult
}

Message_struct['C1G2GetBlockPermalockStatusOpSpecResult'] = {
    'type': 362,
    'fields': [
        'Type',
        'Result',
        'OpSpecID',
        'StatusWordCount',
        'PermalockStatus'
    ],
    'decode': decode_OpSpecResult
}


# 16.2.7.3.1 EPCData Parameter
def decode_EPCData(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['EPCData']['type']:
        return (None, data)
    body = data[par_header_len:length]
    #logger.debugfast('decode_EPCData (len=%d)', length)

    # Decode fields
    par['EPCLengthBits'] = ushort_unpack(body[0:ushort_size])[0]
    par['EPC'] = hexlify(body[ushort_size:])

    return par, data[length:]


Message_struct['EPCData'] = {
    'type': 241,
    'fields': [
        'Type',
        'EPCLengthBits',
        'EPC'
    ],
    'decode': decode_EPCData
}


# 16.2.7.3.2 EPC-96 Parameter
def decode_EPC96(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:tve_header_len]
    msgtype = tve_header_unpack(header)[0]
    msgtype = msgtype & BITMASK(7)
    if msgtype != Message_struct['EPC-96']['type']:
        return (None, data)
    # (EPC-96 bits) (96 // 8) = 12 bytes
    length = tve_header_len + 12
    body = data[tve_header_len:length]
    #logger.debugfast('decode_EPC96 (type=%d)', length)

    # Decode fields
    par['EPC'] = hexlify(body)

    return par, data[length:]


Message_struct['EPC-96'] = {
    'type': 13,
    'fields': [
        'Type',
        'EPC'
    ],
    'decode': decode_EPC96,
    'tv_encoded': True,
}


# 16.2.7.3.3 ROSpecID Parameter
def decode_ROSpecID(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:tve_header_len]
    msgtype, length = tve_header_unpack(header)[0], 1 + 4
    msgtype = msgtype & BITMASK(7)
    if msgtype != Message_struct['ROSpecID']['type']:
        return (None, data)
    body = data[tve_header_len:length]
    logger.debugfast('decode_ROSpecID (type=%d len=%d)', msgtype, length)

    # Decode fields
    par['ROSpecID'] = uint_unpack(body)[0]

    return par, data[length:]


Message_struct['ROSpecID'] = {
    'type': 9,
    'fields': [
        'Type',
        'ROSpecID'
    ],
    'decode': decode_ROSpecID,
    'tv_encoded': True,
}

# 16.2.7.6.1 HoppingEvent Parameter
def decode_HoppingEvent(data):
    logger.debugfast('decode_HoppingEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['HoppingEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_HoppingEvent', msgtype,
                     length)

    # Decode fields
    par['HopTableID'], par['NextChannelIndex'] = ushort_ushort_unpack(body)

    return par, data[length:]

Message_struct['HoppingEvent'] = {
    'type': 247,
    'fields': [
        'Type',
        'HopTableID',
        'NextChannelIndex'
    ],
    'decode': decode_HoppingEvent
}

# 16.2.7.6.2 GPIEvent Parameter
def decode_GPIEvent(data):
    logger.debugfast('decode_GPIEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['GPIEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_GPIEvent', msgtype, length)

    # Decode fields
    par['GPIPortNumber'], flags = ushort_ubyte_unpack(body)
    par['GPIEvent'] = flags & BIT(7) == BIT(7)

    return par, data[length:]

Message_struct['GPIEvent'] = {
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

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ROSpecEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_ROSpecEvent', msgtype,
                     length)

    # Decode fields
    (event_type,
     par['ROSpecID'],
     par['PreemptingROSpecID']) = ubyte_uint_uint_unpack(body)

    if event_type == 0:
        par['EventType'] = 'Start_of_ROSpec'
    elif event_type == 1:
        par['EventType'] = 'End_of_ROSpec'
    else:
        par['EventType'] = 'Preemption_of_ROSpec'

    return par, data[length:]


Message_struct['ROSpecEvent'] = {
    'type': 249,
    'fields': [
        'Type',
        'EventType',
        'ROSpecID',
        'PreemptingROSpecID'
    ],
    'decode': decode_ROSpecEvent
}


def decode_ReportBufferLevelWarning(data):
    logger.debugfast('decode_ReportBufferLevelWarning')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ReportBufferLevelWarning']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_ReportBufferLevelWarning',
                 msgtype, length)

    par['ReportBufferPercentageFull'] = ubyte_unpack(body)[0]

    return par, data[length:]


Message_struct['ReportBufferLevelWarning'] = {
    'type': 250,
    'fields': [
        'Type',
        'ReportBufferPercentageFull'
    ],
    'decode': decode_ReportBufferLevelWarning
}


def decode_ReportBufferOverflowErrorEvent(data):
    logger.debugfast('decode_ReportBufferOverflowErrorEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ReportBufferOverflowErrorEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)',
                     'decode_ReportBufferOverflowErrorEvent', msgtype, length)

    return par, data[length:]


Message_struct['ReportBufferOverflowErrorEvent'] = {
    'type': 251,
    'fields': [
        'Type',
    ],
    'decode': decode_ReportBufferOverflowErrorEvent
}


def decode_ReaderExceptionEvent(data):
    logger.debugfast('decode_ReaderExceptionEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ReaderExceptionEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_ReaderExceptionEvent',
                     msgtype, length)

    offset = ushort_size
    msg_bytecount = ushort_unpack(body[:offset])[0]
    par['Message'] = body[offset:offset + msg_bytecount]
    body = body[offset + msg_bytecount:]

    # grab TV-encoded parameters
    while body:
        ret, nbytes = llrp_decoder.decode_tve_parameter(body)
        if ret:
            par.update(ret)
            body = body[nbytes:]
        else:
            break

    return par, data[length:]


Message_struct['ReaderExceptionEvent'] = {
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
    ],
    'decode': decode_ReaderExceptionEvent
}


def decode_RFSurveyEvent(data):
    logger.debugfast('decode_RFSurveyEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['RFSurveyEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_RFSurveyEvent', msgtype,
                     length)

    # Decode fields
    (event_type,
     par['ROSpecID'],
     par['SpecIndex']) = ubyte_uint_ushort_unpack(body)

    if event_type == 0:
        par['EventType'] = 'Start_of_RFSurvey'
    else:
        par['EventType'] = 'End_of_RFSurvey'


    return par, data[length:]

Message_struct['RFSurveyEvent'] = {
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

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['AISpecEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_AISpecEvent', msgtype, length)


    # Decode fields
    (_,
     par['ROSpecID'],
     par['SpecIndex']) = ubyte_uint_ushort_unpack(body)
    offset = ubyte_uint_ushort_size
    body = body[offset:]


    # first parameter (event_type) is ignored as just a single value is
    # possible.
    par['EventType'] = 'End_of_AISpec'


    # Optionnal AirProtocolSingulationDetailsParameter parameter:
    # C1G2SingulationDetails that is a tve
    if body:
        ret, nbytes = llrp_decoder.decode_tve_parameter(body)
        if ret:
            par.update(ret)
            body = body[nbytes:]

    return par, data[length:]


Message_struct['AISpecEvent'] = {
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

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['AntennaEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_AntennaEvent', msgtype,
                     length)

    # Decode fields
    event_type, antenna_id = ubyte_ushort_unpack(body)
    par['EventType'] = event_type and 'Connected' or 'Disconnected'
    par['AntennaID'] = antenna_id

    return par, data[length:]


Message_struct['AntennaEvent'] = {
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

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ConnectionAttemptEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_ConnectionAttemptEvent',
                     msgtype, length)

    # Decode fields
    status = ushort_unpack(body)[0]
    par['Status'] = ConnEvent_Type2Name[status]

    return par, data[length:]


Message_struct['ConnectionAttemptEvent'] = {
    'type': 256,
    'fields': [
        'Type',
        'Status'
    ],
    'decode': decode_ConnectionAttemptEvent
}


def decode_ConnectionCloseEvent(data):
    logger.debugfast('decode_ConnectionCloseEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ConnectionCloseEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_ConnectionCloseEvent',
                     msgtype, length)

    return par, data[length:]


Message_struct['ConnectionCloseEvent'] = {
    'type': 257,
    'fields': [
        'Type'
    ],
    'decode': decode_ConnectionCloseEvent
}


def decode_SpecLoopEvent(data):
    logger.debugfast('decode_SpecLoopEvent')
    par = {}

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['SpecLoopEvent']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_SpecLoopEvent', msgtype,
                     length)

    # Decode fields
    (par['ROSpecID'],
     par['LoopCount']) = uint_uint_unpack(body)

    return par, data[length:]


# Only available with protocol v2 (llrp 1_1)
Message_struct['SpecLoopEvent'] = {
    'type': 356,
    'fields': [
        'Type',
        'ROSpecID',
        'LoopCount'
    ],
    'decode': decode_SpecLoopEvent
}


# 16.2.7.6 ReaderEventNotificationData Parameter
def decode_ReaderEventNotificationData(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)',
                     'decode_ReaderEventNotificationData', msgtype, length)

    # Decode parameters
    ret, body = decode('UTCTimestamp')(body)
    if ret:
        par['UTCTimestamp'] = ret
    else:
        raise LLRPError('missing or invalid UTCTimestamp parameter')

    while len(body):
        evt_header = body[0:par_header_len]
        evt_msgtype, evt_length = par_header_unpack(evt_header)
        evt_msgtype = evt_msgtype & BITMASK(10)

        event_name = Event_Type2Name.get(evt_msgtype)
        if not event_name:
            logger.warning('skipping unsupported event (type: %d)',
                           evt_msgtype)
            logger.debugfast('Unprocessed bytes of unsupported reader EVENT: %s',
                             hexlify(body[:evt_length]))
            body = body[evt_length:]
            continue

        if event_name not in Message_struct:
            logger.warning('No decoder available for event: %s . Skipping...',
                           event_name)
            body = body[evt_length:]
            continue

        ret, body = decode(event_name)(body)
        if ret:
            par[event_name] = ret
        else:
            logger.warning('error decoding event %s', )
            body = body[evt_length:]
            continue

    return par, body


Message_struct['ReaderEventNotificationData'] = {
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
        'SpecLoopEvent'
    ],
    'decode': decode_ReaderEventNotificationData
}


# 13.2.6 ReaderEventNotificationData events list
Event_Type2Name = {}
for field_name in Message_struct['ReaderEventNotificationData']['fields']:
    if field_name in ['Type', 'UTCTimestamp']:
        continue
    event_type_id = Message_struct.get(field_name, {}).get('type')
    if event_type_id:
        Event_Type2Name[event_type_id] = field_name


# 16.2.8.1 LLRPStatus Parameter
def decode_LLRPStatus(data):
    logger.debugfast('decode_LLRPStatus: %s', hexlify(data))
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    ls = Message_struct['LLRPStatus']
    if msgtype != ls['type']:
        logger.debugfast('got msgtype=%s, expected %s', msgtype, ls['type'])
        logger.debugfast('note length=%d', length)
        return None, data
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d)', 'decode_LLRPStatus', msgtype, length)

    # Decode fields
    offset = ushort_ushort_size
    code, n = ushort_ushort_unpack(body[:offset])
    try:
        par['StatusCode'] = Error_Type2Name[code]
    except KeyError:
        logger.warning('Unknown field code %s', code)
    par['ErrorDescription'] = body[offset:offset + n]

    # Decode parameters
    ret, body = decode('FieldError')(body[offset + n:])
    if ret:
        par['FieldError'] = ret
    else:
        logger.debugfast('no FieldError')

    ret, body = decode('ParameterError')(body)
    if ret:
        par['ParameterError'] = ret
    else:
        logger.debugfast('no ParameterError')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return par, data[length:]


Message_struct['LLRPStatus'] = {
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
def decode_FieldError(data):
    logger.debugfast('decode_FieldError')
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['FieldError']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d data=%s)', 'decode_FieldError', msgtype,
                     length, repr(body))

    # Decode fields
    offset = ushort_size
    par['FieldNum'] = ushort_unpack(body[:offset])[0]

    return par, data[length:]


Message_struct['FieldError'] = {
    'type':   288,
    'fields': [
        'Type',
        'ErrorCode',
        'FieldNum',
    ],
    'decode': decode_FieldError
}


# 16.2.8.1.2 ParameterError Parameter
def decode_ParameterError(data):
    logger.debugfast('decode_ParameterError')
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0:par_header_len]
    msgtype, length = par_header_unpack(header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ParameterError']['type']:
        return (None, data)
    body = data[par_header_len:length]
    logger.debugfast('%s (type=%d len=%d data=%s)', 'decode_ParameterError',
                     msgtype, length, repr(body))

    # Decode fields
    offset = ushort_ushort_size
    (par['ParameterType'],
     par['ErrorCode']) = ushort_ushort_unpack(body[:offset])

    # Decode parameters
    ret, body = decode('FieldError')(body[offset:])
    if ret:
        par['FieldError'] = ret

    ret, body = decode('ParameterError')(body)
    if ret:
        par['ParameterError'] = ret

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('Junk at end of message ({} bytes)'.format(len(body)))

    return par, data[length:]


Message_struct['ParameterError'] = {
    'type':   289,
    'fields': [
        'Type',
        'ParameterType',
        'ErrorCode',
        'FieldError',
        'ParameterError'
    ],
    'decode': decode_ParameterError
}

def encode_CustomMessage(msg):
    vendor_id = msg['VendorID']
    subtype = msg['Subtype']
    payload = msg.get('Payload', struct.pack('!I', 0))
    data = struct.pack('!IB', vendor_id, subtype) + payload
    # logger.debug('data: %s', hexlify(data))
    return data


def decode_CustomMessageResponse(data):
    logger.debugfast('decode_CustomMessageResponse')
    msg = LLRPMessageDict()

    skip_len = struct.calcsize('!IB')  # skip vendor ID + subtype
    ret, body = decode('LLRPStatus')(data[skip_len:])
    msg['LLRPStatus'] = ret

    return msg


Message_struct['CUSTOM_MESSAGE'] = {
    'type': 1023,
    'fields': [
        'Ver', 'Type', 'ID',
        'VendorID',
        'Subtype',
        'Payload',
    ],
    'encode': encode_CustomMessage,
    'decode': decode_CustomMessageResponse
}


def encode_CustomParameter(par):
    msgtype = Message_struct['CustomParameter']['type']
    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)

    data = struct.pack('!I', par['VendorID'])
    data += struct.pack('!I', par['Subtype'])
    data += par['Payload']

    header = struct.pack(msg_header, msgtype, msg_header_len + len(data))
    return header + data


Message_struct['CustomParameter'] = {
    'type': 1023,
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


def encode_ImpinjCustomParameter(subtype, value):
    custom_par = {
        'VendorID': 25882,
        'Subtype': subtype,
        'Payload': struct.pack('!H', value)
    }
    return encode('CustomParameter')(custom_par)


def encode_ImpinjInventorySearchModeParameter(par):
    return encode_ImpinjCustomParameter(23, par)


Message_struct['ImpinjInventorySearchModeParameter'] = {
    'vendorid': 25882,
    'subtype': 23,
    'fields': [],
    'encode': encode_ImpinjInventorySearchModeParameter
}

def encode_ImpinjFixedFrequencyListParameter(par):
    msg_struct_param = Message_struct['ImpinjFixedFrequencyListParameter']
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

Message_struct['ImpinjFixedFrequencyListParameter'] = {
    'vendorid': 25882,
    'subtype': 26,
    'fields': [
        'FixedFrequencyMode',
        'Reserved',
        'ChannelListCount',
        'ChannelListIndex'
    ],
    'encode': encode_ImpinjFixedFrequencyListParameter
}

def encode_ImpinjTagReportContentSelectorParameter(par):
    msg_struct_param = Message_struct['ImpinjTagReportContentSelectorParameter']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
    }

    payload = encode('ImpinjEnableRFPhaseAngleParameter')(
        par.get('ImpinjEnableRFPhaseAngleParameter', False))
    payload += encode('ImpinjEnablePeakRSSIParameter')(
        par.get('ImpinjEnablePeakRSSIParameter', False))
    payload += encode('ImpinjEnableRFDopplerParameter')(
        par.get('ImpinjEnableRFDopplerParameter', False))
    custom_par['Payload'] = payload

    return encode('CustomParameter')(custom_par)

Message_struct['ImpinjTagReportContentSelectorParameter'] = {
    'vendorid': 25882,
    'subtype': 50,
    'fields': [
        'ImpinjEnableRFPhaseAngleParameter',
        'ImpinjEnablePeakRSSIParameter',
        'ImpinjEnableRFDopplerParameter'
    ],
    'encode': encode_ImpinjTagReportContentSelectorParameter
}

def encode_ImpinjEnableRFPhaseAngleParameter(par):
    msg_struct_param = Message_struct['ImpinjEnableRFPhaseAngleParameter']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)

Message_struct['ImpinjEnableRFPhaseAngleParameter'] = {
    'vendorid': 25882,
    'subtype': 52,
    'fields': [],
    'encode': encode_ImpinjEnableRFPhaseAngleParameter
}

def encode_ImpinjEnablePeakRSSIParameter(par):
    msg_struct_param = Message_struct['ImpinjEnablePeakRSSIParameter']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)

Message_struct['ImpinjEnablePeakRSSIParameter'] = {
    'vendorid': 25882,
    'subtype': 53,
    'fields': [],
    'encode': encode_ImpinjEnablePeakRSSIParameter
}

def encode_ImpinjEnableRFDopplerParameter(par):
    msg_struct_param = Message_struct['ImpinjEnableRFDopplerParameter']
    custom_par = {
        'VendorID': msg_struct_param['vendorid'],
        'Subtype': msg_struct_param['subtype'],
        'Payload': struct.pack('!H', par)
    }
    return encode('CustomParameter')(custom_par)

Message_struct['ImpinjEnableRFDopplerParameter'] = {
    'vendorid': 25882,
    'subtype': 67,
    'fields': [],
    'encode': encode_ImpinjEnableRFDopplerParameter
}


def llrp_data2xml(msg):
    def __llrp_data2xml(msg, name, level=0):
        tabs = '\t' * level

        xml_str = tabs + '<%s>\n' % name

        fields = Message_struct[name]['fields']
        for p in fields:
            try:
                sub = msg[p]
            except KeyError:
                continue

            if isinstance(sub, dict):
                xml_str += __llrp_data2xml(sub, p, level + 1)
            elif isinstance(sub, list) and sub and isinstance(sub[0], dict):
                for e in sub:
                    xml_str += __llrp_data2xml(e, p, level + 1)
            else:
                xml_str += tabs + '\t<%s>%r</%s>\n' % (p, sub, p)

        xml_str += tabs + '</%s>\n' % name

        return xml_str

    ans = ''
    for p in msg:
        ans += __llrp_data2xml(msg[p], p)
    return ans[:-1]


class LLRPROSpec(dict):
    def __init__(self, reader_mode, rospecid, priority=0, state='Disabled',
                 antennas=(1,), tx_power=0, duration_sec=None,
                 report_every_n_tags=None, report_timeout_ms=0,
                 tag_content_selector=None, tari=None,
                 session=2, tag_population=4,
                 impinj_search_mode=None, impinj_tag_content_selector=None):
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
                ['ImpinjTagReportContentSelectorParameter'] = {
                    'ImpinjEnableRFPhaseAngleParameter':
                        impinj_tag_content_selector['EnableRFPhaseAngle'],
                    'ImpinjEnablePeakRSSIParameter':
                        impinj_tag_content_selector['EnablePeakRSSI'],
                    'ImpinjEnableRFDopplerParameter':
                        impinj_tag_content_selector['EnableRFDopplerFrequency']
                }

        ips = self['ROSpec']['AISpec']['InventoryParameterSpec']

        # patch up per-antenna config
        for antid in antennas:
            transmit_power = tx_power[antid]
            antconf = {
                'AntennaID': antid,
                'RFTransmitter': {
                    'HopTableId': 1,
                    'ChannelIndex': 1,
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
                    ['ImpinjInventorySearchModeParameter'] = int(impinj_search_mode)

            if impinj_fixed_frequency_param is not None:
                antconf['C1G2InventoryCommand']\
                    ['ImpinjFixedFrequencyListParameter'] = {
                        'FixedFrequencyMode': 
                            impinj_fixed_frequency_param['FixedFrequencyMode'],
                        'ChannelListIndex': 
                            impinj_fixed_frequency_param['ChannelListIndex']
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
for msgname, msgstruct in iteritems(Message_struct):
    # HACK: skip parameters
    if 'PARAM' in msgname.upper():
        continue

    try:
        ty = msgstruct['type']
    except KeyError:
        logging.debug('Pseudo-warning: Message_struct type %s lacks "type" '
                      'field', msgname)
        continue

    try:
        if msgstruct['tv_encoded']:
            continue
    except KeyError:
        pass

    Message_Type2Name[ty] = msgname
