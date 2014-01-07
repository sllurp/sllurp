#!/usr/bin/env python

# llrp_proto.py - LLRP protocol client support
#
# Copyright (C) 2009 Rodolfo Giometti <giometti@linux.it>
# Copyright (C) 2009 CAEN RFID <support.rfid@caen.it>
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

import logging, struct, exceptions
import traceback
from threading import *
from types import *
from socket import *
import time
from util import *
import llrp_decoder
from llrp_errors import *

#
# Define exported symbols
#

__all__ = [
    # Class
    "LLRPdConnection",
    "LLRPdCapabilities",
    "LLRPROSpec",

    # Commands
    "llrp_set_logging",

    # Misc
    "func",
]

#
# Setup logging
#

logger = logging.getLogger('sllurp')

#
# Local functions
#

def decode(data):
    return Message_struct[data]['decode']

def encode(data):
    return Message_struct[data]['encode']

def bin2dump(data, label=''):
    def isprint(c):
        return ord(c) >= 32 and ord(c) <= 126

    def conv(c):
        if isprint(c):
            return c
        return '.'

    l = len(data)
    if len(label) > 0:
        str = label + '\n'
    else:
        str = ''

    p = 0
    line = ' ' * 80
    i = 0
    while i < l:
        num = '%02x' % struct.unpack('B', data[i])
        line = line[ : p * 3] + num + line[p * 3 + 2 : ]
        line = line[ : 50 + p] + conv(data[i])

        p += 1
        if p == 16:
            str += line + '\n'
            p = 0
            line = ' ' * 80
        i += 1
    if p != 0:
        str += line + '\n'
    return str[ : -1]

def dump(data, label):
    logger.debug(bin2dump(data, label))

def recv_message(connection):
    msg = LLRPMessageDict()
    logger.debug('recv_message()')

    # Try to read the message's header first.
    data = connection.stream.recv(gen_header_len)
    msgtype, length = struct.unpack(gen_header, data)

    # Little sanity checks
    ver = (msgtype >> 10) & BITMASK(3)
    if (ver != VER_PROTO_V1) :
        raise LLRPError('messages version %d are not supported' % ver)

    # Then try to read the message's body.
    length -= gen_header_len
    data += connection.stream.recv(length)
    dump(data, 'recv')

    header = data[0 : msg_header_len]
    msgtype, length, msgid = struct.unpack(msg_header, header)
    msgtype = msgtype & BITMASK(10)
    body = data[msg_header_len : length]
    logger.debug('%s (msgtype=%d len=%d msgid=%d)' % (func(), msgtype, length, msgid))

    # Decode message
    try:
       name = Message_Type2Name[msgtype]
    except KeyError:
       raise LLRPError('message msgtype %d is not supported' % msgtype)
    data = decode(name)(body)

    msg[name] = data
    msg[name]['Ver'] = ver
    msg[name]['Type'] = msgtype
    msg[name]['ID'] = msgid
    logger.debug(msg)

    return msg

def send_message(connection, msg):
    logger.debug('%s' % func())
    logger.debug(msg)

    # Sanity checks
    key = msg.keys()
    if (len(key) != 1):
        raise LLRPError('invalid message format')
    name = key[0]

    if name not in Message_struct:
        raise LLRPError('invalid message %s' % name)
    ver = msg[name]['Ver'] & BITMASK(3)
    msgtype = msg[name]['Type'] & BITMASK(10)
    msgid = msg[name]['ID']

    data = encode(name)(msg[name])

    data = struct.pack(msg_header, (ver << 10) | msgtype,
                len(data) + msg_header_len, msgid) + data
    dump(data, 'send')

    connection.stream.send(data)

#
# LLRP defines & structs
#

LLRP_PORT               = 5084

VER_PROTO_V1                = 1

gen_header = '!HI'
gen_header_len = struct.calcsize(gen_header)
msg_header = '!HII'
msg_header_len = struct.calcsize(msg_header)
par_header = '!HH'
par_header_len = struct.calcsize(par_header)
tve_header = '!B'
tve_header_len = struct.calcsize(tve_header)

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

# 13.2.6.11 Connection attemp events
ConnEvent_Name2Type = {
    'Success':                          0,
    'Failed (a Reader initiated connection already exists)':    1,
    'Failed (a Client initiated connection already exists)':    2,
    'Failed (any reason other than a connection already exists)':   3,
    'Another connection attempted':                 4,
}

ConnEvent_Type2Name = reverse_dict(ConnEvent_Name2Type)
for m in ConnEvent_Name2Type:
    i = ConnEvent_Name2Type[m]
    ConnEvent_Type2Name[i] = m

# 14.1.1 Error messages
Error_Name2Type = {
    'Success':              0,
    'ParameterError':           100,
    'FieldError':               101,
    'DeviceError':              401,
}

Error_Type2Name = reverse_dict(Error_Name2Type)
for m in Error_Name2Type:
    i = Error_Name2Type[m]
    Error_Type2Name[i] = m

# 13.2.1 ROReportTrigger
ROReportTrigger_Name2Type = {
    'None': 0,
    'Upon_N_Tags_Or_End_Of_AISpec': 1,
    'Upon_N_Tags_Or_End_Of_ROSpec': 2,
}

# 15.2.1.1.2.1 UHFC1G2RFModeTableEntry
ModeIndex_Name2Type = {
    ## TODO flesh out this table by looking at capabilities from different
    ## readers
    'M4': 2,
    'M8': 3,
    'FM0': 1000,
    #'AutosetSingle': 1001
}

ModeIndex_Type2Name = reverse_dict(ModeIndex_Name2Type)
for m in ModeIndex_Name2Type:
    i = ModeIndex_Name2Type[m]
    ModeIndex_Type2Name[i] = m

#
# LLRP Messages
#

Message_struct = { }

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    ret, body = decode('LLRPCapabilities')(body)
    if ret:
        msg['LLRPCapabilities'] = ret

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

    return msg

Message_struct['GET_READER_CAPABILITIES_RESPONSE'] = {
    'type': 11,
    'fields': [
        'Ver', 'Type', 'ID',
        'LLRPStatus',
        'GeneralDeviceCapabilities',
        'LLRPCapabilities',
        'AirProtocolLLRPCapabilities'
    ],
    'decode': decode_GetReaderCapabilitiesResponse
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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    logger.debug('%s' % func())

    logger.debug('RO_ACCESS_REPORT bytes: {}'.format(data.encode('hex')))

    # Decode parameters
    msg['TagReportData'] = [ ]
    while True:
        ret, data = decode('TagReportData')(data)
        #print('len(ret) = {}'.format(len(ret)))
        #print('len(data) = {}'.format(len(data)))
        if ret:
            msg['TagReportData'].append(ret)
        else:
            break

    ## Check the end of the message
    #if len(data) > 0:
    #    raise LLRPError('junk at end of message: ' + bin2dump(data))

    return msg

Message_struct['RO_ACCESS_REPORT'] = {
    'type': 61,
    'fields': [
        'Ver', 'Type', 'ID',
        'TagReportData',
    ],
    'decode': decode_ROAccessReport
}

# 16.1.33 READER_EVENT_NOTIFICATION
def decode_ReaderEventNotification(data):
    msg = LLRPMessageDict()
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('ReaderEventNotificationData')(data)
    if ret:
        msg['ReaderEventNotificationData'] = ret

    # Check the end of the message
        if len(body) > 0:
                raise LLRPError('junk at end of message: ' + bin2dump(body))

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
    return ''

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
    logger.debug('%s' % func())

    # Decode parameters
    ret, body = decode('LLRPStatus')(data)
    if ret:
        msg['LLRPStatus'] = ret
    else:
        raise LLRPError('missing or invalid LLRPStatus parameter')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

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

#
# LLRP Parameters
#

# 16.2.2.1 UTCTimestamp Parameter
def decode_UTCTimestamp(data):
    logger.debug(func())
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['UTCTimestamp']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    (par['Microseconds'], ) = struct.unpack('!Q', body)

    return par, data[length : ]

Message_struct['UTCTimestamp'] = {
    'type':   128,
    'fields': [
        'Type',
        'Microseconds'
    ],
    'decode' : decode_UTCTimestamp
}

Message_struct['LLRPdCapabilities'] = {
    # no 'type': dummy message struct!
    'type': -1,
    'fields': [
        'GeneralDeviceCapabilities',
        'LLRPCapabilities',
        'AirProtocolLLRPCapabilities'
    ]
}

# 16.2.3.2 LLRPCapabilities Parameter
def decode_LLRPCapabilities(data):
    logger.debug(func())
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['LLRPCapabilities']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    (flags,
     par['MaxPriorityLevelSupported'],
     par['ClientRequestOpSpecTimeout'],
     par['MaxNumROSpec'],
     par['MaxNumSpecsPerROSpec'],
     par['MaxNumInventoryParametersSpecsPerAISpec'],
     par['MaxNumAccessSpec'],
     par['MaxNumOpSpecsPerAccessSpec']) = struct.unpack('!BBHIIIII', body)

    par['CanDoRFSurvey'] = (flags & BIT(7) == BIT(7))
    par['CanReportBufferFillWarning'] = (flags & BIT(6) == BIT(6))
    par['SupportsClientRequestOpSpec'] = (flags & BIT(5) == BIT(5))
    par['CanDoTagInventoryStateAwareSingulation'] = \
                    (flags & BIT(4) == BIT(4))
    par['SupportsEventAndReportHolding'] = (flags & BIT(3) == BIT(3))

    return par, data[length : ]

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

def decode_ErrorMessage(data):
    msg = LLRPMessageDict()
    logger.debug('%s' % func())
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

    data = ''

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

# 16.2.4.1.1.2 ROSpecStopTrigger Parameter
def encode_ROSpecStopTrigger(par):
    msgtype = Message_struct['ROSpecStopTrigger']['type']
    t_type = StopTrigger_Name2Type[par['ROSpecStopTriggerType']]
    duration = par['DurationTriggerValue']

    msg_header = '!HHBI'
    msg_header_len = struct.calcsize(msg_header)

    data = ''

    data = struct.pack(msg_header, msgtype,
            len(data) + msg_header_len,
            t_type, duration) + data

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
    data = ''

    antid = par['AntennaIDs']
    antennas = []
    if type(antid) is str:
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

# 16.2.4.2.2 InventoryParameterSpec Parameter
def encode_InventoryParameterSpec(par):
    msgtype = Message_struct['InventoryParameterSpec']['type']

    msg_header = '!HH'
    msg_header_len = struct.calcsize(msg_header)
    data = struct.pack('!H', par['InventoryParameterSpecID'])
    data += struct.pack('!B', par['ProtocolID'])

    for antconf in par['AntennaConfiguration']:
        logger.debug('encoding AntennaConfiguration: {}'.format(antconf))
        data += encode('AntennaConfiguration')(antconf)

    data = struct.pack(msg_header, msgtype,
            struct.calcsize(msg_header) + len(data)) + data

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
def encode_RFReceiver (par):
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
def encode_RFTransmitter (par):
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
def encode_C1G2InventoryCommand (par):
    msgtype = Message_struct['C1G2InventoryCommand']['type']
    msg_header = '!HH'
    data = struct.pack('!B', (par['TagInventoryStateAware'] and 1 or 0) << 7)
    if 'C1G2Filter' in par:
        data += encode('C1G2Filter')(par['C1G2Filter'])
    if 'C1G2RFControl' in par:
        data += encode('C1G2RFControl')(par['C1G2RFControl'])
    if 'C1G2SingulationControl' in par:
        data += encode('C1G2SingulationControl')(par['C1G2SingulationControl'])
    # XXX custom parameters

    data = struct.pack(msg_header, msgtype,
            len(data) + struct.calcsize(msg_header)) + data
    return data

Message_struct['C1G2InventoryCommand'] = {
    'type': 330,
    'fields': [
        'TagInventoryStateAware',
        'C1G2Filter',
        'C1G2RFControl',
        'C1G2SingulationControl'
        # XXX custom parameters
    ],
    'encode': encode_C1G2InventoryCommand
}

# 16.3.1.2.1.1 C1G2Filter Parameter
def encode_C1G2Filter (par):
    raise NotImplementedError

Message_struct['C1G2Filter'] = {
    'type': 331,
}

# 16.3.1.2.1.2 C1G2RFControl Parameter
def encode_C1G2RFControl (par):
# 'C1G2RFControl': {
#     'ModeIndex': 1,
#     'Tari': 0,
# },
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
def encode_C1G2SingulationControl (par):
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
def encode_ROReportSpec (par):
    msgtype = Message_struct['ROReportSpec']['type']
    n = int(par['N'])
    roReportTrigger = ROReportTrigger_Name2Type[par['ROReportTrigger']]

    msg_header = '!HHBH'
    msg_header_len = struct.calcsize(msg_header)

    data = encode('TagReportContentSelector')(par['TagReportContentSelector'])

    data = struct.pack(msg_header, msgtype,
            len(data) + msg_header_len,
            roReportTrigger, n) + data

    return data

Message_struct['ROReportSpec'] = {
    'type': 237,
    'fields': [
        'N',
        'ROReportTrigger',
        'TagReportContentSelector'
    ],
    'encode': encode_ROReportSpec
}

# 16.2.7.1 TagReportContentSelector Parameter
def encode_TagReportContentSelector (par):
    msgtype = Message_struct['TagReportContentSelector']['type']

    msg_header = '!HH'

    flags = 0
    i = 15
    for field in Message_struct['TagReportContentSelector']['fields']:
        if field in par and par[field]:
            flags = flags | (1 << i)
        i = i - 1

    data = struct.pack('!H', flags)
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
        'EnablePeakRRSI',
        'EnableFirstSeenTimestamp',
        'EnableLastSeenTimestamp',
        'EnableTagSeenCount',
        'EnableAccessSpecID'
    ],
    'encode': encode_TagReportContentSelector
}

# 16.2.7.3 TagReportData Parameter
def decode_TagReportData(data):
    par = {}
    logger.debug('%s' % func())
    logger.debug('TagReportData bytes: {}'.format(data.encode('hex')))

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['TagReportData']['type']:
        return (None, data)
    body = data[par_header_len : length]

    # Decode parameters
    ret, body = decode('EPCData')(body)
    if ret:
        logger.debug("got EPCData; won't try EPC-96")
        par['EPCData'] = ret
    else:
        logger.debug('failed to decode EPCData; trying EPC-96')
        ret, body = decode('EPC-96')(body)
        if ret:
            par['EPC-96'] = ret['EPC']
        else:
            raise LLRPError('missing or invalid EPCData parameter')

    par.update(llrp_decoder.decode_tve_parameters(body))

    return par, data[length : ]

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
        'AirProtocolTagData',
        'AccessSpecID',
        'OpSpecResultParameter',
    ],
    'decode': decode_TagReportData
}

# 16.2.7.3.1 EPCData Parameter
def decode_EPCData(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['EPCData']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    (par['EPCLengthBits'], ) = struct.unpack('!H',
                    body[0 : struct.calcsize('!H')])
    par['EPC'] = body[struct.calcsize('!H') : ].encode('hex')

    return par, data[length : ]

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

    header = data[0 : tve_header_len]
    (msgtype, ), length = struct.unpack(tve_header, header), 1 + (96 / 8)
    msgtype = msgtype & BITMASK(7)
    if msgtype != Message_struct['EPC-96']['type']:
        return (None, data)
    body = data[tve_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    par['EPC'] = body.encode('hex')

    return par, data[length : ]

Message_struct['EPC-96'] = {
    'type': 13,
    'fields': [
        'Type',
        'EPC'
    ],
    'decode': decode_EPC96
}

# 16.2.7.3.3 ROSpecID Parameter
def decode_ROSpecID(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : tve_header_len]
    (msgtype, ), length = struct.unpack(tve_header, header), 1 + 4
    msgtype = msgtype & BITMASK(7)
    if msgtype != Message_struct['ROSpecID']['type']:
        return (None, data)
    body = data[tve_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    (par['ROSpecID'], ) = struct.unpack('!I', body)

    return par, data[length : ]

Message_struct['ROSpecID'] = {
    'type': 9,
    'fields': [
        'Type',
        'ROSpecID'
    ],
    'decode': decode_ROSpecID
}

# 16.2.7.6 ReaderEventNotificationData Parameter
def decode_ReaderEventNotificationData(data):
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode parameters
    ret, body = decode('UTCTimestamp')(body)
    if ret:
        par['UTCTimestamp'] = ret
    else:
        raise LLRPError('missing or invalid UTCTimestamp parameter')

    ret, body = decode('ConnectionAttemptEvent')(body)
    if ret:
        par['ConnectionAttemptEvent'] = ret

    ret, body = decode('AntennaEvent')(body)
    if ret:
        par['AntennaEvent'] = ret

    return par, body

Message_struct['ReaderEventNotificationData'] = {
    'type': 246,
    'fields': [
        'Type',
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
        'ConnectionCloseEvent'
    ],
    'decode': decode_ReaderEventNotificationData
}

# 16.2.7.6.9 AntennaEvent Parameter
def decode_AntennaEvent(data):
    logger.debug(func())
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['AntennaEvent']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    (event_type, antenna_id) = struct.unpack('!BH', body)
    par['EventType'] = event_type and 'Connected' or 'Disconnected'
    par['AntennaID'] = antenna_id

    return par, data[length : ]

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
    logger.debug(func())
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ConnectionAttemptEvent']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    (status, ) = struct.unpack('!H', body)
    par['Status'] = ConnEvent_Type2Name[status]

    return par, data[length : ]

Message_struct['ConnectionAttemptEvent'] = {
    'type': 256,
    'fields': [
        'Type',
        'Status'
    ],
    'decode': decode_ConnectionAttemptEvent
}

# 16.2.8.1 LLRPStatus Parameter
def decode_LLRPStatus(data):
    logger.debug(func())
    par = {}
    logger.debug('decode_LLRPStatus: {}'.format(hexlify(data)))

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['LLRPStatus']['type']:
        logger.debug('got msgtype={0}, expected {1}'.format(msgtype,
                    Message_struct['LLRPStatus']['type']))
        logger.debug('note length={}'.format(length))
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d)' % (func(), msgtype, length))

    # Decode fields
    offset = struct.calcsize('!HH')
    (code, n) = struct.unpack('!HH', body[ : offset])
    try:
        par['StatusCode'] = Error_Type2Name[code]
    except KeyError:
        logger.warning('Unknown field code {}'.format(hex(code)))
    par['ErrorDescription'] = body[offset : offset + n]

    # Decode parameters
    ret, body = decode('FieldError')(body[offset + n : ])
    if ret:
        par['FieldError'] = ret
    else:
        logging.debug('no FieldError')

    ret, body = decode('ParameterError')(body)
    if ret:
        par['ParameterError'] = ret
    else:
        logging.debug('no ParameterError')

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

    return par, data[length : ]

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
    logger.debug(func())
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['FieldError']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d data=%s)' % \
            (func(), msgtype, length, repr(body)))

    # Decode fields
    offset = struct.calcsize('!H')
    (par['FieldNum'], ) = struct.unpack('!H', body[ : offset])

    return par, data[length : ]

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
    logger.debug(func())
    par = {}

    if len(data) == 0:
        return None, data

    header = data[0 : par_header_len]
    msgtype, length = struct.unpack(par_header, header)
    msgtype = msgtype & BITMASK(10)
    if msgtype != Message_struct['ParameterError']['type']:
        return (None, data)
    body = data[par_header_len : length]
    logger.debug('%s (type=%d len=%d data=%s)' % \
            (func(), msgtype, length, repr(body)))

    # Decode fields
    offset = struct.calcsize('!HH')
    (par['ParameterType'], par['ErrorCode']) = \
            struct.unpack('!HH', body[ : offset])

    # Decode parameters
    ret, body = decode('FieldError')(body[offset : ])
    if ret:
        par['FieldError'] = ret

    ret, body = decode('ParameterError')(body)
    if ret:
        par['ParameterError'] = ret

    # Check the end of the message
    if len(body) > 0:
        raise LLRPError('junk at end of message: ' + bin2dump(body))

    return par, data[length : ]

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

#
# LLRP Commands
#

def llrp_add_rospec(connection, rospec):
    msgid = rospec['ROSpec']['ROSpecID']

    msg = LLRPMessageDict()
    msg['ADD_ROSPEC'] = {
        'Ver':  1,
                'Type': Message_struct['ADD_ROSPEC']['type'],
                'ID':   0,
        'ROSpecID' : msgid
    }
    msg['ADD_ROSPEC']['ROSpec'] = rospec['ROSpec']

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        (code, descr) = (ans['ADD_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['ADD_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

def llrp_close(connection):
    # Send the message to gently close the connection
    msg = LLRPMessageDict()
    msg['CLOSE_CONNECTION'] = {
        'Ver':  1,
                'Type': Message_struct['CLOSE_CONNECTION']['type'],
                'ID':   0
    }

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Close the communication socket
    connection.stream.close()

    # Check the server response
    try:
        (code, descr) = (ans['CLOSE_CONNECTION_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['CLOSE_CONNECTION_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

def llrp_connect(connection, host, port = LLRP_PORT):
    connection.stream.connect((host, port))

    # Wait for the answer
    ans = recv_message(connection)

    # Check connection status
    try:
        status = ans['READER_EVENT_NOTIFICATION']\
                ['ReaderEventNotificationData']\
                ['ConnectionAttemptEvent']\
                ['Status']
    except:
        raise LLRPError('invalid connection answer!')

    if status != 'Success':
        raise LLRPResponseError(status)

def llrp_delete_rospec(connection, rospec):
    msgid = rospec['ROSpec']['ROSpecID']

    msg = LLRPMessageDict()
    msg['DELETE_ROSPEC'] = {
        'Ver':  1,
                'Type': Message_struct['DELETE_ROSPEC']['type'],
                'ID':   0,
        'ROSpecID' : msgid
    }

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        (code, descr) = (ans['DELETE_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['DELETE_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

def llrp_disable_rospec(connection, rospec):
    msgid = rospec['ROSpec']['ROSpecID']

    msg = LLRPMessageDict()
    msg['DISABLE_ROSPEC'] = {
        'Ver':  1,
                'Type': Message_struct['DISABLE_ROSPEC']['type'],
                'ID':   0,
        'ROSpecID' : msgid
    }

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        (code, descr) = (ans['DISABLE_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['DISABLE_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

def llrp_enable_rospec(connection, rospec):
    msgid = rospec['ROSpec']['ROSpecID']

    msg = LLRPMessageDict()
    msg['ENABLE_ROSPEC'] = {
        'Ver':  1,
        'Type': Message_struct['ENABLE_ROSPEC']['type'],
        'ID':   0,
        'ROSpecID' : msgid
    }

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        (code, descr) = (ans['ENABLE_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['ENABLE_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

def llrp_get_capabilities(connection, req):
    # Sanity checks
    if req not in Capability_Name2Type:
        raise LLRPError('invalid request (req=%s)' % req)

    msg = LLRPMessageDict()
    msg['GET_READER_CAPABILITIES'] = {
        'Ver':  1,
        'Type': Message_struct['GET_READER_CAPABILITIES']['type'],
        'ID':   0,
        'RequestedData' : Capability_Name2Type[req]
    }

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        (code, descr) = (ans['GET_READER_CAPABILITIES_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['GET_READER_CAPABILITIES_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

    # Create an LLRPdCapabilities instance
    cap = LLRPdCapabilities()

    # Add LLRPCapabilities?
    if 'LLRPCapabilities' in ans['GET_READER_CAPABILITIES_RESPONSE']:
        c = ans['GET_READER_CAPABILITIES_RESPONSE']['LLRPCapabilities']

        cap.LLRPCapabilities( c['CanDoRFSurvey'],
            c['CanReportBufferFillWarning'],
            c['SupportsClientRequestOpSpec'],
            c['CanDoTagInventoryStateAwareSingulation'],
            c['SupportsEventAndReportHolding'],
            c['MaxPriorityLevelSupported'],
            c['ClientRequestOpSpecTimeout'],
            c['MaxNumROSpec'],
            c['MaxNumSpecsPerROSpec'],
            c['MaxNumInventoryParametersSpecsPerAISpec'],
            c['MaxNumAccessSpec'],
            c['MaxNumOpSpecsPerAccessSpec'])

    return cap

def llrp_data2xml(msg):
    def __llrp_data2xml(msg, name, level = 0):
        tabs = '\t' * level

        str = tabs + '<%s>\n' % name

        fields =  Message_struct[name]['fields']
        for p in fields:
            try:
                sub = msg[p]
            except KeyError:
                continue

            if type(sub) == DictionaryType:
                str += __llrp_data2xml(sub, p, level + 1)
            elif type(sub) == ListType and sub and \
                    type(sub[0]) == DictionaryType:
                for e in sub:
                    str += __llrp_data2xml(e, p, level + 1)
            else:
                str += tabs + '\t<%s>%s</%s>\n' % (p, sub, p)

        str += tabs + '</%s>\n' % name

        return str

    ans = ''
    for p in msg:
        ans += __llrp_data2xml(msg[p], p)
    return ans[ : -1]

def llrp_set_logging(level):
    log.setLevel(level)

def llrp_start_rospec(connection, rospec):
    msgid = rospec['ROSpec']['ROSpecID']

    msg = LLRPMessageDict()
    msg['START_ROSPEC'] = {
        'Ver':  1,
        'Type': Message_struct['START_ROSPEC']['type'],
        'ID':   0,
        'ROSpecID' : msgid
    }

    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        (code, descr) = (ans['START_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['START_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

def llrp_stop_rospec(connection, rospec):
    msgid = rospec['ROSpec']['ROSpecID']

    msg = LLRPMessageDict()
    msg['STOP_ROSPEC'] = {
        'Ver':  1,
                'Type': Message_struct['STOP_ROSPEC']['type'],
                'ID':   0,
        'ROSpecID' : msgid
    }

    logger.debug(msg)
    send_message(connection, msg)

    # Wait for the answer
    ans = wait_for_message(connection)

    # Check the server response
    try:
        print ans
        (code, descr) = (ans['STOP_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['StatusCode'],
                 ans['STOP_ROSPEC_RESPONSE']\
                    ['LLRPStatus']['ErrorDescription'])
    except:
        raise LLRPError('invalid response')

    if code != 'Success':
        raise LLRPResponseError('%s: %s' % (code, descr))

#
# LLRP classes
#

def do_nothing(connection, msg):
    pass

def wait_for_message(connection):
    logger.debug('wait_for_message: acquiring lock')
    connection.msg_cond.acquire()
    logger.debug('wait_for_message: got lock')

    logger.debug('wait_for_message: waiting for #messages != 0')
    while len(connection.messages) == 0:
        connection.msg_cond.wait()
    logger.debug('wait_for_message: #messages != 0')

    msg = connection.messages.pop(0)

    logger.debug('wait_for_message: releasing lock')
    connection.msg_cond.release()

    return msg

class ReaderThread(Thread):
    keep_running = False

    def __init__(self, connection):
        Thread.__init__(self)
        self.connection = connection
        self.keep_running = True

    def run(self):
        connection = self.connection
        events = [
            'RO_ACCESS_REPORT',
            'READER_EVENT_NOTIFICATION',
            'ADD_ROSPEC_RESPONSE',
            'START_ROSPEC_RESPONSE',
            'ENABLE_ROSPEC_RESPONSE',
            'DELETE_ROSPEC_RESPONSE',
            'STOP_ROSPEC_RESPONSE',
            'GET_READER_CAPABILITIES_RESPONSE',
            'CLOSE_CONNECTION_RESPONSE',
        ]

        while self.keep_running:
            # Wait for a server message
            while True:
                try:
                    msg = recv_message(connection)
                    #logger.debug('got message via recv_message')
                except:
                    return

                # Before returning data to the caller we should check
                # for remote server's events
                if msg.keys()[0] in events:
                    connection.event_cb(connection, msg)
                else:
                    print 'unrecognized msg: %s' % msg

                break

            connection.msg_cond.acquire()

            connection.messages.append(msg)

            connection.msg_cond.notifyAll()
            connection.msg_cond.release()

    def stop(self):
        self.keep_running = False

class LLRPdCapabilities(dict):
    def __init__(self):
        self['LLRPdCapabilities'] = { }

    def __repr__(self):
        return llrp_data2xml(self)

    def LLRPCapabilities(self, can_do_rfsurvey, can_report_buf_fill,
            supports_client_reqs, can_do_tag_inv,
            supports_ev_rep_holding,
            max_prio, timeout,
            max_rospec, max_spec_x_rospec,
            max_inv_x_aispec,
            max_accesspec, max_opspec_x_accesspec):
        # Sanity checks
        if type(can_do_rfsurvey) != BooleanType:
            raise LLRPError('invalid argument 1 (not bool)')
        if type(can_report_buf_fill) != BooleanType:
            raise LLRPError('invalid argument 2 (not bool)')
        if type(supports_client_reqs) != BooleanType:
            raise LLRPError('invalid argument 3 (not bool)')
        if type(can_do_tag_inv) != BooleanType:
            raise LLRPError('invalid argument 4 (not bool)')
        if type(supports_ev_rep_holding) != BooleanType:
            raise LLRPError('invalid argument 5 (not bool)')
        if (max_prio < 0 or max_prio > 7):
            raise LLRPError('invalid argument 6 (not in [0-7])')
        if (timeout < 0):
            raise LLRPError('invalid argument 7 (not positive)')
        if (max_rospec < 0):
            raise LLRPError('invalid argument 8 (not positive)')
        if (max_spec_x_rospec < 0):
            raise LLRPError('invalid argument 9 (not positive)')
        if (max_inv_x_aispec < 0):
            raise LLRPError('invalid argument 10 (not positive)')
        if (max_accesspec < 0):
            raise LLRPError('invalid argument 11 (not positive)')
        if (max_opspec_x_accesspec < 0):
            raise LLRPError('invalid argument 12 (not positive)')

        self['LLRPdCapabilities']['LLRPCapabilities'] = { }

        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['CanDoRFSurvey'] = can_do_rfsurvey
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['CanReportBufferFillWarning'] = can_report_buf_fill
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['SupportsClientRequestOpSpec'] = supports_client_reqs
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['CanDoTagInventoryStateAwareSingulation'] = can_do_tag_inv
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['SupportsEventAndReportHolding'] = supports_ev_rep_holding
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['MaxPriorityLevelSupported'] = max_prio
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['ClientRequestOpSpecTimeout'] = timeout
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['MaxNumROSpec'] = max_rospec
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['MaxNumSpecsPerROSpec'] = max_spec_x_rospec
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['MaxNumInventoryParametersSpecsPerAISpec'] = max_inv_x_aispec
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['MaxNumAccessSpec'] = max_accesspec
        self['LLRPdCapabilities']['LLRPCapabilities']\
            ['MaxNumOpSpecsPerAccessSpec'] = max_opspec_x_accesspec

class LLRPROSpec(dict):
    def __init__(self, msgid, priority=0, state = 'Disabled', antennas=(1,),
            tx_power=91, modulation='M4', tari=0,
            duration_sec=None, report_every_n_tags=None):
        # Sanity checks
        if msgid <= 0:
            raise LLRPError('invalid argument 1 (not positive)')
        if priority < 0 or priority > 7:
            raise LLRPError('invalid argument 2 (not in [0-7])')
        if not state in ROSpecState_Name2Type:
            raise LLRPError('invalid argument 3 (not [%s])' %
                    ROSpecState_Name2Type.keys())

        self['ROSpec'] = {
            'ROSpecID': msgid,
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
                'AntennaIDs': ' '.join(map(str, antennas)),
                'AISpecStopTrigger': {
                    'AISpecStopTriggerType': 'Duration',
                    'DurationTriggerValue': 500,
                },
                'InventoryParameterSpec': {
                    'InventoryParameterSpecID': 1,
                    'ProtocolID': AirProtocol['EPCGlobalClass1Gen2'],
                    'AntennaConfiguration': [],
                },
            },
            'ROReportSpec': {
                'ROReportTrigger': 'Upon_N_Tags_Or_End_Of_AISpec',
                'N': 1,
                'TagReportContentSelector': {
                    'EnableROSpecID': False,
                    'EnableSpecIndex': False,
                    'EnableInventoryParameterSpecID': False,
                    'EnableAntennaID': True,
                    'EnableChannelIndex': False,
                    'EnablePeakRRSI': True,
                    'EnableFirstSeenTimestamp': False,
                    'EnableLastSeenTimestamp': False,
                    'EnableTagSeenCount': True,
                    'EnableAccessSpecID': False,
                },
            },
        }

        # patch up per-antenna config
        for antid in antennas:
            self['ROSpec']['AISpec']['InventoryParameterSpec']\
                ['AntennaConfiguration'].append({
                    'AntennaID': antid,
                    'RFTransmitter': {
                        'HopTableId': 1,
                        'ChannelIndex': 0,
                        'TransmitPower': tx_power,
                    },
                    'C1G2InventoryCommand': {
                        'TagInventoryStateAware': False,
                        'C1G2RFControl': {
                            'ModeIndex': ModeIndex_Name2Type[modulation],
                            'Tari': tari,
                        },
                        'C1G2SingulationControl': {
                            'Session': 0,
                            'TagPopulation': 4,
                            'TagTransitTime': 0
                        }
                    }
                })

        if duration_sec is not None:
            self['ROSpec']['ROBoundarySpec']['ROSpecStopTrigger'] = {
                'ROSpecStopTriggerType': 'Duration',
                'DurationTriggerValue': duration_sec * 1000,
            }

        if report_every_n_tags is not None:
            logger.debug('will report every ~N={}' \
                    ' tags'.format(report_every_n_tags))
            self['ROSpec']['ROReportSpec']['N'] = report_every_n_tags

    def __repr__(self):
        return llrp_data2xml(self)

    def add(self, connection):
        llrp_add_rospec(connection, self)

    def delete(self, connection):
        llrp_delete_rospec(connection, self)

    def disable(self, connection):
        llrp_disable_rospec(connection, self)

    def enable(self, connection):
        llrp_enable_rospec(connection, self)

    def start(self, connection):
        llrp_start_rospec(connection, self)

    def stop(self, connection):
        llrp_stop_rospec(connection, self)

class LLRPMessageDict(dict):
    def __repr__(self):
        return llrp_data2xml(self)

# Reverse dictionary for Message_struct types
Message_Type2Name = { }
for m in Message_struct:
    if 'type' in Message_struct[m]:
        i = Message_struct[m]['type']
        Message_Type2Name[i] = m
    else:
        logging.warn('Message_struct type {} lacks "type" field'.format(m))

#
# Main
#

def main():
    print 'nothing to do...'

#
# Module or not module?
#
if __name__ == '__main__':
    main()
