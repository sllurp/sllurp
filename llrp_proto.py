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

import logging, inspect, struct, exceptions
from threading import *
from types import *
from socket import *

#
# Define exported symbols
#

__all__ = [
	# Exceptions
	"LLRPError",
	"LLRPResponseError",

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

logger = logging.getLogger("llrpc")
logger.setLevel(logging.DEBUG)

# Create console handler and set level to debug
log = logging.StreamHandler()
log.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(name)s[%(process)d]: ' \
			'%(filename)s[%(lineno) 4d]: %(message)s')
log.setFormatter(formatter)

# Add log to logger
logger.addHandler(log)

#
# Define exceptions
#

class LLRPError(Exception):
	pass

class LLRPResponseError(LLRPError):
	pass

#
# Local functions
#

def BIT(n):
	return 1 << n

def BITMASK(n):
	return ((1 << (n)) - 1)

def func():
	return inspect.stack()[1][3]

def decode(data):
	return Message_struct[data]['decode']

def encode(data):
	return Message_struct[data]['encode']

def reverse_dict(data):
	atad = { }
	for m in data:
		i = data[m]
		atad[i] = m

	return atad

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
	msg = LLRPMessage()

	# Try to read the message's header first.
	data = connection.stream.recv(gen_header_len)
	type, length = struct.unpack(gen_header, data)

	# Little sanity checks
	ver = (type >> 10) & BITMASK(3)
	if (ver != VER_PROTO_V1) :
		raise LLRPError('messages version %d are not supported' % ver)
	
	# Then try to read the message's body.
	length -= gen_header_len
	data += connection.stream.recv(length)
	dump(data, 'recv')

	header = data[0 : msg_header_len]
	type, length, id = struct.unpack(msg_header, header)
	type = type & BITMASK(10)
	body = data[msg_header_len : msg_header_len + length - msg_header_len]
	logger.debug('%s (type=%d len=%d id=%d)' % (func(), type, length, id))

	# Decode message
        try:
        	name = Message_Type2Name[type]
        except KeyError:
                raise LLRPError('message type %d is not supported' % type)
	data = decode(name)(body)

	msg[name] = data
	msg[name]['Ver'] = ver
	msg[name]['Type'] = type
	msg[name]['ID'] = id
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
	type = msg[name]['Type'] & BITMASK(10)
	id = msg[name]['ID']

	data = encode(name)(msg[name])

	data = struct.pack(msg_header, (ver << 10) | type,
				len(data) + msg_header_len, id) + data
	dump(data, 'send')

	connection.stream.send(data)

#
# LLRP defines & structs
#

LLRP_PORT				= 5084

VER_PROTO_V1				= 1

gen_header = '!HI'
gen_header_len = struct.calcsize(gen_header)
msg_header = '!HII'
msg_header_len = struct.calcsize(msg_header)    
par_header = '!HH'
par_header_len = struct.calcsize(par_header)    
tve_header = '!B'
tve_header_len = struct.calcsize(tve_header)    

# 9.1.1 Capabilities requests
Capability_Name2Type = {
	'All':					0,
	'General Device Capabilities':		1,
	'LLRP Capabilities':			2,
	'Regulatory Capabilities':		3,
	'Air Protocol LLRP Capabilities':	4
}

Capability_Type2Name = reverse_dict(Capability_Name2Type)

# 10.2.1 ROSpec states
ROSpecState_Name2Type = {
	'Disabled':				0,
	'Inactive':				1,
	'Active':				2
}

ROSpecState_Type2Name = reverse_dict(ROSpecState_Name2Type)

# 10.2.1.1.1 ROSpec Start trigger
StartTrigger_Name2Type = {
	'Null':					0,
	'Immediate':				1,
	'Periodic':				2,
	'GPI':					3
}

StartTrigger_Type2Name = reverse_dict(StartTrigger_Name2Type)

# 10.2.1.1.2 ROSpec Stop trigger
StopTrigger_Name2Type = {
	'Null':					0,
	'Duration':				1,
	'GPI with timeout':			2,
	'Tag observation':			3
}

StopTrigger_Type2Name = reverse_dict(StopTrigger_Name2Type)

# 13.2.6.11 Connection attemp events
ConnEvent_Name2Type = {
	'Success':							0,
	'Failed (a Reader initiated connection already exists)':	1,
	'Failed (a Client initiated connection already exists)':	2,
	'Failed (any reason other than a connection already exists)':	3,
	'Another connection attempted':					4,
}

ConnEvent_Type2Name = reverse_dict(ConnEvent_Name2Type)
for m in ConnEvent_Name2Type:
	i = ConnEvent_Name2Type[m]
	ConnEvent_Type2Name[i] = m

# 14.1.1 Error messages
Error_Name2Type = {
	'Success':				0,
	'ParameterError':			100,
	'FieldError':				101,
	'DeviceError':				401,
}

Error_Type2Name = reverse_dict(Error_Name2Type)
for m in Error_Name2Type:
	i = Error_Name2Type[m]
	Error_Type2Name[i] = m

#
# LLRP Messages
#

Message_struct = { }

# 16.1.1 GET_READER_CAPABILITIES
def encode_GetReaderCapabilities(msg):
	req = msg['RequestedData']

	return struct.pack('!B', req)

Message_struct['GET_READER_CAPABILITIES'] = {
	'type':	1,
	'fields': [
		'Ver', 'Type', 'ID',
		'RequestedData'
	],
	'encode': encode_GetReaderCapabilities
}

# 16.1.2 GET_READER_CAPABILITIES_RESPONSE
def decode_GetReaderCapabilitiesResponse(data):
	msg = LLRPMessage()
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
	'type':	11,
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
	'type':	20,
	'fields': [
		'Ver', 'Type', 'ID',
		'ROSpec'
	],
	'encode': encode_AddROSpec
}

# 16.1.4 ADD_ROSPEC_RESPONSE
def decode_AddROSpecResponse(data):
	msg = LLRPMessage()
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
	'type':	30,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_AddROSpecResponse
}

# 16.1.5 DELETE_ROSPEC
def encode_DeleteROSpec(msg):
        id = msg['ROSpecID']

        return struct.pack('!I', id)

Message_struct['DELETE_ROSPEC'] = {
	'type':	21,
	'fields': [
		'Ver', 'Type', 'ID',
		'ROSpecID'
	],
	'encode': encode_DeleteROSpec
}

# 16.1.6 DELETE_ROSPEC_RESPONSE
def decode_DeleteROSpecResponse(data):
	msg = LLRPMessage()
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
	'type':	31,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_DeleteROSpecResponse
}

# 16.1.7 START_ROSPEC
def encode_StartROSpec(msg):
        id = msg['ROSpecID']

        return struct.pack('!I', id)

Message_struct['START_ROSPEC'] = {
	'type':	22,
	'fields': [
		'Ver', 'Type', 'ID',
		'ROSpecID'
	],
	'encode': encode_StartROSpec
}

# 16.1.8 START_ROSPEC_RESPONSE
def decode_StartROSpecResponse(data):
	msg = LLRPMessage()
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
	'type':	32,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_StartROSpecResponse
}

# 16.1.9 STOP_ROSPEC
def encode_StopROSpec(msg):
        id = msg['ROSpecID']

        return struct.pack('!I', id)

Message_struct['STOP_ROSPEC'] = {
	'type':	23,
	'fields': [
		'Ver', 'Type', 'ID',
		'ROSpecID'
	],
	'encode': encode_StopROSpec
}

# 16.1.10 STOP_ROSPEC_RESPONSE
def decode_StopROSpecResponse(data):
	msg = LLRPMessage()
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
	'type':	33,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_StopROSpecResponse
}

# 16.1.11 ENABLE_ROSPEC
def encode_EnableROSpec(msg):
	id = msg['ROSpecID']

	return struct.pack('!I', id)

Message_struct['ENABLE_ROSPEC'] = {
	'type':	24,
	'fields': [
		'Ver', 'Type', 'ID',
		'ROSpecID'
	],
	'encode': encode_EnableROSpec
}

# 16.1.12 ENABLE_ROSPEC_RESPONSE
def decode_EnableROSpecResponse(data):
	msg = LLRPMessage()
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
	'type':	34,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_EnableROSpecResponse
}

# 16.1.13 DISABLE_ROSPEC
def encode_DisableROSpec(msg):
        id = msg['ROSpecID']

        return struct.pack('!I', id)

Message_struct['DISABLE_ROSPEC'] = {
	'type':	25,
	'fields': [
		'Ver', 'Type', 'ID',
		'ROSpecID'
	],
	'encode': encode_DisableROSpec
}

# 16.1.14 DISABLE_ROSPEC_RESPONSE
def decode_DisableROSpecResponse(data):
	msg = LLRPMessage()
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
	'type':	35,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_DisableROSpecResponse
}

# 16.1.30 RO_ACCESS_REPORT
def decode_ROAccessReport(data):
	msg = LLRPMessage()
	logger.debug('%s' % func())

	# Decode parameters
	msg['TagReportData'] = [ ]
	while True:
		ret, data = decode('TagReportData')(data)
		if ret:
			msg['TagReportData'].append(ret)
		else:
			break

	# Check the end of the message
	if len(data) > 0:
		raise LLRPError('junk at end of message: ' + bin2dump(body))

	return msg

Message_struct['RO_ACCESS_REPORT'] = {
	'type':	61,
	'fields': [
		'Ver', 'Type', 'ID',
		'TagReportData',
	],
	'decode': decode_ROAccessReport
}

# 16.1.33 READER_EVENT_NOTIFICATION
def decode_ReaderEventNotification(data):
	msg = LLRPMessage()
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
	'type':	63,
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
	'type':	14,
	'fields': [
		'Ver', 'Type', 'ID',
	],
	'encode': encode_CloseConnection
}

# 16.1.41 CLOSE_CONNECTION_RESPONSE
def decode_CloseConnectionResponse(data):
	msg = LLRPMessage()
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
	'type':	4,
	'fields': [
		'Ver', 'Type', 'ID',
		'LLRPStatus'
	],
	'decode': decode_CloseConnectionResponse
}

Message_Type2Name = { }
for m in Message_struct:
	i = Message_struct[m]['type']
	Message_Type2Name[i] = m

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
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['UTCTimestamp']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

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
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['LLRPCapabilities']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

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
	'type':	142,
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

# 16.2.4.1 ROSpec Parameter
def encode_ROSpec(par):
	type = Message_struct['ROSpec']['type']
	id = par['ROSpecID'] & BITMASK(10)
	priority = par['Priority'] & BITMASK(7)
	state = ROSpecState_Name2Type[par['CurrentState']] & BITMASK(7)

	msg_header = '!HHIBB'
	msg_header_len = struct.calcsize(msg_header)

	data = encode('ROBoundarySpec')(par['ROBoundarySpec'])
	data += encode('AISpec')(par['AISpec'])

        data = struct.pack(msg_header, type,
                                len(data) + msg_header_len,
				id, priority, state) + data

	return data

Message_struct['ROSpec'] = {
	'type':	177,
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
	type = Message_struct['ROBoundarySpec']['type']

	msg_header = '!HH'
	msg_header_len = struct.calcsize(msg_header)

	data = encode('ROSpecStartTrigger')(par['ROSpecStartTrigger'])
	data += encode('ROSpecStopTrigger')(par['ROSpecStopTrigger'])

	data = struct.pack(msg_header, type,
                                len(data) + msg_header_len) + data

	return data

Message_struct['ROBoundarySpec'] = {
	'type':	178,
	'fields': [
		'Type',
		'ROSpecStartTrigger',
		'ROSpecStopTrigger'
	],
	'encode': encode_ROBoundarySpec
}

# 16.2.4.1.1.1 ROSpecStartTrigger Parameter
def encode_ROSpecStartTrigger(par):
	type = Message_struct['ROSpecStartTrigger']['type']
	t_type = StartTrigger_Name2Type[par['ROSpecStartTriggerType']]

	msg_header = '!HHB'
	msg_header_len = struct.calcsize(msg_header)

	data = ''

        data = struct.pack(msg_header, type,
                                len(data) + msg_header_len, t_type) + data

	return data

Message_struct['ROSpecStartTrigger'] = {
	'type':	179,
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
	type = Message_struct['ROSpecStopTrigger']['type']
	t_type = StopTrigger_Name2Type[par['ROSpecStopTriggerType']]
	duration = par['DurationTriggerValue']

	msg_header = '!HHBI'
	msg_header_len = struct.calcsize(msg_header)

	data = ''

        data = struct.pack(msg_header, type,
                                len(data) + msg_header_len,
				t_type, duration) + data

	return data

Message_struct['ROSpecStopTrigger'] = {
	'type':	182,
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
	type = Message_struct['AISpec']['type']
	count = len(par['AntennaID'])

	msg_header = '!HHH'
	msg_header_len = struct.calcsize(msg_header)

	data = ''
	for a in par['AntennaID']:
		data += struct.pack('!H', a)

	data += encode('AISpecStopTrigger')(par['AISpecStopTrigger'])
	data += encode('InventoryParameterSpec')(par['InventoryParameterSpec'])

        data = struct.pack(msg_header, type,
                                len(data) + msg_header_len, count) + data

	return data

Message_struct['AISpec'] = {
	'type': 183,
	'fields': [
                'Type',
		'AntennaID',
		'AISpecStopTrigger',
		'InventoryParameterSpec'
	],
	'encode': encode_AISpec
}

# 16.2.4.2.1 AISpecStopTrigger Parameter
def encode_AISpecStopTrigger(par):
	type = Message_struct['AISpecStopTrigger']['type']
	t_type = StopTrigger_Name2Type[par['AISpecStopTriggerType']]
	duration = par['DurationTriggerValue']

	msg_header = '!HHBI'
	msg_header_len = struct.calcsize(msg_header)

	data = ''

        data = struct.pack(msg_header, type,
                                len(data) + msg_header_len,
				t_type, duration) + data

	return data

Message_struct['AISpecStopTrigger'] = {
	'type':	184,
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
	type = Message_struct['InventoryParameterSpec']['type']
	inv = par['InventoryParameterSpecID']
	proto = par['ProtocolID']

	msg_header = '!HHHB'
	msg_header_len = struct.calcsize(msg_header)

	data = ''

        data = struct.pack(msg_header, type,
                                len(data) + msg_header_len,
				inv, proto) + data

	return data

Message_struct['InventoryParameterSpec'] = {
	'type':	186,
	'fields': [
		'Type',
		'InventoryParameterSpecID',
		'ProtocolID',
		'AntennaConfiguration'
	],
	'encode': encode_InventoryParameterSpec
}

# 16.2.7.3 TagReportData Parameter
def decode_TagReportData(data):
	par = {}
	logger.debug('%s' % func())

	if len(data) == 0:
		return None, data

	header = data[0 : par_header_len]
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
        if type != Message_struct['TagReportData']['type']:
                return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode parameters
	ret, body = decode('EPCData')(body)
	if ret:
		par['EPCData'] = ret
	else:
		ret, body = decode('EPC-96')(body)
		if ret:
			par['EPC-96'] = ret
		else:
			raise LLRPError('missing or invalid EPCData parameter')

	ret, body = decode('ROSpecID')(body)
	if ret:
		par['ROSpecID'] = ret

	# Check the end of the message
	if len(body) > 0:
		raise LLRPError('junk at end of message: ' + bin2dump(body))

	return par, data[length : ]

Message_struct['TagReportData'] = {
	'type':	240,
	'fields': [
		'Type',
		'EPCData', 'EPC-96',
		'ROSpecID',
	],
	'decode': decode_TagReportData
}

# 16.2.7.3.1 EPCData Parameter
def decode_EPCData(data):
	par = {}

	if len(data) == 0:
		return None, data

	header = data[0 : par_header_len]
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['EPCData']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode fields
	(par['EPCLengthBits'], ) = struct.unpack('!H',
					body[0 : struct.calcsize('!H')])
	par['EPC'] = body[struct.calcsize('!H') : ].encode('hex')

        return par, data[length : ]

Message_struct['EPCData'] = {
	'type':	241,
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
	(type, ), length = struct.unpack(tve_header, header), 1 + (96 / 8)
	type = type & BITMASK(7)
	if type != Message_struct['EPC-96']['type']:
		return (None, data)
	body = data[tve_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode fields
	par['EPC'] = body.encode('hex')

        return par, data[length : ]

Message_struct['EPC-96'] = {
	'type':	13,
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
	(type, ), length = struct.unpack(tve_header, header), 1 + 4
	type = type & BITMASK(7)
	if type != Message_struct['EPC-96']['type']:
		return (None, data)
	body = data[tve_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode fields
	(par['ROSpecID'], ) = struct.unpack('!I', body)

        return par, data[length : ]

Message_struct['ROSpecID'] = {
	'type':	9,
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
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode parameters
	ret, body = decode('UTCTimestamp')(body)
	if ret:
		par['UTCTimestamp'] = ret
	else:
		raise LLRPError('missing or invalid UTCTimestamp parameter')

	ret, body = decode('ConnectionAttemptEvent')(body)
	if ret:
		par['ConnectionAttemptEvent'] = ret

	return par, body

Message_struct['ReaderEventNotificationData'] = {
	'type':	246,
	'fields': [
		'Type',
	],
	'decode': decode_ReaderEventNotificationData
}

# 16.2.7.6.10 ConnectionAttemptEvent Parameter
def decode_ConnectionAttemptEvent(data):
	logger.debug(func())
	par = {}

	if len(data) == 0:
		return None, data

	header = data[0 : par_header_len]
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['ConnectionAttemptEvent']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode fields
	(status, ) = struct.unpack('!H', body)
	par['Status'] = ConnEvent_Type2Name[status]

	return par, data[length : ]

Message_struct['ConnectionAttemptEvent'] = {
	'type':	256,
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

	if len(data) == 0:
		return None, data

	header = data[0 : par_header_len]
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['LLRPStatus']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d)' % (func(), type, length))

	# Decode fields
	offset = struct.calcsize('!HH')
	(code, n) = struct.unpack('!HH', body[ : offset])
	par['StatusCode'] = Error_Type2Name[code]
	par['ErrorDescription'] = body[offset : offset + n]

	# Decode parameters
	ret, body = decode('FieldError')(body[offset + n : ])
	if ret:
		par['FieldError'] = ret

	ret, body = decode('ParameterError')(body)
	if ret:
		par['ParameterError'] = ret

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
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['FieldError']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d data=%s)' % \
			(func(), type, length, repr(body)))

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
	type, length = struct.unpack(par_header, header)
	type = type & BITMASK(10)
	if type != Message_struct['ParameterError']['type']:
		return (None, data)
	body = data[par_header_len : length]
	logger.debug('%s (type=%d len=%d data=%s)' % \
			(func(), type, length, repr(body)))

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
	id = rospec['ROSpec']['ROSpecID']

	msg = LLRPMessage()
	msg['ADD_ROSPEC'] = {
		'Ver':  1,
                'Type': Message_struct['ADD_ROSPEC']['type'],
                'ID':   0,
		'ROSpecID' : id
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
	msg = LLRPMessage()
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
	id = rospec['ROSpec']['ROSpecID']

	msg = LLRPMessage()
	msg['DELETE_ROSPEC'] = {
		'Ver':  1,
                'Type': Message_struct['DELETE_ROSPEC']['type'],
                'ID':   0,
		'ROSpecID' : id
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
	id = rospec['ROSpec']['ROSpecID']

	msg = LLRPMessage()
	msg['DISABLE_ROSPEC'] = {
		'Ver':  1,
                'Type': Message_struct['DISABLE_ROSPEC']['type'],
                'ID':   0,
		'ROSpecID' : id
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
	id = rospec['ROSpec']['ROSpecID']

	msg = LLRPMessage()
	msg['ENABLE_ROSPEC'] = {
		'Ver':	1,
		'Type': Message_struct['ENABLE_ROSPEC']['type'],
		'ID':	0,
		'ROSpecID' : id
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

	msg = LLRPMessage()
	msg['GET_READER_CAPABILITIES'] = {
		'Ver':	1,
		'Type':	Message_struct['GET_READER_CAPABILITIES']['type'],
		'ID':	0,
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
			elif type(sub) == ListType and \
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
	id = rospec['ROSpec']['ROSpecID']

	msg = LLRPMessage()
	msg['START_ROSPEC'] = {
		'Ver':	1,
		'Type':	Message_struct['START_ROSPEC']['type'],
		'ID':	0,
		'ROSpecID' : id
	}

	logger.debug(msg)
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
	id = rospec['ROSpec']['ROSpecID']

	msg = LLRPMessage()
	msg['STOP_ROSPEC'] = {
		'Ver':  1,
                'Type': Message_struct['STOP_ROSPEC']['type'],
                'ID':   0,
		'ROSpecID' : id
	}

	logger.debug(msg)
	send_message(connection, msg)

	# Wait for the answer
	ans = wait_for_message(connection)

	# Check the server response
	try:
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
	connection.msg_cond.acquire()

	while len(connection.messages) == 0:
		connection.msg_cond.wait()

	msg = connection.messages.pop(0)

	connection.msg_cond.release()

	return msg

class reader_thread(Thread):
	def __init__(self, connection):
		Thread.__init__(self)
		self.connection = connection

	def run(self):
		connection = self.connection

		while True:
			events = [
				'RO_ACCESS_REPORT',
				'READER_EVENT_NOTIFICATION',
			]

			# Wait for a server message
			while True:
				try:
					msg = recv_message(connection)
				except:
					return

				# Before returning data to the caller we should check
				# for remote server's events
				if msg.keys()[0] in events:
					connection.event_cb(connection, msg)
				else:
					break

			connection.msg_cond.acquire()

			connection.messages.append(msg)

			connection.msg_cond.notifyAll()
			connection.msg_cond.release()

class LLRPdConnection():
	def __init__(self, host, port = LLRP_PORT, event_cb = do_nothing):
		# Create the communication socket and then do the connect
		self.stream = socket(AF_INET, SOCK_STREAM)
		llrp_connect(self, host, port)

		# Set events callback to void function
		self.event_cb = event_cb

		# Setup the messages mutex
		self.messages = list()
		self.msg_cond = Condition()

		# Start the receiving thread
		self.recv_thread = reader_thread(self)
		self.recv_thread.start()

	def close(self):
		llrp_close(self)

	def delete_all_rospec(self):
		rospec = { }
		rospec['ROSpec'] = { }
		rospec['ROSpec']['ROSpecID'] = 0
		llrp_delete_rospec(self, rospec)

	def disable_all_rospec(self):
		rospec = { }
		rospec['ROSpec'] = { }
		rospec['ROSpec']['ROSpecID'] = 0
		llrp_disable_rospec(self, rospec)

	def enable_all_rospec(self):
		rospec = { }
		rospec['ROSpec'] = { }
		rospec['ROSpec']['ROSpecID'] = 0
		llrp_enable_rospec(self, rospec)

	def get_capabilities(self, req):
		return llrp_get_capabilities(self, req)

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
	def __init__(self, id, priority = 0, state = 'Disabled'):
		# Sanity checks
		if id <= 0:
			raise LLRPError('invalid argument 1 (not positive)')
		if priority < 0 or priority > 7:
			raise LLRPError('invalid argument 2 (not in [0-7])')
		if not state in ROSpecState_Name2Type:
			raise LLRPError('invalid argument 3 (not [%s])' %
					ROSpecState_Name2Type.keys())

		self['ROSpec'] = { }
		self['ROSpec']['ROSpecID'] = id
		self['ROSpec']['Priority'] = priority
		self['ROSpec']['CurrentState'] = state

		self['ROSpec']['ROBoundarySpec'] = {}
		self['ROSpec']['ROBoundarySpec']\
				['ROSpecStartTrigger'] = { }
		self['ROSpec']['ROBoundarySpec']\
				['ROSpecStartTrigger']\
				['ROSpecStartTriggerType'] = 'Null'

		self['ROSpec']['ROBoundarySpec']\
				['ROSpecStopTrigger'] = { }
		self['ROSpec']['ROBoundarySpec']\
				['ROSpecStopTrigger']\
				['ROSpecStopTriggerType'] = 'Null'
		self['ROSpec']['ROBoundarySpec']\
				['ROSpecStopTrigger']\
				['DurationTriggerValue'] = 0

		self['ROSpec']['AISpec'] = {}
		self['ROSpec']['AISpec']\
				['AntennaID'] = [ 0, ]

		self['ROSpec']['AISpec']\
				['AISpecStopTrigger'] = { }
		self['ROSpec']['AISpec']\
				['AISpecStopTrigger']\
				['AISpecStopTriggerType'] = 'Null'
		self['ROSpec']['AISpec']\
				['AISpecStopTrigger']\
				['DurationTriggerValue'] = 0

		self['ROSpec']['AISpec']\
				['InventoryParameterSpec'] = { }
		self['ROSpec']['AISpec']\
				['InventoryParameterSpec']\
				['InventoryParameterSpecID'] = 0
		self['ROSpec']['AISpec']\
				['InventoryParameterSpec']\
				['ProtocolID'] = 0

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

class LLRPMessage(dict):
	def __repr__(self):
		return llrp_data2xml(self)

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
