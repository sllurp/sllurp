from __future__ import print_function
from collections import defaultdict
import time
import socket
import logging
import pprint
import struct
from llrp_proto import LLRPROSpec, LLRPError, Message_struct, \
         Message_Type2Name, Capability_Name2Type, AirProtocol, \
         llrp_data2xml, LLRPMessageDict, ModeIndex_Name2Type, \
         Modulation_Name2Type, DEFAULT_MODULATION
import copy
from binascii import hexlify
from util import *
from twisted.internet import reactor, task, defer
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet.error import ReactorAlreadyRunning, ReactorNotRunning

LLRP_PORT = 5084

logger = logging.getLogger(__name__)

class LLRPMessage:
    hdr_fmt = '!HI'
    hdr_len = struct.calcsize(hdr_fmt) # == 6 bytes
    full_hdr_fmt = hdr_fmt + 'I'
    full_hdr_len = struct.calcsize(full_hdr_fmt) # == 10 bytes
    msgdict = None
    msgbytes = None

    def __init__ (self, msgdict=None, msgbytes=None):
        if not (msgdict or msgbytes):
            raise LLRPError('Provide either a message dict or a sequence' \
                    ' of bytes.')
        if msgdict:
            self.msgdict = LLRPMessageDict(msgdict)
            if not msgbytes:
                self.serialize()
        if msgbytes:
            self.msgbytes = msgbytes
            if not msgdict:
                self.deserialize()
        self.peername = None

    def serialize (self):
        if self.msgdict is None:
            raise LLRPError('No message dict to serialize.')
        name = self.msgdict.keys()[0]
        logger.debug('serializing %s command', name)
        ver = self.msgdict[name]['Ver'] & BITMASK(3)
        msgtype = self.msgdict[name]['Type'] & BITMASK(10)
        msgid = self.msgdict[name]['ID']
        try:
            encoder = Message_struct[name]['encode']
        except KeyError:
            raise LLRPError('Cannot find encoder for message type '
                    '{}'.format(name))
        data = encoder(self.msgdict[name])
        self.msgbytes = struct.pack(self.full_hdr_fmt,
                (ver << 10) | msgtype,
                len(data) + self.full_hdr_len,
                msgid) + data
        logger.debug('serialized bytes: %s', hexlify(self.msgbytes))
        logger.debug('done serializing %s command', name)

    def deserialize (self):
        """Turns a sequence of bytes into a message dictionary."""
        if self.msgbytes is None:
            raise LLRPError('No message bytes to deserialize.')
        data = ''.join(self.msgbytes)
        msgtype, length, msgid = struct.unpack(self.full_hdr_fmt,
                data[:self.full_hdr_len])
        ver = (msgtype >> 10) & BITMASK(3)
        msgtype = msgtype & BITMASK(10)
        try:
            name = Message_Type2Name[msgtype]
            logger.debug('deserializing %s command', name)
            decoder = Message_struct[name]['decode']
        except KeyError:
            raise LLRPError('Cannot find decoder for message type '
                    '{}'.format(msgtype))
        body = data[self.full_hdr_len:length]
        try:
            self.msgdict = {
               name: dict(decoder(body))
            }
            self.msgdict[name]['Ver'] = ver
            self.msgdict[name]['Type'] = msgtype
            self.msgdict[name]['ID'] = msgid
            logger.debug('done deserializing %s command', name)
        except LLRPError as e:
            logger.exception('Problem with %s message format', name)
            return ''
        return ''

    def isSuccess (self):
        if not self.msgdict:
            return False
        success = False
        msgName = self.getName()
        md = self.msgdict[msgName]

        try:
            if msgName == 'READER_EVENT_NOTIFICATION':
                return md['ReaderEventNotificationData']\
                    ['ConnectionAttemptEvent']['Status'] == 'Success'
            elif 'LLRPStatus' in md:
                return md['LLRPStatus']['StatusCode'] == 'Success'
        except KeyError as KE:
            logger.exception('failed to parse status from %s', msgName)
            return False

    def getName (self):
        if not self.msgdict:
            return None
        return self.msgdict.keys()[0]

    def __repr__ (self):
        try:
            ret = llrp_data2xml(self.msgdict)
        except TypeError as te:
            logger.exception(te)
            ret = ''
        return ret

class LLRPClient (LineReceiver):
    STATE_DISCONNECTED = 1
    STATE_CONNECTING = 2
    STATE_CONNECTED = 3
    STATE_SENT_ADD_ROSPEC = 4
    STATE_SENT_ENABLE_ROSPEC = 5
    STATE_INVENTORYING = 6
    STATE_SENT_DELETE_ROSPEC = 7
    STATE_SENT_DELETE_ACCESSSPEC = 8
    STATE_SENT_GET_CAPABILITIES = 9
    STATE_PAUSING = 10
    STATE_PAUSED = 11

    @classmethod
    def getStates (_):
        state_names = [st for st in dir(LLRPClient) if st.startswith('STATE_')]
        for state_name in state_names:
            state_num = getattr(LLRPClient, state_name)
            yield state_name, state_num

    @classmethod
    def getStateName (_, state):
        try:
            return [st_name for st_name, st_num in LLRPClient.getStates() \
                    if st_num == state][0]
        except IndexError:
            raise LLRPError('unknown state {}'.format(state))

    def __init__ (self, factory, duration=None, report_every_n_tags=None,
            antennas=(1,), tx_power=0, modulation=DEFAULT_MODULATION, tari=0,
            start_inventory=True, reset_on_connect=True,
            disconnect_when_done=True,
            tag_content_selector={},
            session=2, tag_population=4):
        self.factory = factory
        self.setRawMode()
        self.state = LLRPClient.STATE_DISCONNECTED
        self.report_every_n_tags = report_every_n_tags
        self.capabilities = {}
        self.reader_mode = None
        self.tx_power = tx_power
        self.modulation = modulation
        self.tari = tari
        self.session = session
        self.tag_population = tag_population
        self.antennas = antennas
        self.duration = duration
        self.peername = None
        self.tx_power_table = []
        self.start_inventory = start_inventory
        self.reset_on_connect = reset_on_connect
        if self.reset_on_connect:
            logger.info('will reset reader state on connect')
        self.disconnect_when_done = disconnect_when_done
        self.tag_content_selector = tag_content_selector
        if self.start_inventory:
            logger.info('will start inventory on connect')

        logger.info('using antennas: %s', self.antennas)

        # for partial data transfers
        self.expectingRemainingBytes = 0
        self.partialData = ''

        # state-change callbacks: STATE_* -> [list of callables]
        self._state_callbacks = {}
        for _, st_num in LLRPClient.getStates():
            self._state_callbacks[st_num] = []

        # message callbacks (including tag reports):
        # msg_name -> [list of callables]
        self._message_callbacks = defaultdict(list)

        # Deferreds to fire during state machine machinations
        self._deferreds = defaultdict(list)

        self.disconnecting = False
        self.rospec = None

    def addStateCallback (self, state, cb):
        self._state_callbacks[state].append(cb)

    def addMessageCallback (self, msg_type, cb):
        self._message_callbacks[msg_type].append(cb)

    def connectionMade (self):
        self.transport.setTcpKeepAlive(True)
        self.peername = self.transport.getHandle().getpeername()
        logger.info('connected to %s', self.peername)
        self.factory.protocols.add(self)

    def setState (self, newstate, onComplete=None):
        assert newstate is not None
        logger.debug('state change: %s -> %s',
                    LLRPClient.getStateName(self.state),
                    LLRPClient.getStateName(newstate))

        self.state = newstate

        for fn in self._state_callbacks[newstate]:
            fn(self)

    def _setState_wrapper (self, _, *args, **kwargs):
        """Version of setState suitable for calling via a Deferred callback.
           XXX this is a gross hack."""
        self.setState(args[0], **kwargs)

    def connectionLost (self, reason):
        self.factory.protocols.remove(self)

    def parseCapabilities (self, capdict):
        def find_p (p, arr):
            m = p(arr)
            for idx, val in enumerate(arr):
                if val == m: return idx

        # check requested antenna set
        gdc = capdict['GeneralDeviceCapabilities']
        if max(self.antennas) > gdc['MaxNumberOfAntennaSupported']:
            reqd = ','.join(map(str, self.antennas))
            avail = ','.join(map(str,
                             range(1, gdc['MaxNumberOfAntennaSupported']+1)))
            logger.warn('Invalid antenna set specified: requested=%s,'
                        ' available=%s; ignoring invalid antennas', reqd, avail)
            self.antennas = [ant for ant in self.antennas \
                            if ant <= gdc['MaxNumberOfAntennaSupported']]

        # check requested Tx power
        logger.debug('requested tx_power: %s', self.tx_power)
        bandtbl = capdict['RegulatoryCapabilities']['UHFBandCapabilities']
        bandtbl = {k: v for k, v in bandtbl.items() \
            if k.startswith('TransmitPowerLevelTableEntry')}
        self.tx_power_table = [0,] * (len(bandtbl) + 1)
        for k, v in bandtbl.items():
            idx = v['Index']
            self.tx_power_table[idx] = int(v['TransmitPowerValue']) / 100.0
        logger.debug('tx_power_table: %s', self.tx_power_table)
        if self.tx_power == 0:
            # tx_power = 0 means max power
            self.tx_power = find_p(max, self.tx_power_table)
        elif self.tx_power not in range(len(self.tx_power_table)):
            raise LLRPError('Invalid tx_power: requested={},' \
                    ' max_available={}, min_available={}'.format(self.tx_power,
                        find_p(max, self.tx_power_table),
                        find_p(min, self.tx_power_table)))
        logger.debug('set tx_power: %s (%s dBm)', self.tx_power,
                    self.tx_power_table[self.tx_power])

        # fill UHFC1G2RFModeTable & check requested modulation & Tari
        match = False # have we matched the user's requested values yet?
        regcap = capdict['RegulatoryCapabilities']
        logger.info('requested modulation: %s', self.modulation)
        for v in regcap['UHFBandCapabilities']['UHFRFModeTable'].values():
            match = v['Mod'] == Modulation_Name2Type[self.modulation]
            if self.tari:
                match = match and (v['MaxTari'] == self.tari)
            if match:
                self.reader_mode = dict(v)
        if not self.reader_mode:
            taristr = ' and Tari={}'.format(self.tari) if self.tari else ''
            logger.warn('Could not find reader mode matching '\
                    'modulation=%s%s', self.modulation, taristr)
            self.reader_mode = dict(regcap['UHFBandCapabilities']\
                    ['UHFRFModeTable']['UHFC1G2RFModeTableEntry0'])
        logger.info('using reader mode: %s', self.reader_mode)

    def processDeferreds (self, msgName, isSuccess):
        deferreds = self._deferreds[msgName]
        if not deferreds:
            return
        logger.debug('running %d Deferreds for %s; ' \
                'isSuccess=%s', len(deferreds), msgName, isSuccess)
        for d in deferreds:
            if isSuccess:
                d.callback(self.state)
            else:
                d.errback(self.state)
        del self._deferreds[msgName]

    def handleMessage (self, lmsg):
        """Implements the LLRP client state machine."""
        logger.debug('LLRPMessage received in state %s: %s', self.state, lmsg)
        msgName = lmsg.getName()
        lmsg.peername = self.peername

        # call per-message callbacks
        logger.debug('starting message callbacks for %s', msgName)
        for fn in self._message_callbacks[msgName]:
            fn(lmsg)
        logger.debug('done with message callbacks for %s', msgName)

        # keepalives can occur at any time
        if msgName == 'KEEPALIVE':
            self.send_KEEPALIVE_ACK()
            return

        if msgName == 'RO_ACCESS_REPORT' and \
                    self.state != LLRPClient.STATE_INVENTORYING:
            logger.debug('ignoring RO_ACCESS_REPORT because not inventorying')
            return

        logger.debug('in handleMessage(%s), there are %d Deferreds',
                msgName, len(self._deferreds[msgName]))

        #######
        # LLRP client state machine follows.  Beware: gets thorny.  Note the
        # order of the LLRPClient.STATE_* fields.
        #######

        # in DISCONNECTED, CONNECTING, and CONNECTED states, expect only
        # READER_EVENT_NOTIFICATION messages.
        if self.state in (LLRPClient.STATE_DISCONNECTED,
                LLRPClient.STATE_CONNECTING, LLRPClient.STATE_CONNECTED):
            if msgName != 'READER_EVENT_NOTIFICATION':
                logger.error('unexpected message %s while connecting', msgName)
                return

            if not lmsg.isSuccess():
                try:
                    status = lmsg.msgdict[msgName]\
                             ['ReaderEventNotificationData']\
                             ['ConnectionAttemptEvent']['Status']
                except KeyError:
                    status = '(unknown status)'
                logger.fatal('Could not start session on reader: %s', status)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

            # a Deferred to call when we get GET_READER_CAPABILITIES_RESPONSE
            d = defer.Deferred()
            d.addCallback(self._setState_wrapper, LLRPClient.STATE_CONNECTED)
            d.addErrback(self.panic, 'GET_READER_CAPABILITIES failed')
            self.send_GET_READER_CAPABILITIES(onCompletion=d)

        # in state SENT_GET_CAPABILITIES, expect only GET_CAPABILITIES_RESPONSE;
        # respond to this message by advancing to state CONNECTED.
        elif self.state == LLRPClient.STATE_SENT_GET_CAPABILITIES:
            if msgName != 'GET_READER_CAPABILITIES_RESPONSE':
                logger.error('unexpected response %s when getting capabilities',
                        msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s getting capabilities: %s', status, err)
                return

            self.capabilities = lmsg.msgdict['GET_READER_CAPABILITIES_RESPONSE']
            logger.debug('Capabilities: %s', pprint.pformat(self.capabilities))
            try:
                self.parseCapabilities(self.capabilities)
            except LLRPError as err:
                logger.exception('Capabilities mismatch')
                raise err

            self.processDeferreds(msgName, lmsg.isSuccess())

            if self.reset_on_connect:
                d = self.stopPolitely(disconnect=False)
                if self.start_inventory:
                    d.addCallback(self.startInventory)
            elif self.start_inventory:
                self.startInventory()

        # in state SENT_ADD_ROSPEC, expect only ADD_ROSPEC_RESPONSE; respond to
        # favorable ADD_ROSPEC_RESPONSE by enabling the added ROSpec and
        # advancing to state SENT_ENABLE_ROSPEC.
        elif self.state == LLRPClient.STATE_SENT_ADD_ROSPEC:
            if msgName != 'ADD_ROSPEC_RESPONSE':
                logger.error('unexpected response %s when adding ROSpec', msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s adding ROSpec: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state PAUSING, we have sent a DISABLE_ROSPEC, so expect only
        # DISABLE_ROSPEC_RESPONSE.  advance to state PAUSED.
        elif self.state == LLRPClient.STATE_PAUSING:
            if msgName != 'DISABLE_ROSPEC_RESPONSE':
                logger.error('unexpected response %s ' \
                        ' when disabling ROSpec', msgName)

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.error('DISABLE_ROSPEC failed with status %s: %s',
                        status, err)
                logger.warn('Error %s disabling ROSpec: %s', status, err)

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state SENT_ENABLE_ROSPEC, expect only ENABLE_ROSPEC_RESPONSE;
        # respond to favorable ENABLE_ROSPEC_RESPONSE by starting the enabled
        # ROSpec and advancing to state INVENTORYING.
        elif self.state == LLRPClient.STATE_SENT_ENABLE_ROSPEC:
            if msgName != 'ENABLE_ROSPEC_RESPONSE':
                logger.error('unexpected response %s when enabling ROSpec', msgName)

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.error('ENABLE_ROSPEC failed with status %s: %s',
                        status, err)
                logger.fatal('Error %s enabling ROSpec: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

        elif self.state == LLRPClient.STATE_INVENTORYING:
            if msgName not in ('RO_ACCESS_REPORT', 'READER_EVENT_NOTIFICATION',
                    'ADD_ACCESSSPEC_RESPONSE', 'ENABLE_ACCESSSPEC_RESPONSE'):
                logger.error('unexpected message %s while inventorying',
                        msgName)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

        elif self.state == LLRPClient.STATE_SENT_DELETE_ACCESSSPEC:
            if msgName != 'DELETE_ACCESSSPEC_RESPONSE':
                logger.error('unexpected response %s when deleting AccessSpec',
                        msgName)

            self.processDeferreds(msgName, lmsg.isSuccess())

        elif self.state == LLRPClient.STATE_SENT_DELETE_ROSPEC:
            if msgName != 'DELETE_ROSPEC_RESPONSE':
                logger.error('unexpected response %s when deleting ROSpec',
                        msgName)

            if lmsg.isSuccess():
                logger.info('reader finished inventory')
                if self.disconnecting:
                    self.setState(LLRPClient.STATE_DISCONNECTED)
                else:
                    self.setState(LLRPClient.STATE_CONNECTED)

            else:
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.error('DELETE_ROSPEC failed with status %s: %s',
                        status, err)

            self.processDeferreds(msgName, lmsg.isSuccess())
            if self.disconnecting:
                logger.info('disconnecting')
                self.transport.loseConnection()

        else:
            logger.warn('message %s received in unknown state!', msgName)

        if self._deferreds[msgName]:
            logger.error('there should NOT be Deferreds left for %s,' \
                    ' but there are!', msgName)


    def rawDataReceived (self, data):
        logger.debug('got %d bytes from reader: %s', len(data),
                data.encode('hex'))

        if self.expectingRemainingBytes:
            if len(data) >= self.expectingRemainingBytes:
                data = self.partialData + data
                self.partialData = ''
                self.expectingRemainingBytes -= len(data)
            else:
                # still not enough; wait until next time
                self.partialData += data
                self.expectingRemainingBytes -= len(data)
                return

        while data:
            # parse the message header to grab its length
            if len(data) >= LLRPMessage.full_hdr_len:
                msg_type, msg_len, message_id = \
                    struct.unpack(LLRPMessage.full_hdr_fmt,
                                  data[:LLRPMessage.full_hdr_len])
            else:
                logger.warning('Too few bytes (%d) to unpack LLRP message header',
                        len(data))
                self.partialData = data
                self.expectingRemainingBytes = \
                    LLRPMessage.full_hdr_len - len(data)
                break

            logger.debug('expect %d bytes (have %d)', msg_len, len(data))

            if len(data) < msg_len:
                # got too few bytes
                self.partialData = data
                self.expectingRemainingBytes = msg_len - len(data)
                break
            else:
                # got at least the right number of bytes
                self.expectingRemainingBytes = 0
                try:
                    lmsg = LLRPMessage(msgbytes=data[:msg_len])
                    self.handleMessage(lmsg)
                    data = data[msg_len:]
                except LLRPError as err:
                    logger.exception('Failed to decode LLRPMessage; ' \
                            'will not decode %d remaining bytes', len(data))
                    break

    def panic (self, failure, *args):
        logger.error('panic(): %s', args)
        logger.error(failure.getErrorMessage())
        logger.error(failure.getTraceback())

    def complain (self, failure, *args):
        logger.warn('complain(): %s', args)

    def send_KEEPALIVE_ACK (self):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'KEEPALIVE_ACK': {
                'Ver':  1,
                'Type': 72,
                'ID':   0,
            }}))

    def send_GET_READER_CAPABILITIES (self, onCompletion):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'GET_READER_CAPABILITIES': {
                'Ver':  1,
                'Type': 1,
                'ID':   0,
                'RequestedData': Capability_Name2Type['All']
            }}))
        self.setState(LLRPClient.STATE_SENT_GET_CAPABILITIES)
        self._deferreds['GET_READER_CAPABILITIES_RESPONSE'].append(onCompletion)

    def send_ADD_ROSPEC (self, rospec, onCompletion):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'ADD_ROSPEC': {
                'Ver':  1,
                'Type': 20,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID'],
                'ROSpec': rospec,
            }}))
        self.setState(LLRPClient.STATE_SENT_ADD_ROSPEC)
        self._deferreds['ADD_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ROSPEC (self, _, rospec, onCompletion):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'ENABLE_ROSPEC': {
                'Ver':  1,
                'Type': 24,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }}))
        self.setState(LLRPClient.STATE_SENT_ENABLE_ROSPEC)
        self._deferreds['ENABLE_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ADD_ACCESSSPEC (self, accessSpec, onCompletion):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'ADD_ACCESSSPEC': {
                'Ver':  1,
                'Type': 40,
                'ID':   0,
                'AccessSpec': accessSpec,
            }}))
        self._deferreds['ADD_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ACCESSSPEC (self, _, accessSpecID, onCompletion=None):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'ENABLE_ACCESSSPEC': {
                'Ver':  1,
                'Type': 42,
                'ID':   0,
                'AccessSpecID': accessSpecID,
            }}))

        if onCompletion:
            self._deferreds['ENABLE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def startAccess (self, readWords=None, writeWords=None, target = None,
            *args):
        m = Message_struct['AccessSpec']
        if not target:
            target = {
                'MB' : 0,
                'Pointer' : 0,
                'MaskBitCount': 0,
                'TagMask': '',
                'DataBitCount': 0,
                'TagData': ''
            }

        accessSpecID = 1

        opSpecParam = {
            'OpSpecID': 0,
            'AccessPassword': 0,
        }

        if readWords:
            opSpecParam['MB'] = readWords['MB']
            opSpecParam['WordPtr'] = readWords['WordPtr']
            opSpecParam['WordCount'] = readWords['WordCount']
            if 'OpSpecID' in readWords:
                opSpecParam['OpSpecID'] = readWords['OpSpecID']

        elif writeWords:
            opSpecParam['MB'] = writeWords['MB']
            opSpecParam['WordPtr'] = writeWords['WordPtr']
            opSpecParam['WriteDataWordCount'] = writeWords['WriteDataWordCount']
            opSpecParam['WriteData'] = writeWords['WriteData']
            if 'OpSpecID' in writeWords:
                opSpecParam['OpSpecID'] = writeWords['OpSpecID']
        else:
            raise LLRPError('startAccess requires readWords or writeWords.')

        accessSpec = {
            'Type': m['type'],
            'AccessSpecID': accessSpecID,
            'AntennaID': 0, # all antennas
            'ProtocolID': AirProtocol['EPCGlobalClass1Gen2'],
            'C': False, # disabled by default
            'ROSpecID': 0, # all ROSpecs
            'AccessSpecStopTrigger': {
                # 1 = stop after OperationCountValue accesses
                'AccessSpecStopTriggerType': 0,
                'OperationCountValue': 1,
            },
            'AccessCommand': {
                'TagSpecParameter': {
                    'C1G2TargetTag': { # XXX correct values?
                        'MB': target['MB'],
                        'M': 1,
                        'Pointer': target['Pointer'],
                        'MaskBitCount': target['MaskBitCount'],
                        'TagMask': target['TagMask'],
                        'DataBitCount': target['DataBitCount'],
                        'TagData': target['TagData']
                    }
                },
                'OpSpecParameter': opSpecParam,
            },
            'AccessReportSpec': {
                'AccessReportTrigger': 1 # report at end of access
            }
        }

        d = defer.Deferred()
        d.addCallback(self.send_ENABLE_ACCESSSPEC, accessSpecID)
        d.addErrback(self.panic, 'ADD_ACCESSSPEC failed')

        self.send_ADD_ACCESSSPEC(accessSpec, onCompletion=d)

    def startInventory (self, *args):
        """Add a ROSpec to the reader and enable it."""
        if self.state == LLRPClient.STATE_INVENTORYING:
            logger.warn('ignoring startInventory() while already inventorying')
            return None

        rospec = self.getROSpec()['ROSpec']

        logger.info('starting inventory')

        started = defer.Deferred()
        started.addCallback(self._setState_wrapper,
                LLRPClient.STATE_INVENTORYING)
        started.addErrback(self.panic, 'ENABLE_ROSPEC failed')

        if self.duration:
            task.deferLater(reactor, self.duration, self.stopPolitely, True)

        d = defer.Deferred()
        d.addCallback(self.send_ENABLE_ROSPEC, rospec, onCompletion=started)
        d.addErrback(self.panic, 'ADD_ROSPEC failed')

        self.send_ADD_ROSPEC(rospec, onCompletion=d)

    def getROSpec (self):
        if self.rospec:
            return self.rospec

        # create an ROSpec to define the reader's inventorying behavior
        self.rospec = LLRPROSpec(self, 1, duration_sec=self.duration,
                            report_every_n_tags=self.report_every_n_tags,
                            tx_power=self.tx_power, antennas=self.antennas,
                            tag_content_selector=self.tag_content_selector,
                            session=self.session,
                            tag_population=self.tag_population)
        logger.debug('ROSpec: %s', self.rospec)
        return self.rospec

    def stopPolitely (self, disconnect=False):
        """Delete all active ROSpecs.  Return a Deferred that will be called
           when the DELETE_ROSPEC_RESPONSE comes back."""
        logger.info('stopping politely')
        if disconnect:
            logger.info('will disconnect when stopped')
            self.disconnecting = True
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'DELETE_ACCESSSPEC': {
                'Ver': 1,
                'Type': 41,
                'ID': 0,
                'AccessSpecID': 0 # all AccessSpecs
            }}))
        self.setState(LLRPClient.STATE_SENT_DELETE_ACCESSSPEC)

        d = defer.Deferred()
        d.addCallback(self.stopAllROSpecs)
        d.addErrback(self.panic, 'DELETE_ACCESSSPEC failed')

        self._deferreds['DELETE_ACCESSSPEC_RESPONSE'].append(d)
        return d

    def stopAllROSpecs (self, *args):
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'DELETE_ROSPEC': {
                'Ver':  1,
                'Type': 21,
                'ID':   0,
                'ROSpecID': 0
            }}))
        self.setState(LLRPClient.STATE_SENT_DELETE_ROSPEC)

        d = defer.Deferred()
        d.addErrback(self.panic, 'DELETE_ROSPEC failed')

        self._deferreds['DELETE_ROSPEC_RESPONSE'].append(d)
        return d

    def pause (self, duration_seconds=0):
        """Pause an inventory operation for a set amount of time."""
        logger.info('pausing for %d seconds', duration_seconds)

        rospec = self.getROSpec()['ROSpec']

        self.sendLLRPMessage(LLRPMessage(msgdict={
            'DISABLE_ROSPEC': {
                'Ver':  1,
                'Type': 25,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }}))
        self.setState(LLRPClient.STATE_PAUSING)

        d = defer.Deferred()
        d.addCallback(self._setState_wrapper, LLRPClient.STATE_PAUSED)
        d.addErrback(self.complain, 'pause() failed')
        self._deferreds['DISABLE_ROSPEC_RESPONSE'].append(d)

        if duration_seconds > 0:
            startAgain = task.deferLater(reactor, duration_seconds, lambda: 0)
            startAgain.addCallback(self.resume)

        return d

    def resume (self):
        if self.state in (LLRPClient.STATE_CONNECTED,
                LLRPClient.STATE_DISCONNECTED):
            self.startInventory()
            return

        if self.state != LLRPClient.STATE_PAUSED:
            logger.debug('cannot resume() if not paused; ignoring')
            return None

        logger.info('resuming')

        rospec = self.getROSpec()['ROSpec']

        d = defer.Deferred()
        d.addCallback(self._setState_wrapper, LLRPClient.STATE_INVENTORYING)
        d.addErrback(self.panic, 'resume() failed')
        self.send_ENABLE_ROSPEC(None, rospec, onCompletion=d)

    def sendLLRPMessage (self, llrp_msg):
        assert isinstance(llrp_msg, LLRPMessage)
        assert llrp_msg.msgbytes, "LLRPMessage is empty"
        self.transport.write(llrp_msg.msgbytes)

class LLRPClientFactory (ClientFactory):
    def __init__ (self, onFinish=None, reconnect=False,
            **kwargs):
        self.onFinish = onFinish
        self.reconnect = reconnect
        self.reconnect_delay = 1.0 # seconds
        self.client_args = kwargs

        # callbacks to pass to connected clients
        # (map of LLRPClient.STATE_* -> [list of callbacks])
        self._state_callbacks = {}
        for _, st_num in LLRPClient.getStates():
            self._state_callbacks[st_num] = []

        # message callbacks to pass to connected clients
        self._message_callbacks = defaultdict(list)

        self.protocols = set()

    def startedConnecting(self, connector):
        logger.info('connecting...')

    def addStateCallback (self, state, cb):
        assert state in self._state_callbacks
        self._state_callbacks[state].append(cb)

    def addTagReportCallback (self, cb):
        self._message_callbacks['RO_ACCESS_REPORT'].append(cb)

    def buildProtocol(self, _):
        proto = LLRPClient(factory=self, **self.client_args)

        # register state-change callbacks with new client
        for state, cbs in self._state_callbacks.items():
            for cb in cbs:
                proto.addStateCallback(state, cb)

        # register message callbacks with new client
        for msg_type, cbs in self._message_callbacks.items():
            for cb in cbs:
                proto.addMessageCallback(msg_type, cb)

        return proto

    def clientConnectionLost(self, connector, reason):
        logger.info('lost connection: %s', reason.getErrorMessage())
        ClientFactory.clientConnectionLost(self, connector, reason)
        if self.reconnect:
            time.sleep(self.reconnect_delay)
            connector.connect()
        elif not self.protocols:
            if self.onFinish:
                self.onFinish.callback(None)

    def clientConnectionFailed(self, connector, reason):
        logger.info('connection failed: %s', reason.getErrorMessage())
        ClientFactory.clientConnectionFailed(self, connector, reason)
        if self.reconnect:
            time.sleep(self.reconnect_delay)
            connector.connect()
        elif not self.protocols:
            if self.onFinish:
                self.onFinish.callback(None)

    def resumeInventory (self):
        for proto in self.protocols:
            proto.resume()

    def pauseInventory (self, seconds=0):
        for proto in self.protocols:
            proto.pause(seconds)

    def politeShutdown (self):
        """Stop inventory on all connected readers."""
        protoDeferreds = []
        for proto in self.protocols:
            protoDeferreds.append(proto.stopPolitely(disconnect=True))
        return defer.DeferredList(protoDeferreds)

    def getProtocolStates (self):
        states = {'{}'.format(proto.peername[0]): \
            LLRPClient.getStateName(proto.state) for proto in self.protocols}
        logger.info('states: %s', states)
        return states
