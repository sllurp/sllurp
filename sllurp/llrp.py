from __future__ import print_function, unicode_literals
from collections import defaultdict
import logging
import pprint
import struct

import sys
import select

from socket import (AF_INET, SOCK_STREAM, SHUT_RDWR, socket,
                    timeout as socktimeout, SOL_SOCKET, SO_KEEPALIVE,
                    error as SocketError)
from threading import Thread, Event

from .llrp_proto import LLRPROSpec, LLRPError, Message_struct, \
    Message_Type2Name, Capability_Name2Type, AirProtocol, \
    llrp_data2xml, LLRPMessageDict, Modulation_Name2Type, \
    DEFAULT_MODULATION
from .llrp_errors import ReaderConfigurationError
from binascii import hexlify
from .util import BITMASK, natural_keys, iterkeys

LLRP_PORT = 5084

logger = logging.getLogger(__name__)


class LLRPMessage(object):
    hdr_fmt = '!HI'
    hdr_len = struct.calcsize(hdr_fmt)  # == 6 bytes
    full_hdr_fmt = hdr_fmt + 'I'
    full_hdr_len = struct.calcsize(full_hdr_fmt)  # == 10 bytes

    def __init__(self, msgdict=None, msgbytes=None):
        if not (msgdict or msgbytes):
            raise LLRPError('Provide either a message dict or a sequence'
                            ' of bytes.')
        self.proto = None
        self.peername = None
        self.msgdict = None
        self.msgbytes = None
        if msgdict:
            self.msgdict = LLRPMessageDict(msgdict)

            if not msgbytes:
                self.serialize()
        if msgbytes:
            self.msgbytes = msgbytes
            if not msgdict:
                self.deserialize()

    def serialize(self):
        if self.msgdict is None:
            raise LLRPError('No message dict to serialize.')
        msgdict_iter = iterkeys(self.msgdict)
        name = next(msgdict_iter)
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

    def deserialize(self):
        """Turns a sequence of bytes into a message dictionary."""
        if self.msgbytes is None:
            raise LLRPError('No message bytes to deserialize.')
        data = self.msgbytes
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
        except LLRPError:
            logger.exception('Problem with %s message format', name)
            return ''
        return ''

    def isSuccess(self):
        if not self.msgdict:
            return False
        msgName = self.getName()
        md = self.msgdict[msgName]

        try:
            if msgName == 'READER_EVENT_NOTIFICATION':
                ev = md['ReaderEventNotificationData']
                if 'ConnectionAttemptEvent' in ev:
                    return ev['ConnectionAttemptEvent']['Status'] == 'Success'
                elif 'AntennaEvent' in ev:
                    return ev['AntennaEvent']['EventType'] == 'Connected'
            elif 'LLRPStatus' in md:
                return md['LLRPStatus']['StatusCode'] == 'Success'
        except KeyError:
            logger.exception('failed to parse status from %s', msgName)
            return False

    def getName(self):
        if not self.msgdict:
            return None
        msgdict_iter = iterkeys(self.msgdict)
        return next(msgdict_iter)

    def __repr__(self):
        try:
            ret = llrp_data2xml(self.msgdict)
        except TypeError as te:
            logger.exception(te)
            ret = ''
        return ret


#class LLRPClient(LineReceiver):
class LLRPClient:
    STATE_DISCONNECTED = 1
    STATE_CONNECTING = 2
    STATE_CONNECTED = 3
    STATE_SENT_GET_CONFIG = 4
    STATE_SENT_SET_CONFIG = 5
    STATE_SENT_ADD_ROSPEC = 15
    STATE_SENT_ENABLE_ROSPEC = 16
    STATE_SENT_START_ROSPEC = 17
    STATE_INVENTORYING = 18
    STATE_SENT_DELETE_ROSPEC = 19
    STATE_SENT_DELETE_ACCESSSPEC = 20
    STATE_SENT_GET_CAPABILITIES = 21
    STATE_PAUSING = 22
    STATE_PAUSED = 23
    STATE_SENT_ENABLE_IMPINJ_EXTENSIONS = 24

    @classmethod
    def getStates(_):
        state_names = [st for st in dir(LLRPClient) if st.startswith('STATE_')]
        for state_name in state_names:
            state_num = getattr(LLRPClient, state_name)
            yield state_name, state_num

    @classmethod
    def getStateName(_, state):
        try:
            return [st_name for st_name, st_num in LLRPClient.getStates()
                    if st_num == state][0]
        except IndexError:
            raise LLRPError('unknown state {}'.format(state))

    def __init__(self, transport_tx_write=None,
                 factory=None, duration=None, report_every_n_tags=None,
                 antennas=(1,), tx_power=0, modulation=DEFAULT_MODULATION,
                 tari=0, start_inventory=True, reset_on_connect=True,
                 disconnect_when_done=True,
                 report_timeout_ms=0,
                 tag_content_selector={},
                 mode_identifier=None,
                 session=2, tag_population=4,
                 impinj_search_mode=None,
                 impinj_tag_content_selector=None):
        if transport_tx_write is None:
            raise LLRPError('Must provide a transport_tx_write')
        self.transport_tx_write = transport_tx_write

        self.factory = factory
        self.state = LLRPClient.STATE_DISCONNECTED

        self.report_every_n_tags = report_every_n_tags
        self.report_timeout_ms = report_timeout_ms
        self.capabilities = {}
        self.reader_mode = None
        if isinstance(tx_power, int):
            self.tx_power = {ant: tx_power for ant in antennas}
        elif isinstance(tx_power, dict):
            if set(antennas) != set(tx_power.keys()):
                raise LLRPError('Must specify tx_power for each antenna')
            self.tx_power = tx_power.copy()
        else:
            raise LLRPError('tx_power must be dict or int')
        self.modulation = modulation
        self.tari = tari
        self.session = session
        self.tag_population = tag_population
        self.mode_identifier = mode_identifier
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
        if (impinj_search_mode is not None or
                impinj_tag_content_selector is not None):
            logger.info('Enabling Impinj extensions')
        self.impinj_search_mode = impinj_search_mode
        self.impinj_tag_content_selector = impinj_tag_content_selector

        logger.info('using antennas: %s', self.antennas)
        logger.info('transmit power: %s', self.tx_power)

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

        self.rospec = None

        self.last_msg_id = 0

    def addStateCallback(self, state, cb):
        """Add a callback to run upon a state transition.

        When an LLRPClient `proto` enters `state`, `cb(proto)` will be called.

        Args:
            state: A state from LLRPClient.STATE_*.
            cb: A callable that takes an LLRPClient argument.
        """
        self._state_callbacks[state].append(cb)

    def addMessageCallback(self, msg_type, cb):
        self._message_callbacks[msg_type].append(cb)

    def addTagReportCallback(self, cb):
        self._message_callbacks['RO_ACCESS_REPORT'].append(cb)

    def setState(self, newstate, onComplete=None):
        assert newstate is not None
        logger.debug('state change: %s -> %s',
                     LLRPClient.getStateName(self.state),
                     LLRPClient.getStateName(newstate))

        self.state = newstate

        for fn in self._state_callbacks[newstate]:
            fn(self)

    def parseCapabilities(self, capdict):
        """Parse a capabilities dictionary and adjust instance settings

           Sets the following instance variables:
           - self.antennas (list of antenna numbers, e.g., [1] or [1, 2])
           - self.tx_power_table (list of dBm values)
           - self.reader_mode (dictionary of mode settings, e.g., Tari)

           Raises ReaderConfigurationError if requested settings are not within
           reader's capabilities.
        """
        # check requested antenna set
        gdc = capdict['GeneralDeviceCapabilities']
        max_ant = gdc['MaxNumberOfAntennaSupported']
        if max(self.antennas) > max_ant:
            reqd = ','.join(map(str, self.antennas))
            avail = ','.join(map(str, range(1, max_ant + 1)))
            errmsg = ('Invalid antenna set specified: requested={},'
                      ' available={}; ignoring invalid antennas'.format(
                          reqd, avail))
            raise ReaderConfigurationError(errmsg)
        logger.debug('set antennas: %s', self.antennas)

        # parse available transmit power entries, set self.tx_power
        bandcap = capdict['RegulatoryCapabilities']['UHFBandCapabilities']
        self.tx_power_table = self.parsePowerTable(bandcap)
        logger.debug('tx_power_table: %s', self.tx_power_table)
        self.setTxPower(self.tx_power)

        # fill UHFC1G2RFModeTable & check requested modulation & Tari
        regcap = capdict['RegulatoryCapabilities']
        modes = regcap['UHFBandCapabilities']['UHFRFModeTable']
        mode_list = [modes[k] for k in sorted(modes.keys(), key=natural_keys)]

        # select a mode by matching available modes to requested parameters:
        # favor mode_identifier over modulation
        if self.mode_identifier is not None:
            logger.debug('Setting mode from mode_identifier=%s',
                         self.mode_identifier)
            try:
                mode = [mo for mo in mode_list
                        if mo['ModeIdentifier'] == self.mode_identifier][0]
                self.reader_mode = mode
            except IndexError:
                valid_modes = sorted(mo['ModeIdentifier'] for mo in mode_list)
                errstr = ('Invalid mode_identifier; valid mode_identifiers'
                          ' are {}'.format(valid_modes))
                raise ReaderConfigurationError(errstr)

        elif self.modulation is not None:
            logger.debug('Setting mode from modulation=%s',
                         self.modulation)
            try:
                mo = [mo for mo in mode_list
                      if mo['Mod'] == Modulation_Name2Type[self.modulation]][0]
                self.reader_mode = mo
            except IndexError:
                raise ReaderConfigurationError('Invalid modulation')

        if self.tari:
            if not self.reader_mode:
                errstr = 'Cannot set Tari without choosing a reader mode'
                raise ReaderConfigurationError(errstr)
            if self.tari > self.reader_mode['MaxTari']:
                errstr = ('Requested Tari is greater than MaxTari for selected'
                          'mode {}'.format(self.reader_mode))
                raise ReaderConfigurationError(errstr)

        logger.info('using reader mode: %s', self.reader_mode)

    def processDeferreds(self, msgName, isSuccess):
        deferreds = self._deferreds[msgName]
        if not deferreds:
            return
        logger.debug('running %d Deferreds for %s; '
                     'isSuccess=%s', len(deferreds), msgName, isSuccess)
        for deferred_cb in deferreds:
            deferred_cb(self.state, isSuccess)
        del self._deferreds[msgName]

    def handleMessage(self, lmsg):
        """Implements the LLRP client state machine."""
        logger.debug('LLRPMessage received in state %s: %s', self.state, lmsg)
        msgName = lmsg.getName()
        lmsg.proto = self
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

        if msgName == 'READER_EVENT_NOTIFICATION' and \
                self.state >= LLRPClient.STATE_CONNECTED:
            logger.debug('Got reader event notification')
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
                          LLRPClient.STATE_CONNECTING,
                          LLRPClient.STATE_CONNECTED):
            if msgName != 'READER_EVENT_NOTIFICATION':
                logger.error('unexpected message %s while connecting', msgName)
                return

            if not lmsg.isSuccess():
                rend = lmsg.msgdict[msgName]['ReaderEventNotificationData']
                try:
                    status = rend['ConnectionAttemptEvent']['Status']
                except KeyError:
                    status = '(unknown status)'
                logger.fatal('Could not start session on reader: %s', status)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

            # a Deferred to call when we get GET_READER_CAPABILITIES_RESPONSE
            def get_reader_capabilities_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPClient.STATE_CONNECTED)
                else:
                    self.panic(None, 'GET_READER_CAPABILITIES failed')

            if (self.impinj_search_mode is not None or
                self.impinj_tag_content_selector is not None):

                def enable_impinj_ext_cb(state, is_success, *args):
                    if is_success:
                        self.send_GET_READER_CAPABILITIES(
                            self, onCompletion=get_reader_capabilities_cb)
                    else:
                        self.panic(None, 'ENABLE_IMPINJ_EXTENSIONS failed')

                self.send_ENABLE_IMPINJ_EXTENSIONS(
                    onCompletion=enable_impinj_ext_cb)
            else:
                self.send_GET_READER_CAPABILITIES(
                    self, onCompletion=get_reader_capabilities_cb)

        elif self.state == LLRPClient.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS:
            logger.debug(lmsg)
            if msgName != 'CUSTOM_MESSAGE':
                logger.error('unexpected response %s while enabling Impinj'
                             'extensions', msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s enabling Impinj extensions: %s',
                             status, err)
                return
            logger.debug('Successfully enabled Impinj extensions')

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state SENT_GET_CAPABILITIES, expect GET_CAPABILITIES_RESPONSE;
        # respond to this message by advancing to state CONNECTED.
        elif self.state == LLRPClient.STATE_SENT_GET_CAPABILITIES:
            if msgName != 'GET_READER_CAPABILITIES_RESPONSE':
                logger.error('unexpected response %s getting capabilities',
                             msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s getting capabilities: %s', status, err)
                return

            self.capabilities = \
                lmsg.msgdict['GET_READER_CAPABILITIES_RESPONSE']
            logger.debug('Capabilities: %s', pprint.pformat(self.capabilities))
            try:
                self.parseCapabilities(self.capabilities)
            except LLRPError as err:
                logger.exception('Capabilities mismatch')
                raise err

            self.processDeferreds(msgName, lmsg.isSuccess())

            def get_reader_config_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPClient.STATE_SENT_GET_CONFIG)
                else:
                    self.panic(None, 'GET_READER_CONFIG failed')
            self.send_GET_READER_CONFIG(onCompletion=get_reader_config_cb)

        elif self.state == LLRPClient.STATE_SENT_GET_CONFIG:
            if msgName not in ('GET_READER_CONFIG_RESPONSE',
                               'DELETE_ACCESSSPEC_RESPONSE',
                               'DELETE_ROSPEC_RESPONSE'):
                logger.error('unexpected response %s getting config',
                             msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s getting reader config: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

            def set_reader_config_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPClient.STATE_SENT_SET_CONFIG)
                else:
                    self.panic(None, 'SET_READER_CONFIG failed')

            self.send_ENABLE_EVENTS_AND_REPORTS()
            self.send_SET_READER_CONFIG(onCompletion=set_reader_config_cb)

        elif self.state == LLRPClient.STATE_SENT_SET_CONFIG:
            if msgName not in ('SET_READER_CONFIG_RESPONSE',
                               'GET_READER_CONFIG_RESPONSE',
                               'DELETE_ACCESSSPEC_RESPONSE'):
                logger.error('unexpected response %s setting config',
                             msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s setting reader config: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

            if self.reset_on_connect:
                def on_politely_stopped_cb(state, is_success, *args):
                    if is_success:
                        self.setState(LLRPClient.STATE_CONNECTED)
                        if self.start_inventory:
                            self.startInventory()

                self.stopPolitely(onCompletion=on_politely_stopped_cb)
            elif self.start_inventory:
                self.startInventory()

        # in state SENT_ADD_ROSPEC, expect only ADD_ROSPEC_RESPONSE; respond to
        # favorable ADD_ROSPEC_RESPONSE by enabling the added ROSpec and
        # advancing to state SENT_ENABLE_ROSPEC.
        elif self.state == LLRPClient.STATE_SENT_ADD_ROSPEC:
            if msgName != 'ADD_ROSPEC_RESPONSE':
                logger.error('unexpected response %s when adding ROSpec',
                             msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s adding ROSpec: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state SENT_ENABLE_ROSPEC, expect only ENABLE_ROSPEC_RESPONSE;
        # respond to favorable ENABLE_ROSPEC_RESPONSE by starting the enabled
        # ROSpec and advancing to state SENT_START_ROSPEC.
        elif self.state == LLRPClient.STATE_SENT_ENABLE_ROSPEC:
            if msgName != 'ENABLE_ROSPEC_RESPONSE':
                logger.error('unexpected response %s when enabling ROSpec',
                             msgName)
                return

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s enabling ROSpec: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state PAUSING, we have sent a DISABLE_ROSPEC, so expect only
        # DISABLE_ROSPEC_RESPONSE.  advance to state PAUSED.
        elif self.state == LLRPClient.STATE_PAUSING:
            if msgName != 'DISABLE_ROSPEC_RESPONSE':
                logger.error('unexpected response %s '
                             ' when disabling ROSpec', msgName)

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.error('DISABLE_ROSPEC failed with status %s: %s',
                             status, err)
                logger.warn('Error %s disabling ROSpec: %s', status, err)

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state SENT_START_ROSPEC, expect only START_ROSPEC_RESPONSE;
        # respond to favorable START_ROSPEC_RESPONSE by advancing to state
        # INVENTORYING.
        elif self.state == LLRPClient.STATE_SENT_START_ROSPEC:
            if msgName == 'RO_ACCESS_REPORT':
                return
            if msgName == 'READER_EVENT_NOTIFICATION':
                return
            if msgName != 'START_ROSPEC_RESPONSE':
                logger.error('unexpected response %s when starting ROSpec',
                             msgName)

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.error('START_ROSPEC failed with status %s: %s',
                             status, err)
                logger.fatal('Error %s starting ROSpec: %s', status, err)
                return

            self.processDeferreds(msgName, lmsg.isSuccess())

        elif self.state == LLRPClient.STATE_INVENTORYING:
            if msgName not in ('RO_ACCESS_REPORT',
                               'READER_EVENT_NOTIFICATION',
                               'ADD_ACCESSSPEC_RESPONSE',
                               'ENABLE_ACCESSSPEC_RESPONSE',
                               'DISABLE_ACCESSSPEC_RESPONSE',
                               'DELETE_ACCESSSPEC_RESPONSE'):
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

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.error('DELETE_ROSPEC failed with status %s: %s',
                             status, err)

            self.processDeferreds(msgName, lmsg.isSuccess())


        else:
            logger.warn('message %s received in unknown state!', msgName)

        if self._deferreds[msgName]:
            logger.error('there should NOT be Deferreds left for %s,'
                         ' but there are!', msgName)

    def rawDataReceived(self, data):
        logger.debug('got %d bytes from reader: %s', len(data),
                     hexlify(data))

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
                logger.warning('Too few bytes (%d) to unpack message header',
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
                except LLRPError:
                    logger.exception('Failed to decode LLRPMessage; '
                                     'will not decode %d remaining bytes',
                                     len(data))
                    break

    def panic(self, failure, *args):
        logger.error('panic(): %s', args)
        #logger.error(failure.getErrorMessage())
        #logger.error(failure.getTraceback())
        return failure

    def complain(self, failure, *args):
        logger.warn('complain(): %s', args)

    def send_KEEPALIVE_ACK(self):
        self.sendMessage({
            'KEEPALIVE_ACK': {
                'Ver':  1,
                'Type': 72,
                'ID':   0,
            }})

    def send_ENABLE_IMPINJ_EXTENSIONS(self, onCompletion):
        self.sendMessage({
            'CUSTOM_MESSAGE': {
                'Ver': 1,
                'Type': 1023,
                'ID': 0,
                'VendorID': 25882,
                'Subtype': 21,
                # skip payload
            }})
        self.setState(LLRPClient.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS)
        self._deferreds['CUSTOM_MESSAGE'].append(onCompletion)

    def send_GET_READER_CAPABILITIES(self, _, onCompletion):
        self.sendMessage({
            'GET_READER_CAPABILITIES': {
                'Ver':  1,
                'Type': 1,
                'ID':   0,
                'RequestedData': Capability_Name2Type['All']
            }})
        self.setState(LLRPClient.STATE_SENT_GET_CAPABILITIES)
        self._deferreds['GET_READER_CAPABILITIES_RESPONSE'].append(
            onCompletion)

    def send_GET_READER_CONFIG(self, onCompletion):
        self.sendMessage({
            'GET_READER_CONFIG': {
                'Ver':  1,
                'Type': 2,
                'ID':   0,
                'RequestedData': Capability_Name2Type['All']
            }})
        self.setState(LLRPClient.STATE_SENT_GET_CONFIG)
        self._deferreds['GET_READER_CONFIG_RESPONSE'].append(
            onCompletion)

    def send_ENABLE_EVENTS_AND_REPORTS(self):
        self.sendMessage({
            'ENABLE_EVENTS_AND_REPORTS': {
                'Ver': 1,
                'Type': 64,
                'ID': 0,
            }})

    def send_SET_READER_CONFIG(self, onCompletion):
        self.sendMessage({
            'SET_READER_CONFIG': {
                'Ver':  1,
                'Type': 3,
                'ID':   0,
                'ResetToFactoryDefaults': False,
                'ReaderEventNotificationSpec': {
                    'EventNotificationState': {
                            'HoppingEvent': False,
                            'GPIEvent': False,
                            'ROSpecEvent': False,
                            'ReportBufferFillWarning': False,
                            'ReaderExceptionEvent': False,
                            'RFSurveyEvent': False,
                            'AISpecEvent': False,
                            'AISpecEventWithSingulation': False,
                            'AntennaEvent': False,
                            ## Next one will only be available
                            ## with llrp v2 (spec 1_1)
                            #'SpecLoopEvent': True,
                    },
                    'EventNotificationState': {
                            'HoppingEvent': True,
                            'GPIEvent': True,
                            'ROSpecEvent': True,
                            'ReportBufferFillWarning': True,
                            'ReaderExceptionEvent': True,
                            'RFSurveyEvent': True,
                            'AISpecEvent': True,
                            'AISpecEventWithSingulation': True,
                            'AntennaEvent': True,
                            ## Next one will only be available
                            ## with llrp v2 (spec 1_1)
                            #'SpecLoopEvent': True,
                    }
                }
            }})
        self.setState(LLRPClient.STATE_SENT_SET_CONFIG)
        self._deferreds['SET_READER_CONFIG_RESPONSE'].append(
            onCompletion)

    def send_ADD_ROSPEC(self, rospec, onCompletion):
        logger.debug('about to send_ADD_ROSPEC')
        try:
            self.sendMessage({
                'ADD_ROSPEC': {
                    'Ver':  1,
                    'Type': 20,
                    'ID':   0,
                    'ROSpecID': rospec['ROSpecID'],
                    'ROSpec': rospec,
            }})
        except Exception as ex:
            logger.exception(ex)
        logger.debug('sent ADD_ROSPEC')
        self.setState(LLRPClient.STATE_SENT_ADD_ROSPEC)
        self._deferreds['ADD_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ROSPEC(self, _, rospec, onCompletion):
        self.sendMessage({
            'ENABLE_ROSPEC': {
                'Ver':  1,
                'Type': 24,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPClient.STATE_SENT_ENABLE_ROSPEC)
        self._deferreds['ENABLE_ROSPEC_RESPONSE'].append(onCompletion)

    def send_START_ROSPEC(self, _, rospec, onCompletion):
        self.sendMessage({
            'START_ROSPEC': {
                'Ver':  1,
                'Type': 22,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPClient.STATE_SENT_START_ROSPEC)
        self._deferreds['START_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ADD_ACCESSSPEC(self, accessSpec, onCompletion):
        self.sendMessage({
            'ADD_ACCESSSPEC': {
                'Ver':  1,
                'Type': 40,
                'ID':   0,
                'AccessSpec': accessSpec,
            }})
        self._deferreds['ADD_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_DISABLE_ACCESSSPEC(self, accessSpecID=1, onCompletion=None):
        self.sendMessage({
            'DISABLE_ACCESSSPEC': {
                'Ver':  1,
                'Type': 43,
                'ID':   0,
                'AccessSpecID': accessSpecID,
            }})

        if onCompletion:
            self._deferreds['DISABLE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ACCESSSPEC(self, _, accessSpecID, onCompletion=None):
        self.sendMessage({
            'ENABLE_ACCESSSPEC': {
                'Ver':  1,
                'Type': 42,
                'ID':   0,
                'AccessSpecID': accessSpecID,
            }})

        if onCompletion:
            self._deferreds['ENABLE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_DELETE_ACCESSSPEC(self, accessSpecID=1,
                               onCompletion=None):
        # logger.info('Deleting current accessSpec.')
        self.sendMessage({
            'DELETE_ACCESSSPEC': {
                'Ver': 1,
                'Type': 41,
                'ID': 0,
                'AccessSpecID': accessSpecID  # ONE AccessSpec
            }})

        if onCompletion:
            self._deferreds['DELETE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def startAccess(self, readWords=None, writeWords=None, target=None,
                    accessStopParam=None, accessSpecID=1, param=None,
                    *args):
        m = Message_struct['AccessSpec']
        if not target:
            target = {
                'MB': 0,
                'Pointer': 0,
                'MaskBitCount': 0,
                'TagMask': b'',
                'DataBitCount': 0,
                'TagData': b''
            }

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
            if 'AccessPassword' in readWords:
                opSpecParam['AccessPassword'] = readWords['AccessPassword']

        elif writeWords:
            opSpecParam['MB'] = writeWords['MB']
            opSpecParam['WordPtr'] = writeWords['WordPtr']
            opSpecParam['WriteDataWordCount'] = \
                writeWords['WriteDataWordCount']
            opSpecParam['WriteData'] = writeWords['WriteData']
            if 'OpSpecID' in writeWords:
                opSpecParam['OpSpecID'] = writeWords['OpSpecID']
            if 'AccessPassword' in writeWords:
                opSpecParam['AccessPassword'] = writeWords['AccessPassword']

        elif param:
            # special parameters like C1G2Lock
            opSpecParam = param

        else:
            raise LLRPError('startAccess requires readWords or writeWords.')

        if accessStopParam is None:
            accessStopParam = {}
            accessStopParam['AccessSpecStopTriggerType'] = 0
            accessStopParam['OperationCountValue'] = 0

        accessSpec = {
            'Type': m['type'],
            'AccessSpecID': accessSpecID,
            'AntennaID': 0,  # all antennas
            'ProtocolID': AirProtocol['EPCGlobalClass1Gen2'],
            'C': False,  # disabled by default
            'ROSpecID': 0,  # all ROSpecs
            'AccessSpecStopTrigger': accessStopParam,
            'AccessCommand': {
                'TagSpecParameter': {
                    'C1G2TargetTag': {  # XXX correct values?
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
                'AccessReportTrigger': 1  # report at end of access
            }
        }
        logger.debug('AccessSpec: %s', accessSpec)

        def add_accessspec_cb(state, is_success, *args):
            if is_success:
                self.send_ENABLE_ACCESSSPEC(state, accessSpecID)
            else:
                self.panic(None, 'ADD_ACCESSSPEC failed')

        self.send_ADD_ACCESSSPEC(accessSpec,
                                 onCompletion=add_accessspec_cb)

    def nextAccess(self, readSpecPar, writeSpecPar, stopSpecPar,
                   accessSpecID=1):
        def start_next_accessspec_cb(state, is_success, *args):
            self.startAccess(readWords=readSpecPar,
                             writeWords=writeSpecPar,
                             accessStopParam=stopSpecPar,
                             accessSpecID=accessSpecID)

        def disable_accessspec_cb(state, is_success, *args):
            self.send_DELETE_ACCESSSPEC(accessSpecID,
                                        onCompletion=start_next_accessspec_cb)
            #if not is_success:
            #    self.panic(None, 'DISABLE_ACCESSSPEC failed')

        self.send_DISABLE_ACCESSSPEC(accessSpecID,
                                     onCompletion=disable_accessspec_cb)

    def startInventory(self, proto=None, force_regen_rospec=False):
        """Add a ROSpec to the reader and enable it."""
        if self.state == LLRPClient.STATE_INVENTORYING:
            logger.warn('ignoring startInventory() while already inventorying')
            return None

        rospec = self.getROSpec(force_new=force_regen_rospec)['ROSpec']

        logger.info('starting inventory')

        # upside-down chain of callbacks: add, enable, start ROSpec
        # started_rospec = defer.Deferred()
        # started_rospec.addCallback(self._setState_wrapper,
        #                            LLRPClient.STATE_INVENTORYING)
        # started_rospec.addErrback(self.panic, 'START_ROSPEC failed')
        # logger.debug('made started_rospec')

        def enabled_rospec_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPClient.STATE_INVENTORYING)
            else:
                self.panic(None, 'ENABLE_ROSPEC failed')

        logger.debug('made enabled_rospec')

        def send_added_rospec_cb(state, is_success, *args):
            if is_success:
                self.send_ENABLE_ROSPEC(state, rospec,
                                        onCompletion=enabled_rospec_cb)
            else:
                self.panic(None, 'ADD_ROSPEC failed')

        logger.debug('made added_rospec')

        self.send_ADD_ROSPEC(rospec, onCompletion=send_added_rospec_cb)

    def getROSpec(self, force_new=False):
        if self.rospec and not force_new:
            return self.rospec

        # create an ROSpec to define the reader's inventorying behavior
        rospec_kwargs = dict(
            duration_sec=self.duration,
            report_every_n_tags=self.report_every_n_tags,
            report_timeout_ms=self.report_timeout_ms,
            tx_power=self.tx_power,
            antennas=self.antennas,
            tag_content_selector=self.tag_content_selector,
            session=self.session,
            tari=self.tari,
            tag_population=self.tag_population
        )
        logger.info('Impinj search mode? %s', self.impinj_search_mode)
        if self.impinj_search_mode is not None:
            rospec_kwargs['impinj_search_mode'] = self.impinj_search_mode
        if self.impinj_tag_content_selector is not None:
            rospec_kwargs['impinj_tag_content_selector'] = \
                self.impinj_tag_content_selector

        self.rospec = LLRPROSpec(self.reader_mode, 1, **rospec_kwargs)
        logger.debug('ROSpec: %s', self.rospec)
        return self.rospec

    def stopPolitely(self, onCompletion=None):
        """Delete all active ROSpecs.  Return a Deferred that will be called
           when the DELETE_ROSPEC_RESPONSE comes back."""
        logger.info('stopping politely')
        self.sendMessage({
            'DELETE_ACCESSSPEC': {
                'Ver': 1,
                'Type': 41,
                'ID': 0,
                'AccessSpecID': 0  # all AccessSpecs
            }})
        self.setState(LLRPClient.STATE_SENT_DELETE_ACCESSSPEC)

        def send_delete_accessspec_cb(state, is_success, *args):
            if is_success:
                self.stopAllROSpecs(onCompletion, state)
            else:
                self.panic(None, 'DELETE_ACCESSSPEC failed')
                if onCompletion:
                    onCompletion(state, is_success, *args)

        self._deferreds['DELETE_ACCESSSPEC_RESPONSE'].append(
            send_delete_accessspec_cb)

    def stopAllROSpecs(self, onCompletion=None, *args):
        self.sendMessage({
            'DELETE_ROSPEC': {
                'Ver':  1,
                'Type': 21,
                'ID':   0,
                'ROSpecID': 0
            }})
        self.setState(LLRPClient.STATE_SENT_DELETE_ROSPEC)

        def stop_all_rospecs_cb(state, is_success, *args):
            if not is_success:
                self.panic(None, 'DELETE_ROSPEC failed')
            if onCompletion:
                onCompletion(state, is_success, *args)

        self._deferreds['DELETE_ROSPEC_RESPONSE'].append(stop_all_rospecs_cb)
        return None

    @staticmethod
    def parsePowerTable(uhfbandcap):
        """Parse the transmit power table

        @param uhfbandcap: Capability dictionary from
            self.capabilities['RegulatoryCapabilities']['UHFBandCapabilities']
        @return: a list of [0, dBm value, dBm value, ...]

        >>> LLRPClient.parsePowerTable({'TransmitPowerLevelTableEntry1': \
            {'Index': 1, 'TransmitPowerValue': 3225}})
        [0, 32.25]
        >>> LLRPClient.parsePowerTable({})
        [0]
        """
        bandtbl = {k: v for k, v in uhfbandcap.items()
                   if k.startswith('TransmitPowerLevelTableEntry')}
        tx_power_table = [0] * (len(bandtbl) + 1)
        for k, v in bandtbl.items():
            idx = v['Index']
            tx_power_table[idx] = int(v['TransmitPowerValue']) / 100.0

        return tx_power_table

    def get_tx_power(self, tx_power):
        """Validates tx_power against self.tx_power_table

        @param tx_power: index into the self.tx_power_table list; if tx_power
            is 0 then the max power from self.tx_power_table
        @return: a dict {antenna: (tx_power_index, power_dbm)} from
            self.tx_power_table
        @raise: LLRPError if the requested index is out of range
        """
        if not self.tx_power_table:
            logger.warn('get_tx_power(): tx_power_table is empty!')
            return {}

        logger.debug('requested tx_power: %s', tx_power)
        min_power = self.tx_power_table.index(min(self.tx_power_table))
        max_power = self.tx_power_table.index(max(self.tx_power_table))

        ret = {}
        for antid, tx_power in tx_power.items():
            if tx_power == 0:
                # tx_power = 0 means max power
                max_power_dbm = max(self.tx_power_table)
                tx_power = self.tx_power_table.index(max_power_dbm)
                ret[antid] = (tx_power, max_power_dbm)

            try:
                power_dbm = self.tx_power_table[tx_power]
                ret[antid] = (tx_power, power_dbm)
            except IndexError:
                raise LLRPError('Invalid tx_power for antenna {}: '
                                'requested={}, min_available={}, '
                                'max_available={}'.format(
                                    antid, self.tx_power, min_power,
                                    max_power))
        return ret

    def setTxPower(self, tx_power):
        """Set the transmission power for one or more antennas.

        @param tx_power: index into self.tx_power_table
        """
        tx_pow_validated = self.get_tx_power(tx_power)
        logger.debug('tx_pow_validated: %s', tx_pow_validated)
        needs_update = False
        for ant, (tx_pow_idx, tx_pow_dbm) in tx_pow_validated.items():
            if self.tx_power[ant] != tx_pow_idx:
                self.tx_power[ant] = tx_pow_idx
                needs_update = True

            logger.debug('tx_power for antenna %s: %s (%s dBm)', ant,
                         tx_pow_idx, tx_pow_dbm)

        if needs_update and self.state == LLRPClient.STATE_INVENTORYING:
            logger.debug('changing tx power; will stop politely, then resume')
            def on_politely_stopped_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPClient.STATE_CONNECTED)
                    self.startInventory(force_regen_rospec=True)
            self.stopPolitely(onCompletion=on_politely_stopped_cb)

    def pause(self, duration_seconds=0, force=False, force_regen_rospec=False):
        """Pause an inventory operation for a set amount of time."""
        logger.debug('pause(%s)', duration_seconds)
        # Temporary error until fixed.
        if duration_seconds > 0:
            raise ReaderConfigurationError('"duration_seconds > 0" is not yet'
                                           'implemented for "pause".')
        if self.state != LLRPClient.STATE_INVENTORYING:
            if not force:
                logger.info('ignoring pause(); not inventorying (state==%s)',
                            self.getStateName(self.state))
                return None
            else:
                logger.info('forcing pause()')

        if duration_seconds:
            logger.info('pausing for %s seconds', duration_seconds)

        rospec = self.getROSpec(force_new=force_regen_rospec)['ROSpec']

        self.sendMessage({
            'DISABLE_ROSPEC': {
                'Ver':  1,
                'Type': 25,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPClient.STATE_PAUSING)

        def disable_rospec_pause_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPClient.STATE_PAUSED)
            else:
                self.complain(None, 'pause() failed')

        self._deferreds['DISABLE_ROSPEC_RESPONSE'].append(disable_rospec_pause_cb)

        # TODO @fviard To be fixed!!
        if duration_seconds > 0:
            logger.warning("TO BE FIXED!!")
            # startAgain = task.deferLater(reactor, duration_seconds,
            #                             lambda: None)
            # startAgain.addCallback(lambda _: self.resume())

        return disable_rospec_pause_cb

    def resume(self, force_regen_rospec=False):
        logger.debug('resuming, force_regen_rospec=%s', force_regen_rospec)

        if force_regen_rospec:
            self.rospec = self.getROSpec(force_new=True)

        if self.state in (LLRPClient.STATE_CONNECTED,
                          LLRPClient.STATE_DISCONNECTED):
            logger.debug('will startInventory()')
            self.startInventory()
            return

        if self.state != LLRPClient.STATE_PAUSED:
            logger.debug('cannot resume() if not paused (state=%s); ignoring',
                         self.getStateName(self.state))
            return None

        logger.info('resuming')

        def enable_rospec_resume_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPClient.STATE_INVENTORYING)
            else:
                self.complain(None, 'resume() failed')

        self.send_ENABLE_ROSPEC(None, self.rospec['ROSpec'],
                                onCompletion=enable_rospec_resume_cb)

    def sendMessage(self, msg_dict):
        """Serialize and send a dict LLRP Message

        Note: IDs should be modified in original msg_dict as it is a reference.
        That should be ok.
        """
        sent_ids = []
        for name in msg_dict:
            self.last_msg_id += 1
            msg_dict[name]['ID'] = self.last_msg_id
            sent_ids.append((name, self.last_msg_id))
        llrp_msg = LLRPMessage(msgdict=msg_dict)

        assert llrp_msg.msgbytes, "LLRPMessage is empty"
        self.transport_tx_write(llrp_msg.msgbytes)

        return sent_ids


class LLRPReaderConfig:
    def __init__(self, config_dict=None):

        self.duration = None
        self.tari = 0
        self.session = 2
        self.mode_identifier = None
        self.tag_population = 4
        self.report_every_n_tags = None
        self.report_timeout_ms = 0
        self.antennas = [1]
        self.tx_power = 0
        self.modulation = DEFAULT_MODULATION
        self.disconnect_when_done = self.duration and self.duration > 0
        self.tag_content_selector = {
            'EnableROSpecID': False,
            'EnableSpecIndex': False,
            'EnableInventoryParameterSpecID': False,
            'EnableAntennaID': False,
            'EnableChannelIndex': True,
            'EnablePeakRSSI': False,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': False
        }

        self.reconnect = False
        self.start_inventory = True
        self.reset_on_connect = True

        ## Extensions specific
        self.impinj_search_mode = None
        self.impinj_reports = False
        self.impinj_tag_content_selector = None

        ## If impinj extension, would be like:
        #self.impinj_tag_content_selector = {
        #    'EnableRFPhaseAngle': True,
        #    'EnablePeakRSSI': False,
        #    'EnableRFDopplerFrequency': False
        #}


        # callbacks
        self.on_finish_callback = None
        self.on_tag_report_callback  = None


        if config_dict:
            self.update_config(config_dict)

    def update_config(self, config_dict):
        for key, value in config_dict.items():
            if hasattr(self, key):
                setattr(self, key, value)


class LLRPReaderClient:
    DEFAULT_PORT = 5084

    def __init__(self, host, port=None, config=None, timeout=5.0):
        if port is None:
            port = self.DEFAULT_PORT
        self._port = port
        self._host = host

        self._socket = None
        self._socket_thread = None
        # Needed?
        self.disconnect_requested = Event()
        self._stop_main_loop = Event()

        # for partial data transfers
        self.expectingRemainingBytes = 0
        self.partialData = ''

        if config:
            self.config = config
        else:
            self.config = LLRPReaderConfig()

        self.llrp = self.get_new_llrp_client()


    def get_peername(self):
        return (self._host, self._port)

    def get_new_llrp_client(self):
        reader_config = self.config
        llrp = LLRPClient(transport_tx_write=self.send_data,
                          duration=reader_config.duration,
                          report_every_n_tags=reader_config.report_every_n_tags,
                          antennas=reader_config.antennas,
                          tx_power=reader_config.tx_power,
                          modulation=reader_config.modulation,
                          tari=reader_config.tari,
                          start_inventory=reader_config.start_inventory,
                          reset_on_connect=reader_config.reset_on_connect,
                          disconnect_when_done=reader_config.disconnect_when_done,
                          report_timeout_ms=reader_config.report_timeout_ms,
                          tag_content_selector=reader_config.tag_content_selector,
                          mode_identifier=reader_config.mode_identifier,
                          session=reader_config.session,
                          tag_population=reader_config.tag_population,
                          impinj_search_mode=reader_config.impinj_search_mode,
                          impinj_tag_content_selector=reader_config.impinj_tag_content_selector)

        if reader_config.on_tag_report_callback:
            llrp.addTagReportCallback(reader_config.on_tag_report_callback)

        return llrp

    def _connect_socket(self):
        if self._socket:
            raise ReaderConfigurationError('Already connected')
        try:
            self._socket = socket(AF_INET, SOCK_STREAM)
            self._socket.connect((self._host, self._port))
            # Sllurp original timeout is 3s
            self._socket.settimeout(5.0)
            self._socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

        except:
            self._socket = None
            raise
        logger.info('connected to %s (:%s)', self._host, self._port)
        return True

    def connect(self, start_main_loop=True):
        if self._socket_thread:
            raise ReaderConfigurationError('Already connected')
        self.disconnect_requested.clear()

        self._connect_socket()

        if not start_main_loop:
            return

        self._stop_main_loop.clear()
        # then create thread that wait on read for this reader
        self._socket_thread = Thread(target=self.main_loop)
        self._socket_thread.start()

    def disconnect(self):
        """Clean the reader before disconnecting"""
        if not self._socket_thread and not self._socket:
            logger.warning('Reader not connected. Disconnect is not needed.')

        self.disconnect_requested.set()

        if not self._socket_thread:
            # No polite stop as there would be no reply, just perfom cleanup
            self.hard_disconnect()
            self._execute_finish_callback()
            return

        def on_politely_stopped_cb(state, is_success, *args):
            if is_success:
                self.llrp.setState(LLRPClient.STATE_DISCONNECTED)
            logger.info('disconnecting')
            self.hard_disconnect()
            self._execute_finish_callback()
        logger.info('stopPolitely will disconnect when stopped')
        self.llrp.stopPolitely(onCompletion=on_politely_stopped_cb)

    def _execute_finish_callback(self):
        try:
            if self.config.on_finish_callback:
                self.config.on_finish_callback()
        except:
            logger.exception("Error during user onFinish callback. Continuing...")

    def hard_disconnect(self):
        """Stop the recv worker, and close sockets"""
        self._stop_main_loop.set()
        # stop listening thread.
        if self._socket:
            try:
                self._socket.shutdown(SHUT_RDWR)
            except:
                pass
            self._socket.close()
            self._socket = None

    def on_lost_connection(self):
        """ On lost connection, attempt retries if reconnect enabled
        Return: True if the connection is definitively lost/interrupted.
                False if it was somehow recovered (reconnected).
        """
        max_retry = 5
        retry_delay = 60 # seconds

        logger.info('Lost connection detected')
        if self.disconnect_requested.is_set():
            return True

        try:
            self.hard_disconnect()
        except:
            logger.exception("hard_disconnect error in lost connection")

        if not self.config.reconnect:
            self._execute_finish_callback()
            return True

        while max_retry:
            max_retry -= 1
            try:
                self._connect_socket()
                return False
            except:
                logger.warning('Reconnection attempt failed.')

            if max_retry <= 0:
                logger.info('Too many retries. Giving up...')
                break

            logger.info('Next connection attempt in %ds', retry_delay)
            user_disconnected = self.disconnect_requested.wait(retry_delay)
            if user_disconnected:
                # Disconnection was requested by user
                break

        self._execute_finish_callback()
        return True

    def is_alive(self):
        if self._socket_thread:
            return self._socket_thread.is_alive()
        return False

    def join(self, timeout):
        if self._socket_thread and self._socket_thread.is_alive():
            return self._socket_thread.join(timeout)
        return None

    def main_loop(self):
        if not self._socket:
            self._socket_thread = None
            raise ReaderConfigurationError('Not connected')

        try:
            while True:
                lost_connection = False
                socket_list = [self._socket]
                # Get the list sockets which are readable
                read_sockets, write_sockets, error_sockets = select.select(
                    socket_list , [], [])
                for sock in read_sockets:
                    #incoming message from remote server
                    if sock == self._socket:
                        try:
                            data = sock.recv(4096)
                            if data:
                                self.rawDataReceived(data)
                            else:
                                # Zero byte received == disconnected
                                logger.warning('\nDisconnected from server')
                                lost_connection = True
                        except SocketError:
                            logger.exception('\nDisconnected from server')
                            lost_connection = True

                if self._stop_main_loop.is_set():
                    break

                if lost_connection:
                    if self.on_lost_connection():
                        break
                    else:
                        # Connection has been recovered
                        # we can continue the loop with a socket that should
                        # have been updated
                        self._stop_main_loop.clear()
        except:
            logger.exception("Exception encountered in main loop, exiting...")

        self._socket_thread = None


    def send_data(self, data):
        if not self._socket:
            raise ReaderConfigurationError('Not connected')
        self._socket.sendall(data)

    def rawDataReceived(self, data):
        logger.debug('got %d bytes from reader: %s', len(data),
                     hexlify(data))

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
                logger.warning('Too few bytes (%d) to unpack message header',
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
                    self.llrp.handleMessage(lmsg)
                    data = data[msg_len:]
                except LLRPError:
                    logger.exception('Failed to decode LLRPMessage; '
                                     'will not decode %d remaining bytes',
                                     len(data))
                    break
