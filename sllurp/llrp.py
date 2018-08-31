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

LLRP_DEFAULT_PORT = 5084

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


class LLRPReaderState:
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
        state_names = [st for st in dir(LLRPReaderState) if st.startswith('STATE_')]
        for state_name in state_names:
            state_num = getattr(LLRPReaderState, state_name)
            yield state_name, state_num

    @classmethod
    def getStateName(_, state):
        try:
            return [st_name for st_name, st_num in LLRPReaderState.getStates()
                    if st_num == state][0]
        except IndexError:
            raise LLRPError('unknown state {}'.format(state))


class LLRPClient:
    def __init__(self, config, transport_tx_write=None,
                 state_change_callback=None):

        self.config = config
        self.transport_tx_write = transport_tx_write
        self.state_change_callback = state_change_callback

        self.state = LLRPReaderState.STATE_DISCONNECTED

        self.capabilities = {}
        self.reader_mode = None

        self.peername = None

        self.tx_power_table = []

        if config.reset_on_connect:
            logger.info('will reset reader state on connect')

        if config.start_inventory:
            logger.info('will start inventory on connect')

        if (config.impinj_search_mode is not None or
            config.impinj_tag_content_selector is not None):
            logger.info('Enabling Impinj extensions')

        logger.info('using antennas: %s', config.antennas)
        logger.info('transmit power: %s', config.tx_power)


        # Deferreds to fire during state machine machinations
        self._deferreds = defaultdict(list)

        self.rospec = None

        self.last_msg_id = 0

        self.disconnecting = False



    def setState(self, newstate, onComplete=None):
        assert newstate is not None
        logger.debug('state change: %s -> %s',
                     LLRPReaderState.getStateName(self.state),
                     LLRPReaderState.getStateName(newstate))

        self.state = newstate

        if self.state_change_callback:
            self.state_change_callback(newstate)

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
        if max(self.config.antennas) > max_ant:
            reqd = ','.join(map(str, self.config.antennas))
            avail = ','.join(map(str, range(1, max_ant + 1)))
            errmsg = ('Invalid antenna set specified: requested={},'
                      ' available={}; ignoring invalid antennas'.format(
                          reqd, avail))
            raise ReaderConfigurationError(errmsg)
        logger.debug('set antennas: %s', self.config.antennas)

        # parse available transmit power entries, set self.tx_power
        bandcap = capdict['RegulatoryCapabilities']['UHFBandCapabilities']
        self.tx_power_table = self.parsePowerTable(bandcap)
        logger.debug('tx_power_table: %s', self.tx_power_table)
        self.setTxPower(self.config.tx_power)

        # fill UHFC1G2RFModeTable & check requested modulation & Tari
        regcap = capdict['RegulatoryCapabilities']
        modes = regcap['UHFBandCapabilities']['UHFRFModeTable']
        mode_list = [modes[k] for k in sorted(modes.keys(), key=natural_keys)]

        # select a mode by matching available modes to requested parameters:
        # favor mode_identifier over modulation
        if self.config.mode_identifier is not None:
            logger.debug('Setting mode from mode_identifier=%s',
                         self.config.mode_identifier)
            try:
                mode = [mo for mo in mode_list
                        if mo['ModeIdentifier'] == self.config.mode_identifier][0]
                self.reader_mode = mode
            except IndexError:
                valid_modes = sorted(mo['ModeIdentifier'] for mo in mode_list)
                errstr = ('Invalid mode_identifier; valid mode_identifiers'
                          ' are {}'.format(valid_modes))
                raise ReaderConfigurationError(errstr)

        elif self.config.modulation is not None:
            logger.debug('Setting mode from modulation=%s',
                         self.config.modulation)
            try:
                mo = [mo for mo in mode_list
                      if mo['Mod'] == Modulation_Name2Type[self.config.modulation]][0]
                self.reader_mode = mo
            except IndexError:
                raise ReaderConfigurationError('Invalid modulation')

        if self.config.tari:
            if not self.reader_mode:
                errstr = 'Cannot set Tari without choosing a reader mode'
                raise ReaderConfigurationError(errstr)
            if self.config.tari > self.reader_mode['MaxTari']:
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

        # keepalives can occur at any time
        if msgName == 'KEEPALIVE':
            self.send_KEEPALIVE_ACK()
            return

        if msgName == 'RO_ACCESS_REPORT' and \
                self.state != LLRPReaderState.STATE_INVENTORYING:
            logger.debug('ignoring RO_ACCESS_REPORT because not inventorying')
            return

        if msgName == 'READER_EVENT_NOTIFICATION' and \
                self.state >= LLRPReaderState.STATE_CONNECTED:
            logger.debug('Got reader event notification')
            return

        logger.debug('in handleMessage(%s), there are %d Deferreds',
                     msgName, len(self._deferreds[msgName]))

        #######
        # LLRP client state machine follows.  Beware: gets thorny.  Note the
        # order of the LLRPReaderState.STATE_* fields.
        #######

        # in DISCONNECTED, CONNECTING, and CONNECTED states, expect only
        # READER_EVENT_NOTIFICATION messages.
        if self.state in (LLRPReaderState.STATE_DISCONNECTED,
                          LLRPReaderState.STATE_CONNECTING,
                          LLRPReaderState.STATE_CONNECTED):
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

            self.disconnecting = False

            self.processDeferreds(msgName, lmsg.isSuccess())

            # a Deferred to call when we get GET_READER_CAPABILITIES_RESPONSE
            def get_reader_capabilities_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPReaderState.STATE_CONNECTED)
                else:
                    self.panic(None, 'GET_READER_CAPABILITIES failed')

            if (self.config.impinj_search_mode is not None or
                self.config.impinj_tag_content_selector is not None):

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

        elif self.state == LLRPReaderState.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS:
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
        elif self.state == LLRPReaderState.STATE_SENT_GET_CAPABILITIES:
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
                    self.setState(LLRPReaderState.STATE_SENT_GET_CONFIG)
                else:
                    self.panic(None, 'GET_READER_CONFIG failed')

            if self.disconnecting:
                return
            self.send_GET_READER_CONFIG(onCompletion=get_reader_config_cb)

        elif self.state == LLRPReaderState.STATE_SENT_GET_CONFIG:
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
                    self.setState(LLRPReaderState.STATE_SENT_SET_CONFIG)
                else:
                    self.panic(None, 'SET_READER_CONFIG failed')

            if self.disconnecting:
                return
            self.send_ENABLE_EVENTS_AND_REPORTS()
            self.send_SET_READER_CONFIG(onCompletion=set_reader_config_cb)

        elif self.state == LLRPReaderState.STATE_SENT_SET_CONFIG:
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

            if self.disconnecting:
                return

            if self.config.reset_on_connect:
                def on_politely_stopped_cb(state, is_success, *args):
                    if is_success:
                        self.setState(LLRPReaderState.STATE_CONNECTED)
                        if self.config.start_inventory:
                            self.startInventory()

                self.stopPolitely(onCompletion=on_politely_stopped_cb)
            elif self.config.start_inventory:
                self.startInventory()

        # in state SENT_ADD_ROSPEC, expect only ADD_ROSPEC_RESPONSE; respond to
        # favorable ADD_ROSPEC_RESPONSE by enabling the added ROSpec and
        # advancing to state SENT_ENABLE_ROSPEC.
        elif self.state == LLRPReaderState.STATE_SENT_ADD_ROSPEC:
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
        elif self.state == LLRPReaderState.STATE_SENT_ENABLE_ROSPEC:
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
        elif self.state == LLRPReaderState.STATE_PAUSING:
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
        elif self.state == LLRPReaderState.STATE_SENT_START_ROSPEC:
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

        elif self.state == LLRPReaderState.STATE_INVENTORYING:
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

        elif self.state == LLRPReaderState.STATE_SENT_DELETE_ACCESSSPEC:
            if msgName != 'DELETE_ACCESSSPEC_RESPONSE':
                logger.error('unexpected response %s when deleting AccessSpec',
                             msgName)

            self.processDeferreds(msgName, lmsg.isSuccess())

        elif self.state == LLRPReaderState.STATE_SENT_DELETE_ROSPEC:
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
        self.setState(LLRPReaderState.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS)
        self._deferreds['CUSTOM_MESSAGE'].append(onCompletion)

    def send_GET_READER_CAPABILITIES(self, _, onCompletion):
        self.sendMessage({
            'GET_READER_CAPABILITIES': {
                'Ver':  1,
                'Type': 1,
                'ID':   0,
                'RequestedData': Capability_Name2Type['All']
            }})
        self.setState(LLRPReaderState.STATE_SENT_GET_CAPABILITIES)
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
        self.setState(LLRPReaderState.STATE_SENT_GET_CONFIG)
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
                }
            }})
        self.setState(LLRPReaderState.STATE_SENT_SET_CONFIG)
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
        self.setState(LLRPReaderState.STATE_SENT_ADD_ROSPEC)
        self._deferreds['ADD_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ROSPEC(self, _, rospec, onCompletion):
        self.sendMessage({
            'ENABLE_ROSPEC': {
                'Ver':  1,
                'Type': 24,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPReaderState.STATE_SENT_ENABLE_ROSPEC)
        self._deferreds['ENABLE_ROSPEC_RESPONSE'].append(onCompletion)

    def send_START_ROSPEC(self, _, rospec, onCompletion):
        self.sendMessage({
            'START_ROSPEC': {
                'Ver':  1,
                'Type': 22,
                'ID':   0,
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPReaderState.STATE_SENT_START_ROSPEC)
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
        if self.state == LLRPReaderState.STATE_INVENTORYING:
            logger.warn('ignoring startInventory() while already inventorying')
            return None

        rospec = self.getROSpec(force_new=force_regen_rospec)['ROSpec']

        logger.info('starting inventory')

        # upside-down chain of callbacks: add, enable, start ROSpec
        # started_rospec = defer.Deferred()
        # started_rospec.addCallback(self._setState_wrapper,
        #                            LLRPReaderState.STATE_INVENTORYING)
        # started_rospec.addErrback(self.panic, 'START_ROSPEC failed')
        # logger.debug('made started_rospec')

        def enabled_rospec_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPReaderState.STATE_INVENTORYING)
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
        config = self.config
        rospec_kwargs = dict(
            duration_sec=config.duration,
            report_every_n_tags=config.report_every_n_tags,
            report_timeout_ms=config.report_timeout_ms,
            tx_power=config.tx_power,
            antennas=config.antennas,
            tag_content_selector=config.tag_content_selector,
            session=config.session,
            tari=config.tari,
            tag_population=config.tag_population
        )
        logger.info('Impinj search mode? %s', config.impinj_search_mode)
        if config.impinj_search_mode is not None:
            rospec_kwargs['impinj_search_mode'] = config.impinj_search_mode
        if config.impinj_tag_content_selector is not None:
            rospec_kwargs['impinj_tag_content_selector'] = \
                config.impinj_tag_content_selector

        self.rospec = LLRPROSpec(self.reader_mode, 1, **rospec_kwargs)
        logger.debug('ROSpec: %s', self.rospec)
        return self.rospec

    def stopPolitely(self, onCompletion=None, disconnect=False):
        """Delete all active ROSpecs.  Return a Deferred that will be called
           when the DELETE_ROSPEC_RESPONSE comes back."""
        logger.info('stopping politely')
        if disconnect:
            self.disconnecting = True
        self.sendMessage({
            'DELETE_ACCESSSPEC': {
                'Ver': 1,
                'Type': 41,
                'ID': 0,
                'AccessSpecID': 0  # all AccessSpecs
            }})
        self.setState(LLRPReaderState.STATE_SENT_DELETE_ACCESSSPEC)

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
        self.setState(LLRPReaderState.STATE_SENT_DELETE_ROSPEC)

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

        >>> LLRPReaderState.parsePowerTable({'TransmitPowerLevelTableEntry1': \
            {'Index': 1, 'TransmitPowerValue': 3225}})
        [0, 32.25]
        >>> LLRPReaderState.parsePowerTable({})
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
                                    antid, tx_power, min_power,
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
            if self.config.tx_power[ant] != tx_pow_idx:
                self.config.tx_power[ant] = tx_pow_idx
                needs_update = True

            logger.debug('tx_power for antenna %s: %s (%s dBm)', ant,
                         tx_pow_idx, tx_pow_dbm)

        if needs_update and self.state == LLRPReaderState.STATE_INVENTORYING:
            logger.debug('changing tx power; will stop politely, then resume')
            def on_politely_stopped_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPReaderState.STATE_CONNECTED)
                    self.startInventory(force_regen_rospec=True)
            self.stopPolitely(onCompletion=on_politely_stopped_cb)

    def pause(self, duration_seconds=0, force=False, force_regen_rospec=False):
        """Pause an inventory operation for a set amount of time."""
        logger.debug('pause(%s)', duration_seconds)
        # Temporary error until fixed.
        if duration_seconds > 0:
            raise ReaderConfigurationError('"duration_seconds > 0" is not yet'
                                           'implemented for "pause".')
        if self.state != LLRPReaderState.STATE_INVENTORYING:
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
        self.setState(LLRPReaderState.STATE_PAUSING)

        def disable_rospec_pause_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPReaderState.STATE_PAUSED)
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

        if self.state in (LLRPReaderState.STATE_CONNECTED,
                          LLRPReaderState.STATE_DISCONNECTED):
            logger.debug('will startInventory()')
            self.startInventory()
            return

        if self.state != LLRPReaderState.STATE_PAUSED:
            logger.debug('cannot resume() if not paused (state=%s); ignoring',
                         self.getStateName(self.state))
            return None

        logger.info('resuming')

        def enable_rospec_resume_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPReaderState.STATE_INVENTORYING)
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


        if config_dict:
            self.update_config(config_dict)

        self.validate_config()

    def update_config(self, config_dict):
        for key, value in config_dict.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def validate_config(self):
        if hasattr(self, 'tx_power'):
            if isinstance(self.tx_power, int):
                self.tx_power = {ant: self.tx_power for ant in self.antennas}
            elif isinstance(self.tx_power, dict):
                if set(self.antennas) != set(self.tx_power.keys()):
                    raise LLRPError('Must specify tx_power for each antenna')
            else:
                raise LLRPError('tx_power must be dict or int')

class LLRPReaderClient:
    def __init__(self, host, port=None, config=None, timeout=5.0):
        if port is None:
            port = LLRP_DEFAULT_PORT
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

        # New llrp client
        self.llrp = LLRPClient(
            self.config,
            transport_tx_write=self.send_data,
            state_change_callback=self._on_llrp_state_changed
        )

        # callbacks

        # state-change callbacks: STATE_* -> [list of callables]
        self._llrp_state_callbacks = {}
        for _, st_num in LLRPReaderState.getStates():
            self._llrp_state_callbacks[st_num] = []

        # message callbacks (including tag reports):
        # msg_name -> [list of callables]
        self._llrp_message_callbacks = defaultdict(list)

        self._tag_report_callbacks = []
        self._disconnected_callbacks = []

    def get_peername(self):
        return (self._host, self._port)

    def add_state_callback(self, state, cb):
        """Add a callback to run upon a state transition.

        When an LLRPReaderState enters `state`, `cb()` will be called.

        Args:
            state: A state from LLRPReaderState.STATE_*.
            cb: A callable that takes an LLRPReaderState argument.
        """
        self._llrp_state_callbacks[state].append(cb)

    def add_message_callback(self, msg_type, cb):
        self._llrp_message_callbacks[msg_type].append(cb)

    def add_tag_report_callback(self, cb):
        if not 'RO_ACCESS_REPORT' in self._llrp_message_callbacks:
            self._llrp_message_callbacks['RO_ACCESS_REPORT'].append(
                self._on_llrp_tag_report)

        self._tag_report_callbacks.append(cb)

    def add_disconnected_callback(self, cb):
        self._disconnected_callbacks.append(cb)

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
            self._on_disconnected()
            return

        def on_politely_stopped_cb(state, is_success, *args):
            if is_success:
                self.llrp.setState(LLRPReaderState.STATE_DISCONNECTED)
            logger.info('disconnecting')
            self.hard_disconnect()
            self._on_disconnected()
        logger.info('stopPolitely will disconnect when stopped')

        self.llrp.stopPolitely(onCompletion=on_politely_stopped_cb,
                               disconnect=True)

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
            self._on_disconnected()
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

        self._on_disconnected()
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
                    self._on_llrp_message_received(lmsg)
                    self.llrp.handleMessage(lmsg)
                    data = data[msg_len:]
                except LLRPError:
                    logger.exception('Failed to decode LLRPMessage; '
                                     'will not decode %d remaining bytes',
                                     len(data))
                    break

    def _on_disconnected(self):
        for fn in self._disconnected_callbacks:
            try:
                fn(self)
            except:
                logger.exception("Error during user on_disconnected callback."
                                 "Continuing anyway...")

    def _on_llrp_state_changed(self, newstate):
        """Call user callbacks if needed"""
        for fn in self._llrp_state_callbacks[newstate]:
            try:
                fn(self, newstate)
            except:
                logger.exception("Error during state change callback execution"
                                 ". Continuing anyway...")

    def _on_llrp_message_received(self, lmsg):
        """Call user callbacks if needed"""
        msgName = lmsg.getName()
        # call per-message callbacks
        logger.debug('starting message callbacks for %s', msgName)
        for fn in self._llrp_message_callbacks[msgName]:
            try:
                fn(self, lmsg)
            except:
                logger.exception("Error during message callback execution. "
                                 "Continuing anyway...")
        logger.debug('done with message callbacks for %s', msgName)

    def _on_llrp_tag_report(self, _, lmsg):
        tags_report_dict = lmsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
        for fn in self._tag_report_callbacks:
            try:
                fn(self, tags_report_dict)
            except:
                logger.exception("Error during user on_disconnected callback."
                                 "Continuing anyway...")
