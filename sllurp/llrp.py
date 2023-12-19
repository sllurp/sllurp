from __future__ import print_function, unicode_literals

import select

from binascii import hexlify
from collections import defaultdict
from socket import (AF_INET, SOCK_STREAM, SHUT_RDWR, SOL_SOCKET, SO_KEEPALIVE,
                    IPPROTO_TCP, TCP_NODELAY, socket, error as SocketError)
from threading import Thread, Event
from weakref import WeakSet

from .llrp_decoder import TYPE_CUSTOM, VENDOR_ID_IMPINJ
from .llrp_proto import (LLRPROSpec, LLRPError, Message_struct,
                         msg_header_len, msg_header_pack, msg_header_unpack,
                         msg_header_encode, msg_header_decode,
                         get_message_name_from_type, Capability_Name2Type,
                         AirProtocol, llrp_data2xml, LLRPMessageDict,
                         DEFAULT_CHANNEL_INDEX, DEFAULT_HOPTABLE_INDEX)
from .llrp_errors import ReaderConfigurationError
from .log import get_logger, is_general_debug_enabled
from .util import natural_keys, iteritems, iterkeys, find_closest

LLRP_DEFAULT_PORT = 5084
LLRP_MSG_ID_MAX = 4294967295
THREAD_NAME_PREFIX = 'sllurp-reader'

all_reader_refs = WeakSet()
logger = get_logger(__name__)



class LLRPMessage(object):
    __slots__ = ['msgdict', 'msgbytes', 'msgname']

    def __init__(self, msgdict=None, msgbytes=None):
        if not (msgdict or msgbytes):
            raise LLRPError('Provide either a message dict or a sequence'
                            ' of bytes.')
        self.msgdict = None
        self.msgbytes = None
        self.msgname = None
        if msgdict:
            self.msgdict = LLRPMessageDict(msgdict)
            if not msgbytes:
                self.serialize()
        if msgbytes:
            self.msgbytes = msgbytes
            if not msgdict:
                self.deserialize()

    def serialize(self):
        """Turns a message dictionnary into a sequence of bytes"""
        if self.msgdict is None:
            raise LLRPError('No message dict to serialize.')
        msgdict_iter = iteritems(self.msgdict)
        name, msgitem = next(msgdict_iter)
        logger.debugfast('serializing %s command', name)

        try:
            msg_info = Message_struct[name]
        except KeyError:
            raise LLRPError('Unknown message type: %s. Cannot encode.' % name)

        try:
            encoder = msg_info['encode']
        except KeyError:
            raise LLRPError('Cannot find encoder for message type %s' % name)

        version = msgitem.get('Ver', 1)
        msgtype = msg_info['type']
        if name == "CUSTOM_MESSAGE":
            vendorid = msgitem['VendorID']
            subtype = msgitem['Subtype']
        else:
            vendorid = msg_info.get('vendorid', 0)
            subtype = msg_info.get('subtype', 0)
        msgid = msgitem.get('ID', 0)
        data = encoder(msgitem, msg_info)

        self.msgbytes = msg_header_encode(msgtype, version, len(data), msgid,
                                          vendorid, subtype)
        self.msgbytes += data
        if is_general_debug_enabled():
            logger.debugfast('serialized bytes: %s', hexlify(self.msgbytes))
            logger.debugfast('done serializing %s command', name)
        self.msgname = name

    def deserialize(self):
        """Turns a sequence of bytes into a message dictionary."""
        if self.msgbytes is None:
            raise LLRPError('No message bytes to deserialize.')
        data = self.msgbytes
        (msgtype,
         vendorid,
         subtype,
         ver,
         hdr_len,
         full_length,
         msgid) = msg_header_decode(data)
        try:
            try:
                name = get_message_name_from_type(msgtype, vendorid, subtype)
            except KeyError:
                # If no specific custom_message struct, fallback to generic one
                if msgtype == TYPE_CUSTOM:
                    name = "CUSTOM_MESSAGE"
                    logger.debugfast('Unknown "custom message" will be decoded'
                                     ' with the generic custom_message decoder'
                                     ' (%s,%s,%s)', msgtype, vendorid, subtype)
                else:
                    raise
            logger.debugfast('deserializing %s command', name)
            decoder = Message_struct[name]['decode']
        except KeyError:
            raise LLRPError('Cannot find decoder for message type '
                            '{}'.format(msgtype))
        body = data[hdr_len:full_length]
        try:
            self.msgdict = {
                name: dict(decoder(body, name))
            }
            self.msgdict[name]['Ver'] = ver
            self.msgdict[name]['Type'] = msgtype
            self.msgdict[name]['ID'] = msgid
            logger.debugfast('done deserializing %s command', name)
        except LLRPError:
            logger.error('Problem with %s message format', name)
            raise
        except ValueError:
            logger.exception('Unable to decode body of %s', name)
            raise LLRPError('Unable to decode body of %s' % name)
        self.msgname = name

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
        return self.msgname

    def __repr__(self):
        try:
            ret = llrp_data2xml(self.msgdict)
        except TypeError as te:
            logger.exception(te)
            ret = ''
        return ret


class C1G2TargetTag(object):
    def __init__(self, MB=0, Pointer=0, MaskBitCount=0, TagMask=b'',
                 DataBitCount=0, TagData=b''):
        self.MB = MB
        self.Match = 1
        self.Pointer = Pointer
        self.MaskBitCount = MaskBitCount
        self.TagMask = TagMask
        self.DataBitCount = DataBitCount
        self.TagData = TagData


class C1G2OpSpec(object):
    pass

class C1G2Read(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, MB=0, WordPtr=0,
                 WordCount=0):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.MB = MB
        self.WordPtr = WordPtr
        self.WordCount = WordCount

class C1G2Write(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, MB=0, WordPtr=0,
                 WriteDataWordCount=0, WriteData=b''):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.MB = MB
        self.WordPtr = WordPtr
        self.WriteDataWordCount = WriteDataWordCount
        self.WriteData = WriteData

class C1G2Kill(C1G2OpSpec):
    def __init__(self, OpSpecID=0, KillPassword=0):
        self.OpSpecID = OpSpecID
        self.KillPassword = KillPassword

class C1G2Recommission(C1G2OpSpec):
    def __init__(self, OpSpecID=0, KillPassword=0, Flag3SB=False,
                 Flag2SB=False, FlagLSB=False):
        self.OpSpecID = OpSpecID
        self.KillPassword = KillPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.Flag3SB = Flag3SB
        self.Flag2SB = Flag2SB
        self.FlagLSB = FlagLSB

class C1G2LockPayload(object):
    def __init__(self, Privilege, DataField):
        if Privilege < 0 or Privilege > 3:
            raise ValueError("Invalid Privilege value")
        if DataField < 0 or Privilege > 4:
            raise ValueError("Invalid DataField value")

        self.Privilege = Privilege
        self.DataField = DataField

class C1G2Lock(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, LockPayload=None):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        if not LockPayload:
            raise ValueError("At least one C1G2LockPayload needs to be defined")
        if not isinstance(LockPayload, list):
            LockPayload = [LockPayload]
        self.LockPayload = LockPayload

class C1G2BlockErase(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, MB=0, WordPtr=0,
                 WriteCount=0):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.MB = MB
        self.WordPtr = WordPtr
        self.WriteCount = WriteCount

class C1G2BlockWrite(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, MB=0, WordPtr=0,
                 WriteDataWordCount=0, WriteData=b''):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.MB = MB
        self.WordPtr = WordPtr
        self.WriteDataWordCount = WriteDataWordCount
        self.WriteData = WriteData

class C1G2BlockPermalock(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, MB=0, BlockPtr=0,
                 BlockMaskWordCount=0, BlockMask=b''):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.MB = MB
        self.BlockPtr = BlockPtr
        self.BlockMaskWordCount = BlockMaskWordCount
        self.BlockMask = BlockMask

class C1G2GetBlockPermalockStatus(C1G2OpSpec):
    def __init__(self, OpSpecID=0, AccessPassword=0, MB=0, BlockPtr=0,
                 BlockRange=0):
        self.OpSpecID = OpSpecID
        self.AccessPassword = AccessPassword
        # Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved'
        self.MB = MB
        self.BlockPtr = BlockPtr
        self.BlockRange = BlockRange


class LLRPReaderState(object):
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
    def getStates(cls):
        state_names = [st for st in dir(cls) if st.startswith('STATE_')]
        for state_name in state_names:
            state_num = getattr(LLRPReaderState, state_name)
            yield state_name, state_num

    @classmethod
    def getStateName(cls, state):
        try:
            return [st_name for st_name, st_num in cls.getStates()
                    if st_num == state][0]
        except IndexError:
            raise LLRPError('unknown state {}'.format(state))


class LLRPClient(object):
    def __init__(self, config, transport_tx_write=None,
                 state_change_callback=None):

        self.config = config
        self.transport_tx_write = transport_tx_write
        self.state_change_callback = state_change_callback

        self.state = LLRPReaderState.STATE_DISCONNECTED

        self.capabilities = {}
        # Configuration reported by the reader.
        # Not to be confused with the client config.
        self.reader_config = {}
        self.reader_mode = None
        self.max_ant = 0

        self.peername = None

        self.tx_power_table = []

        if config.reset_on_connect:
            logger.info('will reset reader state on connect')

        if config.start_inventory:
            logger.info('will start inventory on connect')

        if config.impinj_search_mode \
           or config.impinj_tag_content_selector \
           or config.impinj_extended_configuration \
           or config.impinj_event_selector \
           or config.frequencies.get('Automatic', False) \
           or len(config.frequencies.get('Channelist', [])) > 1:
            logger.info('Enabling Impinj extensions')

        logger.info('using antennas: %s', config.antennas)
        logger.info('transmit power: %s', config.tx_power)


        # Deferreds to fire during state machine machinations
        self._deferreds = defaultdict(list)

        self.rospec = None

        self.last_msg_id = 0

        self.disconnecting = False

    def update_config(self, new_config):
        """Update LLRPClient's config

        Not completly safe, to be used with caution.
        """
        self.config = new_config

    def setState(self, newstate, onCompletion=None):
        assert newstate is not None
        if is_general_debug_enabled():
            logger.debugfast('state change: %s -> %s',
                            LLRPReaderState.getStateName(self.state),
                            LLRPReaderState.getStateName(newstate))

        self.state = newstate

        if self.state_change_callback:
            self.state_change_callback(newstate)

    def parseReaderConfig(self, confdict):
        """Parse a reader configuration dictionary and adjust instance settings.

        """
        return

    def parseCapabilities(self, capdict):
        """Parse a capabilities dictionary and adjust instance settings.

        At the time this function is called, the user has requested some
        settings (e.g., mode identifier), but we haven't yet asked the reader
        whether those requested settings are within its capabilities. This
        function's job is to parse the reader's capabilities, compare them
        against any requested settings, and raise an error if there are any
        incompatibilities.

        Sets the following instance variables:
        - self.antennas (list of antenna numbers, e.g., [1] or [1, 2])
        - self.tx_power_table (list of dBm values)
        - self.reader_mode (dictionary of mode settings, e.g., Tari)

        Raises ReaderConfigurationError if the requested settings are not
        within the reader's capabilities.
        """
        # check requested antenna set
        gdc = capdict['GeneralDeviceCapabilities']
        max_ant = gdc['MaxNumberOfAntennaSupported']
        self.max_ant = max_ant
        if max(self.config.antennas) > max_ant:
            reqd = ','.join(map(str, self.config.antennas))
            avail = ','.join(map(str, range(1, max_ant + 1)))
            errmsg = ('Invalid antenna set specified: requested={},'
                      ' available={}; ignoring invalid antennas'.format(
                          reqd, avail))
            raise ReaderConfigurationError(errmsg)
        logger.debugfast('set antennas: %s', self.config.antennas)

        # parse available transmit power entries, set self.tx_power
        bandcap = capdict['RegulatoryCapabilities']['UHFBandCapabilities']
        self.tx_power_table = self.parsePowerTable(bandcap)
        logger.debugfast('tx_power_table: %s', self.tx_power_table)
        if self.config.tx_power_dbm is not None:
            self.setTxPowerDbm(self.config.tx_power_dbm)
        else:
            self.setTxPower(self.config.tx_power)

        # parse list of reader's supported mode identifiers
        regcap = capdict['RegulatoryCapabilities']
        mode_list = regcap['UHFBandCapabilities']['UHFC1G2RFModeTable']\
            ['UHFC1G2RFModeTableEntry']

        # select a mode by matching available modes to requested parameters:
        # favor mode_identifier over modulation
        if self.config.mode_identifier is not None:
            logger.debugfast('Setting mode from mode_identifier=%s',
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

        # if we're trying to set Tari explicitly, but the selected mode doesn't
        # support the requested Tari, that's a configuration error.
        if self.reader_mode and self.config.tari:
            if self.reader_mode['MinTari'] < self.config.tari < self.reader_mode['MaxTari']:
                logger.debug('Overriding mode Tari %s with requested Tari %s',
                             self.reader_mode['MaxTari'], self.config.tari)
            else:
                errstr = ('Requested Tari {} is incompatible with selected '
                          'mode {}'.format(self.config.tari, self.reader_mode))

        logger.info('using reader mode: %s', self.reader_mode)

    def processDeferreds(self, msgName, isSuccess):
        deferreds = self._deferreds[msgName]
        if not deferreds:
            return
        if is_general_debug_enabled():
            logger.debugfast('running %d Deferreds for %s; '
                             'isSuccess=%s', len(deferreds), msgName, isSuccess)
        for deferred_cb in deferreds:
            deferred_cb(self.state, isSuccess)
        del self._deferreds[msgName]

    def handleMessage(self, lmsg):
        """Implements the LLRP client state machine."""
        logger.debugfast('LLRPMessage received in state %s:\n%s', self.state,
                         lmsg)
        msgName = lmsg.getName()

        # keepalives can occur at any time
        if msgName == 'KEEPALIVE':
            self.send_KEEPALIVE_ACK()
            return

        if msgName == 'RO_ACCESS_REPORT' and \
                self.state != LLRPReaderState.STATE_INVENTORYING:
            logger.debugfast('ignoring RO_ACCESS_REPORT because not inventorying')
            return

        if msgName == 'READER_EVENT_NOTIFICATION' and \
                self.state >= LLRPReaderState.STATE_CONNECTED:

            logger.debugfast('Got reader event notification')
            return

        if is_general_debug_enabled():
            logger.debugfast('in handleMessage(%s), there are %d Deferreds',
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

            if self.config.impinj_search_mode \
               or self.config.impinj_tag_content_selector \
               or self.config.impinj_extended_configuration \
               or self.config.impinj_event_selector \
               or self.config.frequencies.get('Automatic', False) \
               or len(self.config.frequencies.get('Channelist', [])) > 1:

                def enable_impinj_ext_cb(state, is_success, *args):
                    if is_success:
                        self.send_GET_READER_CAPABILITIES(
                            self, onCompletion=get_reader_capabilities_cb)
                    else:
                        self.panic(None, 'ENABLE_IMPINJ_EXTENSIONS failed')
                        raise ReaderConfigurationError(
                            "ENABLE_IMPINJ_EXTENSIONS failed")

                self.send_ENABLE_IMPINJ_EXTENSIONS(
                    onCompletion=enable_impinj_ext_cb)
            else:
                self.send_GET_READER_CAPABILITIES(
                    self, onCompletion=get_reader_capabilities_cb)

        elif self.state == LLRPReaderState.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS:
            if is_general_debug_enabled():
                logger.debugfast(lmsg)
            if msgName != 'IMPINJ_ENABLE_EXTENSIONS_RESPONSE':
                logger.error('unexpected response %s while enabling Impinj'
                             'extensions', msgName)
                raise ReaderConfigurationError(
                    "Unexpected response while enabling Impinj extensions")

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s enabling Impinj extensions: %s',
                             status, err)
                raise ReaderConfigurationError(
                    "ENABLE_IMPINJ_EXTENSIONS failed")
            logger.debugfast('Successfully enabled Impinj extensions')

            self.processDeferreds(msgName, lmsg.isSuccess())

        # in state SENT_GET_CAPABILITIES, expect GET_CAPABILITIES_RESPONSE;
        # respond to this message by advancing to state CONNECTED.
        elif self.state == LLRPReaderState.STATE_SENT_GET_CAPABILITIES:
            if msgName != 'GET_READER_CAPABILITIES_RESPONSE':
                logger.error('unexpected response %s getting capabilities',
                             msgName)
                raise ReaderConfigurationError(
                    "Unexpected response while getting capabilities")

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s getting capabilities: %s', status, err)
                raise ReaderConfigurationError(
                    "Error getting capabilities")

            self.capabilities = \
                lmsg.msgdict['GET_READER_CAPABILITIES_RESPONSE']
            try:
                self.parseCapabilities(self.capabilities)
            except ReaderConfigurationError:
                logger.exception('Capabilities mismatch')
                raise

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
                raise ReaderConfigurationError(
                    "Unexpected response while getting reader config")

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s getting reader config: %s', status, err)
                raise ReaderConfigurationError("Error getting reader config")

            if msgName == 'GET_READER_CONFIG_RESPONSE':
                self.reader_config = lmsg.msgdict['GET_READER_CONFIG_RESPONSE']
                try:
                    self.parseReaderConfig(self.reader_config)
                except ReaderConfigurationError:
                    logger.exception('Reader config mismatch')
                    raise

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
                logger.error('unexpected response %s setting config', msgName)
                raise ReaderConfigurationError(
                    "Unexpected response while setting reader config")

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s setting reader config: %s', status, err)
                raise ReaderConfigurationError("Error setting reader config")

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
                raise ReaderConfigurationError(
                    "Unexpected response while adding ROSpec")

            if not lmsg.isSuccess():
                status = lmsg.msgdict[msgName]['LLRPStatus']['StatusCode']
                err = lmsg.msgdict[msgName]['LLRPStatus']['ErrorDescription']
                logger.fatal('Error %s adding ROSpec: %s', status, err)
                raise ReaderConfigurationError("Error adding ROSpec")

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
            'KEEPALIVE_ACK': {}
        })

    def send_ENABLE_IMPINJ_EXTENSIONS(self, onCompletion):
        self.sendMessage({
            'IMPINJ_ENABLE_EXTENSIONS': {}
        })
        self.setState(LLRPReaderState.STATE_SENT_ENABLE_IMPINJ_EXTENSIONS)
        self._deferreds['IMPINJ_ENABLE_EXTENSIONS_RESPONSE'].append(onCompletion)

    def send_GET_READER_CAPABILITIES(self, _, onCompletion):
        self.sendMessage({
            'GET_READER_CAPABILITIES': {
                'RequestedData': Capability_Name2Type['All']
            }})
        self.setState(LLRPReaderState.STATE_SENT_GET_CAPABILITIES)
        self._deferreds['GET_READER_CAPABILITIES_RESPONSE'].append(
            onCompletion)

    def send_GET_READER_CONFIG(self, onCompletion):
        cfg = {
            'RequestedData': Capability_Name2Type['All']
        }
        if self.config.impinj_extended_configuration:
            # NOTE: Not really usefull, as default value when impinj extensions
            # are enabled.
            cfg['ImpinjRequestedData'] = {
                    # per Octane LLRP guide:
                    # 2000 = All configuration params
                    'RequestedData': 2000
            }
        self.sendMessage({
            'GET_READER_CONFIG': cfg
        })
        self.setState(LLRPReaderState.STATE_SENT_GET_CONFIG)
        self._deferreds['GET_READER_CONFIG_RESPONSE'].append(
            onCompletion)

    def send_ENABLE_EVENTS_AND_REPORTS(self):
        self.sendMessage({
            'ENABLE_EVENTS_AND_REPORTS': {}
        })

    def send_SET_READER_CONFIG(self, onCompletion):
        msg = {
            'SET_READER_CONFIG': {
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
                        #'SpecLoopEvent': False,
                    },
                },
            }
        }
        if self.config.keepalive_interval > 0:
            msg['SET_READER_CONFIG']['KeepaliveSpec'] = {
                'KeepaliveTriggerType': 1,
                'TimeInterval': self.config.keepalive_interval
            }
        for event, enabled in self.config.event_selector.items():
            msg['SET_READER_CONFIG']['ReaderEventNotificationSpec']\
                ['EventNotificationState'][event] = enabled
        if self.config.impinj_event_selector:
            ant_event_enable = self.config.impinj_event_selector.get(
                'AntennaAttemptEvent')
            if ant_event_enable is not None:
                msg['SET_READER_CONFIG']['ImpinjAntennaConfiguration'] = {
                    'ImpinjAntennaEventConfiguration': ant_event_enable
                }

        self.sendMessage(msg)
        self.setState(LLRPReaderState.STATE_SENT_SET_CONFIG)
        self._deferreds['SET_READER_CONFIG_RESPONSE'].append(
            onCompletion)

    def send_ADD_ROSPEC(self, rospec, onCompletion):
        logger.debugfast('about to send_ADD_ROSPEC')
        self.sendMessage({
            'ADD_ROSPEC': {
                'ROSpecID': rospec['ROSpecID'],
                'ROSpec': rospec,
            }
        })
        logger.debugfast('sent ADD_ROSPEC')
        self.setState(LLRPReaderState.STATE_SENT_ADD_ROSPEC)
        self._deferreds['ADD_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ROSPEC(self, _, rospec, onCompletion):
        self.sendMessage({
            'ENABLE_ROSPEC': {
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPReaderState.STATE_SENT_ENABLE_ROSPEC)
        self._deferreds['ENABLE_ROSPEC_RESPONSE'].append(onCompletion)

    def send_START_ROSPEC(self, _, rospec, onCompletion):
        self.sendMessage({
            'START_ROSPEC': {
                'ROSpecID': rospec['ROSpecID']
            }})
        self.setState(LLRPReaderState.STATE_SENT_START_ROSPEC)
        self._deferreds['START_ROSPEC_RESPONSE'].append(onCompletion)

    def send_ADD_ACCESSSPEC(self, accessSpec, onCompletion):
        self.sendMessage({
            'ADD_ACCESSSPEC': {
                'AccessSpec': accessSpec,
            }})
        self._deferreds['ADD_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_DISABLE_ACCESSSPEC(self, accessSpecID=1, onCompletion=None):
        self.sendMessage({
            'DISABLE_ACCESSSPEC': {
                'AccessSpecID': accessSpecID,
            }})

        if onCompletion:
            self._deferreds['DISABLE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_ENABLE_ACCESSSPEC(self, _, accessSpecID, onCompletion=None):
        self.sendMessage({
            'ENABLE_ACCESSSPEC': {
                'AccessSpecID': accessSpecID,
            }})

        if onCompletion:
            self._deferreds['ENABLE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def send_DELETE_ACCESSSPEC(self, accessSpecID=1,
                               onCompletion=None):
        # logger.info('Deleting current accessSpec.')
        self.sendMessage({
            'DELETE_ACCESSSPEC': {
                'AccessSpecID': accessSpecID  # ONE AccessSpec
            }})

        if onCompletion:
            self._deferreds['DELETE_ACCESSSPEC_RESPONSE'].append(onCompletion)

    def startAccess(self, opSpec, targetSpec=None, stopAfterCount=0,
                    accessSpecID=1):
        if not targetSpec:
            # XXX correct default values?
            targetSpec = [C1G2TargetTag()]
        if not isinstance(targetSpec, list):
            targetSpec = [targetSpec]
        elif len(targetSpec) > 2:
            raise ValueError("A maximum of 2 C1G2TargetTag is allowed per "
                             "accessSpec")
        targetParam = []
        for target in targetSpec:
            targetParam.append({
                'MB': target.MB,
                'M': target.Match,
                'Pointer': target.Pointer,
                'MaskBitCount': target.MaskBitCount,
                'TagMask': target.TagMask,
                'DataBitCount': target.DataBitCount,
                'TagData': target.TagData
            })

        accessStopParam = {
            'AccessSpecStopTriggerType': 1 if stopAfterCount > 0 else 0,
            'OperationCountValue': stopAfterCount,
        }

        accessSpec = {
            'AccessSpecID': accessSpecID,
            'AntennaID': 0,  # all antennas
            'ProtocolID': AirProtocol['EPCGlobalClass1Gen2'],
            'CurrentState': False,  # disabled by default
            'ROSpecID': 0,  # all ROSpecs
            'AccessSpecStopTrigger': accessStopParam,
            'AccessCommand': {
                'TagSpecParameter': {
                    'C1G2TargetTag': targetParam,
                },
                'OpSpecParameter': [],
            },
            'AccessReportSpec': {
                'AccessReportTrigger': 1  # report at end of access
            }
        }

        if isinstance(opSpec, C1G2Read):
            accessSpec['AccessCommand']['OpSpecParameter'].append({
                'C1G2Read': {
                    'OpSpecID': opSpec.OpSpecID,
                    'AccessPassword': opSpec.AccessPassword,
                    'MB': opSpec.MB,
                    'WordPtr': opSpec.WordPtr,
                    'WordCount': opSpec.WordCount
                }
            })
        elif isinstance(opSpec, C1G2Write):
            accessSpec['AccessCommand']['OpSpecParameter'].append({
                'C1G2Write': {
                    'OpSpecID': opSpec.OpSpecID,
                    'AccessPassword': opSpec.AccessPassword,
                    'MB': opSpec.MB,
                    'WordPtr': opSpec.WordPtr,
                    'WriteDataWordCount': opSpec.WriteDataWordCount,
                    'WriteData': opSpec.WriteData
                }
            })
        elif isinstance(opSpec, C1G2BlockWrite):
            accessSpec['AccessCommand']['OpSpecParameter'].append({
                'C1G2BlockWrite': {
                    'OpSpecID': opSpec.OpSpecID,
                    'AccessPassword': opSpec.AccessPassword,
                    'MB': opSpec.MB,
                    'WordPtr': opSpec.WordPtr,
                    'WriteDataWordCount': opSpec.WriteDataWordCount,
                    'WriteData': opSpec.WriteData
                }
            })
        elif isinstance(opSpec, C1G2Lock):
            accessSpec['AccessCommand']['OpSpecParameter'].append({
                'C1G2Lock': {
                    'OpSpecID': opSpec.OpSpecID,
                    'AccessPassword': opSpec.AccessPassword,
                    'C1G2LockPayload': [{
                        'Privilege': payload.Privilege,
                        'DataField': payload.DataField
                    } for payload in opSpec.LockPayload]
                }
            })
        else:
            raise LLRPError('Selected opSpec type is not yet supported.')


        logger.debugfast('AccessSpec: %s', accessSpec)

        def add_accessspec_cb(state, is_success, *args):
            if is_success:
                self.send_ENABLE_ACCESSSPEC(state, accessSpecID)
            else:
                self.panic(None, 'ADD_ACCESSSPEC failed')

        self.send_ADD_ACCESSSPEC(accessSpec,
                                 onCompletion=add_accessspec_cb)

    def nextAccess(self, opSpec, targetSpec=None, stopAfterCount=0,
                   accessSpecID=1):
        def start_next_accessspec_cb(state, is_success, *args):
            self.startAccess(opSpec=opSpec,
                             targetSpec=targetSpec,
                             stopAfterCount=stopAfterCount,
                             accessSpecID=accessSpecID)

        def disable_accessspec_cb(state, is_success, *args):
            self.send_DELETE_ACCESSSPEC(accessSpecID,
                                        onCompletion=start_next_accessspec_cb)
            #if not is_success:
            #    self.panic(None, 'DISABLE_ACCESSSPEC failed')

        self.send_DISABLE_ACCESSSPEC(accessSpecID,
                                     onCompletion=disable_accessspec_cb)

    def startInventory(self, force_regen_rospec=False):
        """Add a ROSpec to the reader and enable it."""
        if self.state == LLRPReaderState.STATE_INVENTORYING:
            logger.warn('ignoring startInventory() while already inventorying')
            return None

        rospec = self.getROSpec(force_new=force_regen_rospec)

        logger.info('starting inventory')

        # upside-down chain of callbacks: add, enable, start ROSpec
        # started_rospec = defer.Deferred()
        # started_rospec.addCallback(self._setState_wrapper,
        #                            LLRPReaderState.STATE_INVENTORYING)
        # started_rospec.addErrback(self.panic, 'START_ROSPEC failed')
        # logger.debugfast('made started_rospec')

        def enabled_rospec_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPReaderState.STATE_INVENTORYING)
            else:
                self.panic(None, 'ENABLE_ROSPEC failed')

        logger.debugfast('made enabled_rospec')

        def send_added_rospec_cb(state, is_success, *args):
            if is_success:
                self.send_ENABLE_ROSPEC(state, rospec,
                                        onCompletion=enabled_rospec_cb)
            else:
                self.panic(None, 'ADD_ROSPEC failed')

        logger.debugfast('made added_rospec')

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
            tag_population=config.tag_population,
            frequencies=config.frequencies
        )
        if config.tag_filter_mask is not None:
            rospec_kwargs['tag_filter_mask'] = config.tag_filter_mask
        logger.info('Impinj search mode? %s', config.impinj_search_mode)
        if config.impinj_search_mode is not None:
            rospec_kwargs['impinj_search_mode'] = config.impinj_search_mode
        if config.impinj_tag_content_selector is not None:
            rospec_kwargs['impinj_tag_content_selector'] = \
                config.impinj_tag_content_selector

        self.rospec = LLRPROSpec(self.reader_mode, 1, **rospec_kwargs)
        logger.debugfast('ROSpec:\n%s', self.rospec)
        return self.rospec

    def stopPolitely(self, onCompletion=None, disconnect=False):
        """Delete all active ROSpecs.  Return a Deferred that will be called
           when the DELETE_ROSPEC_RESPONSE comes back."""
        logger.info('stopping politely')
        if disconnect:
            self.disconnecting = True
        self.sendMessage({
            'DELETE_ACCESSSPEC': {
                # all AccessSpecs
                'AccessSpecID': 0,
            }})
        self.setState(LLRPReaderState.STATE_SENT_DELETE_ACCESSSPEC)

        def send_delete_accessspec_cb(state, is_success, *args):
            if is_success:
                self.stopAllROSpecs(onCompletion)
            else:
                self.panic(None, 'DELETE_ACCESSSPEC failed')
                if onCompletion:
                    onCompletion(state, is_success, *args)

        self._deferreds['DELETE_ACCESSSPEC_RESPONSE'].append(
            send_delete_accessspec_cb)

    def stopAllROSpecs(self, onCompletion=None):
        self.sendMessage({
            'DELETE_ROSPEC': {
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

        >>> LLRPReaderState.parsePowerTable({'TransmitPowerLevelTableEntry': \
            {'Index': 1, 'TransmitPowerValue': 3225}})
        [0, 32.25]
        >>> LLRPReaderState.parsePowerTable({})
        [0]
        """
        bandtbl = uhfbandcap['TransmitPowerLevelTableEntry']
        tx_power_table = [0] * (len(bandtbl) + 1)
        for v in bandtbl:
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

        logger.debugfast('requested tx_power: %s', tx_power)
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

    def setTxPowerDbm(self, tx_pow_dbm=None):
        if tx_pow_dbm is None:
            # select max TX power
            ret_tx_power = {ant: self.tx_power_table[-1]
                            for ant in self.config.antennas}
        else:
            ret_config_dbm = {}
            ret_tx_power = {}
            for antid, req_dbm in tx_pow_dbm.items():
                tx_power, real_dbm = find_closest(self.tx_power_table, req_dbm)
                ret_config_dbm[antid] = req_dbm
                ret_tx_power[antid] = tx_power
                logger.debug("Want %.1f dBm output, select %.1f dBm, idx %d",
                             req_dbm, real_dbm, tx_power)
            self.config.tx_power_dbm = ret_config_dbm

        self.setTxPower(ret_tx_power)

    def setTxPower(self, tx_power):
        """Set the transmission power for one or more antennas.

        @param tx_power: index into self.tx_power_table
        """
        tx_pow_validated = self.get_tx_power(tx_power)
        logger.debugfast('tx_pow_validated: %s', tx_pow_validated)
        needs_update = False
        for ant, (tx_pow_idx, tx_pow_dbm) in tx_pow_validated.items():
            if self.config.tx_power[ant] != tx_pow_idx:
                self.config.tx_power[ant] = tx_pow_idx
                needs_update = True

            logger.debugfast('tx_power for antenna %s: %s (%s dBm)', ant,
                         tx_pow_idx, tx_pow_dbm)

        if needs_update and self.state == LLRPReaderState.STATE_INVENTORYING:
            logger.debugfast('changing tx power; will stop politely, then resume')
            def on_politely_stopped_cb(state, is_success, *args):
                if is_success:
                    self.setState(LLRPReaderState.STATE_CONNECTED)
                    self.startInventory(force_regen_rospec=True)
            self.stopPolitely(onCompletion=on_politely_stopped_cb)

    def pause(self, duration_seconds=0, force=False, force_regen_rospec=False):
        """Pause an inventory operation for a set amount of time."""
        logger.debugfast('pause(%s)', duration_seconds)
        # Temporary error until fixed.
        if duration_seconds > 0:
            raise ReaderConfigurationError('"duration_seconds > 0" is not yet'
                                           'implemented for "pause".')
        if self.state != LLRPReaderState.STATE_INVENTORYING:
            if not force:
                logger.info('ignoring pause(); not inventorying (state==%s)',
                            LLRPReaderState.getStateName(self.state))
                return None
            else:
                logger.info('forcing pause()')

        if duration_seconds:
            logger.info('pausing for %s seconds', duration_seconds)

        rospec = self.getROSpec(force_new=force_regen_rospec)

        self.sendMessage({
            'DISABLE_ROSPEC': {
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
        logger.debugfast('resuming, force_regen_rospec=%s', force_regen_rospec)

        if force_regen_rospec:
            self.rospec = self.getROSpec(force_new=True)

        if self.state in (LLRPReaderState.STATE_CONNECTED,
                          LLRPReaderState.STATE_DISCONNECTED):
            logger.debugfast('will startInventory()')
            self.startInventory()
            return

        if self.state != LLRPReaderState.STATE_PAUSED:
            logger.debugfast('cannot resume() if not paused (state=%s); '
                             'ignoring',
                             LLRPReaderState.getStateName(self.state))
            return None

        logger.info('resuming')

        def enable_rospec_resume_cb(state, is_success, *args):
            if is_success:
                self.setState(LLRPReaderState.STATE_INVENTORYING)
            else:
                self.complain(None, 'resume() failed')

        self.send_ENABLE_ROSPEC(None, self.rospec,
                                onCompletion=enable_rospec_resume_cb)

    def sendMessage(self, msg_dict):
        """Serialize and send a dict LLRP Message

        Note: IDs should be modified in original msg_dict as it is a reference.
        That should be ok.
        """
        sent_ids = []
        for name in msg_dict:
            if self.last_msg_id < LLRP_MSG_ID_MAX:
                self.last_msg_id += 1
            else:
                self.last_msg_id = 1
            msg_dict[name]['ID'] = self.last_msg_id
            sent_ids.append((name, self.last_msg_id))
        llrp_msg = LLRPMessage(msgdict=msg_dict)

        assert llrp_msg.msgbytes, "LLRPMessage is empty"
        self.transport_tx_write(llrp_msg.msgbytes)

        return sent_ids


class LLRPReaderConfig(object):
    def __init__(self, config_dict=None):

        self.duration = None
        self.tari = 0
        self.session = 2
        self.mode_identifier = None
        self.tag_population = 4
        self.report_every_n_tags = None
        self.report_timeout_ms = 0
        self.antennas = [1]
        # Use the power associated with an exact tx power index
        self.tx_power = 0
        # Use the power level closest to the requested dbm value
        self.tx_power_dbm = None
        self.disconnect_when_done = self.duration and self.duration > 0
        self.tag_filter_mask = None
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

        self.event_selector = {
            'HoppingEvent': False,
            'GPIEvent': False,
            'ROSpecEvent': False,
            'ReportBufferFillWarning': False,
            'ReaderExceptionEvent': False,
            'RFSurveyEvent': False,
            'AISpecEvent': False,
            'AISpecEventWithSingulation': False,
            'AntennaEvent': False,
        }

        self.frequencies = {
            'HopTableId': DEFAULT_HOPTABLE_INDEX,
            'Channelist': [DEFAULT_CHANNEL_INDEX],
            'Automatic': False
        }

        self.reconnect = False
        self.start_inventory = True
        self.reset_on_connect = True

        ## Extensions specific
        self.impinj_extended_configuration = False
        self.impinj_search_mode = None
        self.impinj_reports = False
        self.impinj_tag_content_selector = None
        self.impinj_event_selector = None

        self.keepalive_interval = 60 * 1000  # in ms, 0 = nokeepalive request sent to reader
        self.reconnect_retries = 5
        ## If impinj extension, would be like:
        #self.impinj_tag_content_selector = {
        #    'EnableRFPhaseAngle': True,
        #    'EnablePeakRSSI': False,
        #    'EnableRFDopplerFrequency': False
        #}
        #self.impinj_event_selector = {
        #    'AntennaAttemptEvent': False
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
        if hasattr(self, 'tx_power_dbm') and \
           self.tx_power_dbm is not None:
            if isinstance(self.tx_power_dbm, float):
                self.tx_power_dbm = {ant: self.tx_power_dbm
                                     for ant in self.antennas}
            elif isinstance(self.tx_power_dbm, dict):
                if set(self.antennas) != set(self.tx_power_dbm.keys()):
                    raise LLRPError('Must specify tx_power for each antenna')
            else:
                raise LLRPError('tx_power must be dict or float')

class LLRPReaderClient(object):
    def __init__(self, host, port=None, config=None, timeout=5.0):
        global all_reader_refs

        if port is None:
            port = LLRP_DEFAULT_PORT
        self._port = port
        self._host = host
        self._socktimeout = timeout

        self._socket = None
        self._socket_thread = None
        # Needed?
        self.disconnect_requested = Event()
        self._stop_main_loop = Event()

        # for partial data transfers
        self.expected_bytes = 0
        self.partial_data = b''

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
        self._event_notification_callbacks = []
        self._disconnected_callbacks = []

        all_reader_refs.add(self)

    def update_config(self, new_config):
        """Update ReaderClient's config

        Not completly safe, to be used with caution.
        """
        self.config = new_config
        if self.llrp:
            self.llrp.update_config(new_config)

    def get_peername(self):
        return (self._host, self._port)

    def add_state_callback(self, state, cb):
        """Add a callback to run upon a state transition.

        When an LLRPReaderState enters `state`, `cb()` will be called.

        Args:
            state: A state from LLRPReaderState.STATE_*.
            cb: A callable that takes an LLRPReaderState argument.
        """
        if cb not in self._llrp_state_callbacks[state]:
            self._llrp_state_callbacks[state].append(cb)

    def remove_state_callback(self, state, cb):
        if cb in self._llrp_state_callbacks[state]:
            self._llrp_state_callbacks[state].remove(cb)

    def clear_state_callback(self, state):
        if state in self._llrp_state_callbacks:
            self._llrp_state_callbacks[state] = []
        else:
            self._llrp_message_callbacks = defaultdict(list)


    def add_message_callback(self, msg_type, cb):
        if cb not in self._llrp_message_callbacks[msg_type]:
            self._llrp_message_callbacks[msg_type].append(cb)

    def remove_message_callback(self, msg_type, cb):
        if cb in self._llrp_message_callbacks[msg_type]:
            self._llrp_message_callbacks[msg_type].remove(cb)

    def clear_message_callback(self, msg_type=None):
        if msg_type:
            self._llrp_message_callbacks[msg_type] = []
        else:
            self._llrp_message_callbacks = defaultdict(list)


    def add_tag_report_callback(self, cb):
        if not self._llrp_message_callbacks['RO_ACCESS_REPORT']:
            self._llrp_message_callbacks['RO_ACCESS_REPORT'].append(
                self._on_llrp_tag_report)

        if cb not in self._tag_report_callbacks:
            self._tag_report_callbacks.append(cb)

    def remove_tag_report_callback(self, cb):
        if cb in self._tag_report_callbacks:
            self._tag_report_callbacks.remove(cb)

    def clear_tag_report_callback(self, cb):
        self._tag_report_callbacks = []

    def add_event_callback(self, cb):
        if not self._llrp_message_callbacks['READER_EVENT_NOTIFICATION']:
            self._llrp_message_callbacks['READER_EVENT_NOTIFICATION'].append(
                self._on_llrp_event_notification)

        if cb not in self._event_notification_callbacks:
            self._event_notification_callbacks.append(cb)

    def remove_event_callback(self, cb):
        if cb in self._event_notification_callbacks:
            self._event_notification_callbacks.remove(cb)

    def clear_event_callback(self, cb):
        self._event_notification_callbacks = []

    def add_disconnected_callback(self, cb):
        if cb not in self._disconnected_callbacks:
            self._disconnected_callbacks.append(cb)

    def remove_disconnected_callback(self, cb):
        if cb in self._disconnected_callbacks:
            self._disconnected_callbacks.remove(cb)

    def clear_disconnected_callback(self, cb):
        self._disconnected_callbacks = []

    def _connect_socket(self):
        if self._socket:
            raise ReaderConfigurationError('Already connected')
        try:
            self._socket = socket(AF_INET, SOCK_STREAM)
            # Sllurp original timeout is 3s
            self._socket.settimeout(self._socktimeout)
            self._socket.connect((self._host, self._port))
            self._socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
            self._socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
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
        self._socket_thread = Thread(target=self.main_loop,
                                     name="-".join([THREAD_NAME_PREFIX,
                                                   str(self._host),
                                                   str(self._port)]))
        self._socket_thread.start()

    def disconnect(self, timeout=0):
        """Clean the reader before disconnecting

        By default, disconnect is "non-blocking".
        Timeout argument can be set to have a "blocking" disconnect behavior.
        When the timeout argument is present and not 0 or None, it should be a
        floating point number specifying a timeout for the operation in seconds
        (or fractions thereof).
        When the timeout argument is None, the operation will block until
        the reader connection thread terminates.
        """
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
        # Block until disconnection is completed if needed
        if timeout != 0:
            self.join(timeout)

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

    @staticmethod
    def disconnect_all_readers(timeout_per_reader=1, force=True):
        """Disconnect all readers that are connected

        timeout_per_reader: How long to wait in (s)econds for gracefull shutdown
        force: if True, a Hard shutdown of the connection is done if the gracefull
        shutdown does not finish after "timeout_per_reader".
        """
        # Ask politely first any remaining active reader to stop
        for reader in all_reader_refs:
            try:
                if reader is None:
                    continue
                if not reader.disconnect_requested.is_set():
                    reader.disconnect()
            except:
                pass

        # Be patient...
        for reader in all_reader_refs:
            try:
                reader.join(timeout_per_reader)
            except:
                pass

        if force:
            # Go nuclear to reader instances that would still be connected.
            for reader in all_reader_refs:
                try:
                    reader.hard_disconnect()
                except:
                    pass

    def on_lost_connection(self):
        """ On lost connection, attempt retries if reconnect enabled

        Return: True if the connection is definitively lost/interrupted.
                False if it was somehow recovered (reconnected).
        """
        remaining_attempts = self.config.reconnect_retries
        retry_delay = 60 # seconds

        logger.info('Lost connection detected')
        # When the connection is lost, reset the reader known state
        # so, rospec and config will be restored in case of
        # reconnection
        if self.llrp:
            self.llrp.setState(LLRPReaderState.STATE_DISCONNECTED)

        if self.disconnect_requested.is_set():
            return True

        try:
            self.hard_disconnect()
        except:
            logger.exception("hard_disconnect error in lost connection")

        if not self.config.reconnect:
            self._on_disconnected()
            return True

        while remaining_attempts:
            try:
                self._connect_socket()
                return False
            except:
                logger.warning('Reconnection attempt failed.')
            if remaining_attempts > 0:
                remaining_attempts -= 1
            if remaining_attempts == 0:
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
        """ Return whether the reader connection thread is alive.

        Similar API as the threading module is_alive function.
        """
        if self._socket_thread:
            return self._socket_thread.is_alive()
        return False

    def join(self, timeout=None):
        """ Wait until the reader connection thread terminates.

        Similar API as the threading module is_alive function.
        When the timeout argument is present and not None, it should be a
        floating point number specifying a timeout for the operation in seconds
        (or fractions thereof).
        When the timeout argument is not present or None, the operation will
        block until the reader connection thread terminates.
        """
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
                read_sockets, write_sockets, error_sockets = \
                    select.select(socket_list, [], [])
                for sock in read_sockets:
                    # Incoming message from remote server
                    if sock == self._socket:
                        try:
                            data = sock.recv(4096)
                            if data:
                                self.raw_data_received(data)
                            else:
                                # Zero byte received == disconnected
                                logger.warning('\nDisconnected from server')
                                lost_connection = True
                        except SocketError:
                            logger.exception('\nDisconnected from server')
                            lost_connection = True
                        except ReaderConfigurationError:
                            # A fatal configuration error was encountered with
                            # the reader, abort the connection
                            self.hard_disconnect()
                            self._on_disconnected()
                            logger.error("\nDisconnected because of a reader "
                                         "configuration error")

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

    def raw_data_received(self, data):
        data_len = len(data)
        if is_general_debug_enabled():
            logger.debugfast('got %d bytes from reader: %s', data_len,
                             hexlify(data))

        if self.expected_bytes:
            self.partial_data += data
            data = self.partial_data
            data_len = len(data)
            if data_len < self.expected_bytes:
                # still not enough; wait until next time
                return

        start_pos = 0
        while data_len > 0:
            # parse the message header to grab its length
            if data_len >= msg_header_len:
                msg_type, msg_len, message_id = msg_header_unpack(
                    data[start_pos:start_pos + msg_header_len])
            else:
                logger.warning('Too few bytes (%d) to unpack message header',
                               data_len)
                self.partial_data = data[start_pos:]
                self.expected_bytes = msg_header_len
                break

            logger.debugfast('expect %d bytes (have %d)', msg_len, data_len)

            if data_len < msg_len:
                # got too few bytes
                self.partial_data = data[start_pos:]
                self.expected_bytes = msg_len
                break
            else:
                # got at least the right number of bytes
                self.expected_bytes = 0
                try:
                    lmsg = LLRPMessage(
                        msgbytes=data[start_pos:start_pos + msg_len])
                    self._on_llrp_message_received(lmsg)
                    self.llrp.handleMessage(lmsg)
                    start_pos += msg_len
                    data_len -= msg_len
                except ReaderConfigurationError:
                    raise
                except LLRPError:
                    logger.exception('Failed to decode LLRPMessage; '
                                     'will not decode %d remaining bytes',
                                     data_len)
                    break
        if self.expected_bytes <= 0:
            self.partial_data = b''

    def start_access_spec(self, op_spec, target_spec=None, stop_after_count=0,
                          access_spec_id=1):
        """Add and start a AccessOpSpec command

        stop_after_count=N: (AccessSpecStopTriggerType) Stop the access spec
            after N executions of the spec. N=0 to define no stop trigger.
        """
        if not isinstance(op_spec, C1G2OpSpec):
            raise ValueError("op_spec needs to be a valid C1G2OpSpec object")

        if target_spec and not isinstance(target_spec, C1G2TargetTag):
            raise ValueError("target_spec needs to be a valid C1G2TargetTag "
                             "object")

        if stop_after_count < 0:
            stop_after_count = 0

        self.llrp.startAccess(opSpec=op_spec,
                              targetSpec=target_spec,
                              stopAfterCount=stop_after_count,
                              accessSpecID=access_spec_id)

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
        logger.debugfast('starting message callbacks for %s', msgName)
        for fn in self._llrp_message_callbacks[msgName]:
            try:
                fn(self, lmsg)
            except:
                logger.exception("Error during message callback execution. "
                                 "Continuing anyway...")
        logger.debugfast('done with message callbacks for %s', msgName)

    def _on_llrp_tag_report(self, _, lmsg):
        tags_report_dict = lmsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
        for fn in self._tag_report_callbacks:
            try:
                fn(self, tags_report_dict)
            except:
                logger.exception("Error during user on_llrp_tag_report "
                                 "callback. Continuing anyway...")

    def _on_llrp_event_notification(self, _, lmsg):
        event_data_dict = lmsg.msgdict[
            'READER_EVENT_NOTIFICATION']['ReaderEventNotificationData']
        for fn in self._event_notification_callbacks:
            try:
                fn(self, event_data_dict)
            except:
                logger.exception("Error during user _on_llrp_event_notification"
                                 "callback. Continuing anyway...")
