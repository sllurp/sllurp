from __future__ import print_function
from collections import defaultdict
import time
import socket
import logging
import pprint
import struct
from threading import Thread, Condition
from llrp_proto import LLRPROSpec, LLRPError, Message_struct, \
         Message_Type2Name, llrp_data2xml, LLRPMessageDict
import copy
from util import *
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientCreator, \
         ClientFactory, ReconnectingClientFactory
from twisted.internet.error import ReactorAlreadyRunning

LLRP_PORT = 5084

logger = logging.getLogger('sllurp')

class LLRPMessage:
    hdr_fmt = '!HI'
    hdr_len = struct.calcsize(hdr_fmt) # == 6 bytes
    full_hdr_fmt = hdr_fmt + 'I'
    full_hdr_len = struct.calcsize(full_hdr_fmt) # == 10 bytes
    msgdict = None
    msgbytes = None
    remainder = None

    def __init__ (self, msgdict=None, msgbytes=None):
        if not (msgdict or msgbytes):
            raise LLRPError('Provide either a message dict or a sequence' \
                    ' of bytes.')
        if msgdict:
            self.msgdict = LLRPMessageDict(msgdict)
            if not msgbytes:
                self.serialize()
        if msgbytes:
            self.msgbytes = copy.copy(msgbytes)
            if not msgdict:
                self.remainder = self.deserialize()

    def serialize (self):
        if self.msgdict is None:
            raise LLRPError('No message dict to serialize.')
        name = self.msgdict.keys()[0]
        logger.debug('serializing {} command'.format(name))
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
        logger.debug('serialized bytes: {}'.format(hexlify(self.msgbytes)))
        logger.debug('done serializing {} command'.format(name))

    def deserialize (self):
        """Turns a sequence of bytes into a message dictionary.  Any leftover
        data in the sequence is returned as the remainder."""
        if self.msgbytes is None:
            raise LLRPError('No message bytes to deserialize.')
        data = ''.join(self.msgbytes)
        remainder = ''
        msgtype, length, msgid = struct.unpack(self.full_hdr_fmt,
                data[:self.full_hdr_len])
        ver = (msgtype >> 10) & BITMASK(3)
        msgtype = msgtype & BITMASK(10)
        try:
            name = Message_Type2Name[msgtype]
            logger.debug('deserializing {} command'.format(name))
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
            logger.debug('done deserializing {} command'.format(name))
        except LLRPError as e:
            logger.warning('Problem with {} message format: {}'.format(name, e))
            return ''
        if length < len(data):
            remainder = data[length:]
            logger.debug('{} bytes of data remaining'.format(len(remainder)))
            return remainder
        return ''

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

class LLRPClient (Protocol):
    STATE_DISCONNECTED = 1
    STATE_CONNECTING = 2
    STATE_CONNECTED = 3
    STATE_SENT_ADD_ROSPEC = 4
    STATE_SENT_ENABLE_ROSPEC = 5
    STATE_INVENTORYING = 6
    STATE_SENT_DELETE_ROSPEC = 7

    def __init__ (self, duration=None, report_every_n_tags=None, antennas=(1,),
            start_inventory=True, disconnect_when_done=True, standalone=False):
        self.state = LLRPClient.STATE_DISCONNECTED
        e = self.eventCallbacks = defaultdict(list)
        e['READER_EVENT_NOTIFICATION'].append(self.readerEventCallback)
        self.rospec = None
        self.report_every_n_tags = report_every_n_tags
        self.antennas = antennas
        self.duration = duration
        self.start_inventory = start_inventory
        self.disconnect_when_done = disconnect_when_done
        self.standalone = standalone

    def readerEventCallback (self, llrpMsg):
        """Function to handle ReaderEventNotification messages from the reader."""
        logger.info('got READER_EVENT_NOTIFICATION')
        d = llrpMsg.msgdict['READER_EVENT_NOTIFICATION']\
                ['ReaderEventNotificationData']

        # figure out whether there was an AntennaEvent
        try:
            antev = d['AntennaEvent']
            # TODO: reconcile antenna events against list of antennas
        except KeyError:
            pass

    def connectionMade(self):
        logger.debug('socket connected')

    def connectionLost(self, reason):
        logger.debug('reader disconnected: {}'.format(reason))
        self.state = LLRPClient.STATE_DISCONNECTED
        if self.standalone:
            reactor.callFromThread(reactor.stop)

    def addEventCallbacks (self, callbacks):
        self.eventCallbacks.update(callbacks)

    def handleMessage (self, lmsg):
        """Implements the LLRP client state machine."""
        logger.debug('LLRPMessage received in state {}: {}'.format(self.state,
                    lmsg))
        msgName = lmsg.getName()
        ret = lmsg.remainder
        logger.debug('remaining bytes: {}'.format(len(ret)))

        if msgName == 'RO_ACCESS_REPORT' and \
                    self.state != LLRPClient.STATE_INVENTORYING:
            logger.debug('ignoring RO_ACCESS_REPORT because not inventorying')
            return ret

        run_callbacks = True

        #######
        # LLRP client state machine follows.  Beware: gets thorny.  Note the
        # order of the LLRPClient.STATE_* fields.
        #######

        # in DISCONNECTED, CONNECTING, and CONNECTED states, expect only
        # READER_EVENT_NOTIFICATION messages.
        if self.state in (LLRPClient.STATE_DISCONNECTED,
                LLRPClient.STATE_CONNECTING):
            if msgName == 'READER_EVENT_NOTIFICATION':
                d = lmsg.msgdict['READER_EVENT_NOTIFICATION']\
                        ['ReaderEventNotificationData']
                # figure out whether the connection was successful
                try:
                    status = d['ConnectionAttemptEvent']['Status']
                    if status == 'Success':
                        self.state = LLRPClient.STATE_CONNECTED
                        if self.start_inventory:
                            self.startInventory()
                    else:
                        logger.fatal('Could not start session on reader: ' \
                                '{}'.format(status))
                        self.transport.loseConnection()
                except KeyError:
                    pass
            else:
                logger.error('unexpected message {} while' \
                        ' connecting'.format(msgName))
                run_callbacks = False

        # in state SENT_ADD_ROSPEC, expect only ADD_ROSPEC_RESPONSE; respond to
        # favorable ADD_ROSPEC_RESPONSE by enabling the added ROSpec and
        # advancing to state SENT_ENABLE_ROSPEC.
        elif self.state == LLRPClient.STATE_SENT_ADD_ROSPEC:
            if msgName == 'ADD_ROSPEC_RESPONSE':
                d = lmsg.msgdict['ADD_ROSPEC_RESPONSE']
                if d['LLRPStatus']['StatusCode'] == 'Success':
                    self.sendLLRPMessage(LLRPMessage(msgdict={
                        'ENABLE_ROSPEC': {
                            'Ver':  1,
                            'Type': 24,
                            'ID':   0,
                            'ROSpecID': self.roSpecId
                        }}))
                    self.state = LLRPClient.STATE_SENT_ENABLE_ROSPEC
                else:
                    logger.warn('ADD_ROSPEC failed with status {}: {}' \
                            .format(d['LLRPStatus']['StatusCode'],
                                d['LLRPStatus']['ErrorDescription']))
                    run_callbacks = False
                    self.stopPolitely()
            else:
                logger.error('unexpected response {} ' \
                        ' when adding ROSpec'.format(msgName))
                run_callbacks = False

        # in state SENT_ENABLE_ROSPEC, expect only ENABLE_ROSPEC_RESPONSE;
        # respond to favorable ENABLE_ROSPEC_RESPONSE by starting the enabled
        # ROSpec and advancing to state INVENTORYING.
        elif self.state == LLRPClient.STATE_SENT_ENABLE_ROSPEC:
            if msgName == 'ENABLE_ROSPEC_RESPONSE':
                d = lmsg.msgdict['ENABLE_ROSPEC_RESPONSE']
                if d['LLRPStatus']['StatusCode'] == 'Success':
                    logger.info('starting inventory')
                    self.state = LLRPClient.STATE_INVENTORYING
                    if self.duration:
                        reactor.callFromThread(reactor.callLater, self.duration,
                                self.stopPolitely)
                else:
                    logger.warn('ENABLE_ROSPEC failed with status {}: {}' \
                            .format(d['LLRPStatus']['StatusCode'],
                                d['LLRPStatus']['ErrorDescription']))
                    run_callbacks = False
                    self.stopPolitely()
            else:
                logger.error('unexpected response {} ' \
                        ' when enabling ROSpec'.format(msgName))
                run_callbacks = False

        elif self.state == LLRPClient.STATE_INVENTORYING:
            if msgName not in ('RO_ACCESS_REPORT', 'READER_EVENT_NOTIFICATION'):
                logger.error('unexpected message {} while' \
                        ' inventorying'.format(msgName))
                run_callbacks = False

        elif self.state == LLRPClient.STATE_SENT_DELETE_ROSPEC:
            if msgName == 'DELETE_ROSPEC_RESPONSE':
                d = lmsg.msgdict['DELETE_ROSPEC_RESPONSE']
                if d['LLRPStatus']['StatusCode'] == 'Success':
                    logger.info('reader finished inventory')
                    self.state = LLRPClient.STATE_DISCONNECTED
                    if self.disconnect_when_done:
                        self.transport.loseConnection()
                else:
                    logger.warn('DELETE_ROSPEC failed with status {}: {}' \
                            .format(d['LLRPStatus']['StatusCode'],
                                d['LLRPStatus']['ErrorDescription']))
                    run_callbacks = False
                    logger.info('disconnecting')

                    # no use trying to stop politely if DELETE_ROSPEC has
                    # already failed...
                    self.transport.loseConnection()
            else:
                logger.error('unexpected response {} ' \
                        ' when deleting ROSpec'.format(msgName))
                run_callbacks = False

        if run_callbacks:
            for fn in self.eventCallbacks[msgName]:
                fn(lmsg)

        return ret

    def dataReceived (self, data):
        logger.debug('got {} bytes from reader: {}'.format(len(data),
                    data.encode('hex')))
        try:
            while data:
                lmsg = LLRPMessage(msgbytes=data)
                data = self.handleMessage(lmsg)
        except LLRPError as err:
            logger.warn('Failed to decode LLRPMessage: {}.  Will not decode' \
                    ' {} remaining bytes'.format(err, len(data)))

    def startInventory (self):
        if not self.rospec:
            self.create_rospec()
        r = self.rospec['ROSpec']
        self.roSpecId = r['ROSpecID']

        # add an ROspec
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'ADD_ROSPEC': {
                'Ver':  1,
                'Type': 20,
                'ID':   0,
                'ROSpecID': self.roSpecId,
                'ROSpec': r,
            }}))
        self.state = LLRPClient.STATE_SENT_ADD_ROSPEC

    def create_rospec (self):
        if self.rospec:
            return
        # create an ROSpec, which defines the reader's inventorying
        # behavior, and start running it on the reader
        self.rospec = LLRPROSpec(1, duration_sec=self.duration,
                report_every_n_tags=self.report_every_n_tags,
                antennas=self.antennas)
        logger.debug('ROSpec: {}'.format(self.rospec))

    def stopPolitely (self):
        """Delete all active ROSpecs."""
        logger.info('stopping politely')
        self.sendLLRPMessage(LLRPMessage(msgdict={
            'DELETE_ROSPEC': {
                'Ver':  1,
                'Type': 21,
                'ID':   0,
                'ROSpecID': 0
            }}))
        self.state = LLRPClient.STATE_SENT_DELETE_ROSPEC

    def sendLLRPMessage (self, llrp_msg):
        reactor.callFromThread(self.sendMessage, llrp_msg.msgbytes)

    def sendMessage (self, msg):
        self.transport.write(msg)

class LLRPClientFactory (ClientFactory):
    def __init__ (self, parent, callbacks, **kwargs):
        self.callbacks = callbacks
        self.client_args = kwargs

    def startedConnecting(self, connector):
        logger.info('connecting...')

    def buildProtocol(self, addr):
        c = LLRPClient(**self.client_args)
        c.addEventCallbacks(self.callbacks)
        return c

    def clientConnectionLost(self, connector, reason):
        logger.info('lost connection: {}'.format(reason))
        ClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        logger.info('connection failed: {}'.format(reason))
        ClientFactory.clientConnectionFailed(self, connector, reason)

class LLRPReconnectingClientFactory (ReconnectingClientFactory,
        LLRPClientFactory):
    """TODO: fix me."""
    pass

class LLRPReaderThread (Thread):
    """ Thread object that connects input and output message queues to a
        socket."""
    rospec = None
    host = None
    port = None
    callbacks = defaultdict(list)

    def __init__ (self, host, port=LLRP_PORT, **kwargs):
        super(LLRPReaderThread, self).__init__()
        self.host = host
        self.port = port
        self.inventory_params = dict(kwargs)

    def run (self):
        logger.debug('will connect to {}:{}'.format(self.host, self.port))
        client_factory = LLRPClientFactory(self, self.callbacks,
                **self.inventory_params)
        reactor.connectTCP(self.host, self.port, client_factory)
        try:
            if self.inventory_params['standalone']:
                reactor.run(False)
        except KeyError:
            pass
        except ReactorAlreadyRunning:
            logger.warn('standalone=True but reactor was already running')

    def start_inventory (self):
        if not self.protocol:
            logger.warn('start_inventory called on disconnected client')
            return
        self.protocol.startInventory()

    def stop_inventory (self, _):
        if not self.protocol:
            logger.warn('stop_inventory called on disconnected client')
            return
        self.protocol.stopPolitely()

    def addCallback (self, eventName, eventCb):
        self.callbacks[eventName].append(eventCb)

    def disconnect (self):
        logger.debug('stopping reactor')
        reactor.callFromThread(reactor.stop)
