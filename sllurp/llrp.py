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
from twisted.internet.protocol import Protocol, ClientCreator
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
    STATE_CONNECTED = 2
    STATE_INVENTORYING = 3

    def __init__ (self):
        self.state = LLRPClient.STATE_DISCONNECTED
        e = self.eventCallbacks = defaultdict(list)
        e['READER_EVENT_NOTIFICATION'].append(self.readerEventCallback)

    def readerEventCallback (self, llrpMsg):
        """Function to handle ReaderEventNotification messages from the reader."""
        logger.info('got READER_EVENT_NOTIFICATION')
        d = llrpMsg.msgdict['READER_EVENT_NOTIFICATION']\
                ['ReaderEventNotificationData']

        # figure out whether the connection was successful
        try:
            status = d['ConnectionAttemptEvent']['Status']
            if status == 'Success':
                self.state = LLRPClient.STATE_CONNECTED
            else:
                logger.fatal('Could not start session on reader: ' \
                        '{}'.format(status))
                self.transport.loseConnection()
        except KeyError:
            pass

        # figure out whether there was an AntennaEvent
        try:
            antev = d['AntennaEvent']
            # TODO: reconcile antenna events against list of antennas
        except KeyError:
            pass

    def connectionMade(self):
        logger.debug('socket connected')

    def connectionLost(self, reason):
        logger.debug('socket closed: {}'.format(reason))
        self.state = LLRPClient.STATE_DISCONNECTED

    def addEventCallbacks (self, callbacks):
        self.eventCallbacks.update(callbacks)

    def dataReceived (self, data):
        logger.debug('Got {} bytes from reader: {}'.format(len(data),
                    data.encode('hex')))
        try:
            while data:
                lmsg = LLRPMessage(msgbytes=data)
                logger.debug('LLRPMessage received: {}'.format(lmsg))
                msgName = lmsg.getName()
                if msgName == 'RO_ACCESS_REPORT' and \
                            self.state != LLRPClient.STATE_INVENTORYING:
                    logger.debug('ignoring RO_ACCESS_REPORT because not' \
                            ' currently inventorying')
                else:
                    for fn in self.eventCallbacks[msgName]:
                        fn(lmsg)
                logger.debug('remaining bytes: {}'.format(len(lmsg.remainder)))
                if not lmsg.remainder:
                    break
                data = lmsg.remainder # remaining bytes
        except LLRPError as err:
            logger.warn('Failed to decode LLRPMessage: {}'.format(err))

    def sendLLRPMessage (self, llrp_msg):
        reactor.callFromThread(self.sendMessage, llrp_msg.msgbytes)

    def sendMessage (self, msg):
        self.transport.write(msg)

class LLRPReaderThread (Thread):
    """ Thread object that connects input and output message queues to a
        socket."""
    rospec = None
    host = None
    port = None
    protocol = None
    callbacks = defaultdict(list)

    def __init__ (self, host, port=LLRP_PORT):
        super(LLRPReaderThread, self).__init__()
        self.host = host
        self.port = port

    def cbConnected (self, connectedProtocol):
        logger.info('Connected to {}:{}'.format(self.host, self.port))
        self.protocol = connectedProtocol
        self.protocol.addEventCallbacks(self.callbacks)

    def ebConnectError (self, reason):
        logger.debug('Connection error: {}'.format(reason))
        pass

    def run (self):
        logger.debug('Will connect to {}:{}'.format(self.host, self.port))
        cc = ClientCreator(reactor, LLRPClient)
        whenConnected = cc.connectTCP(self.host, self.port)
        whenConnected.addCallbacks(self.cbConnected, self.ebConnectError)
        try:
            reactor.run(False)
        except ReactorAlreadyRunning:
            pass

    def addCallback (self, eventName, eventCb):
        self.callbacks[eventName].append(eventCb)

    # XXX move this to LLRPClient
    def start_inventory (self, delay=1, duration=None, report_every_n_tags=None,
            antennas=(1,)):
        "Start the reader inventorying."
        if not self.protocol:
            time.sleep(delay)
            if not self.protocol:
                logger.error('no LLRP connection after {} seconds'.format(delay))
                return
        if not self.rospec:
            # create an ROSpec, which defines the reader's inventorying
            # behavior, and start running it on the reader
            self.rospec = LLRPROSpec(1, duration_sec=duration,
                    report_every_n_tags=report_every_n_tags,
                    antennas=antennas)
            logger.debug('ROSpec: {}'.format(self.rospec))

        r = self.rospec['ROSpec']
        roSpecId = r['ROSpecID']

        # add an ROspec
        self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
            'ADD_ROSPEC': {
                'Ver':  1,
                'Type': 20,
                'ID':   0,
                'ROSpecID': roSpecId,
                'ROSpec': r,
            }}))

        # enable the ROspec
        self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
            'ENABLE_ROSPEC': {
                'Ver':  1,
                'Type': 24,
                'ID':   0,
                'ROSpecID': roSpecId
            }}))

        rt = r['ROBoundarySpec']['ROSpecStartTrigger']
        if rt['ROSpecStartTriggerType'] != 'Immediate':
            # start the ROspec
            self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
                'START_ROSPEC': {
                    'Ver':  1,
                    'Type': 22,
                    'ID':   0,
                    'ROSpecID': roSpecId
                }}))

    def delete_all_rospecs (self):
        """Delete all active ROSpecs."""
        self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
            'DELETE_ROSPEC': {
                'Ver':  1,
                'Type': 21,
                'ID':   0,
                'ROSpecID': 0
            }}))

        logger.debug('waiting 3 seconds reader to delete all ROSpecs...')
        time.sleep(3)

    def stop_inventory (self):
        "Stop the reader from inventorying."
        if not self.protocol:
            return
        if not self.rospec:
            return

        roSpecId = self.rospec['ROSpec']['ROSpecID']

        # stop the ROspec
        self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
            'STOP_ROSPEC': {
                'Ver':  1,
                'Type': 23,
                'ID':   0,
                'ROSpecID': roSpecId
            }}))

        # disable the ROspec
        self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
            'DISABLE_ROSPEC': {
                'Ver':  1,
                'Type': 25,
                'ID':   0,
                'ROSpecID': roSpecId
            }}))

        # delete the ROspec
        self.protocol.sendLLRPMessage(LLRPMessage(msgdict={
            'DELETE_ROSPEC': {
                'Ver':  1,
                'Type': 21,
                'ID':   0,
                'ROSpecID': roSpecId
            }}))

        logger.debug('waiting 3 seconds for inventory to stop...')
        time.sleep(3)

    def disconnect (self):
        logger.debug('stopping reactor')
        reactor.callFromThread(reactor.stop)
