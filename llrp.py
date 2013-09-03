from __future__ import print_function
import time
import socket
import logging
import struct
import asyncore
import Queue
from threading import Thread, Condition
from llrp_proto import LLRPROSpec, LLRPError, Message_struct, Message_Type2Name
import copy
from util import *

LLRP_PORT = 5084

class LLRPMessage:
    hdr_fmt = '!HI'
    hdr_len = struct.calcsize(hdr_fmt)
    full_hdr_fmt = hdr_fmt + 'I'
    full_hdr_len = struct.calcsize(full_hdr_fmt)
    msgdict = None
    msgbytes = None

    def __init__ (self, msgdict=None, msgbytes=None):
        if not (msgdict or msgbytes):
            raise LLRPError('Provide either a message dict or a sequence' \
                    ' of bytes.')
        if msgdict:
            self.msgdict = dict(msgdict)
        if msgbytes:
            self.msgbytes = copy.copy(msgbytes)

    def serialize (self):
        if self.msgdict is None:
            raise LLRPError('No message dict to serialize.')
        name = self.msgdict.keys()[0]
        logging.debug('serializing {} command'.format(name))
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
        logging.debug('serialized bytes: {}'.format(hexlify(self.msgbytes)))
        logging.debug('done serializing {} command'.format(name))
        return self.msgbytes

    def deserialize (self):
        if self.msgbytes is None:
            raise LLRPError('No message bytes to deserialize.')
        data = ''.join(self.msgbytes)
        msgtype, length, msgid = struct.unpack(self.full_hdr_fmt,
                data[:self.full_hdr_len])
        ver = (msgtype >> 10) & BITMASK(3)
        msgtype = msgtype & BITMASK(10)
        try:
            name = Message_Type2Name[msgtype]
            logging.debug('deserializing {} command'.format(name))
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
        except LLRPError as e:
            logging.warning('Problem with {} message format: {}'.format(name, e))
        logging.debug('done deserializing {} command'.format(name))
        return self.msgdict

class LLRPDispatcher (asyncore.dispatcher):
    """ Simply manage sending and receiving the contents of incoming & outgoing
        message queues.
    """
    inqueue = None
    outqueue = None

    def __init__ (self, host, port, inqueue, outqueue):
        asyncore.dispatcher.__init__(self)
        self.inqueue = inqueue
        self.outqueue = outqueue
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        msgbytes = self.recv(LLRPMessage.hdr_len)
        bytes_read = len(msgbytes)
        ty, length = struct.unpack(LLRPMessage.hdr_fmt, msgbytes)
        to_read = length - LLRPMessage.hdr_len
        while (bytes_read < to_read):
            bs = self.recv(to_read)
            bytes_read += len(bs)
            msgbytes += bs
        logging.debug('Got {} bytes from reader: {}'.format(bytes_read, hexlify(msgbytes)))
        self.inqueue.put(LLRPMessage(msgbytes=msgbytes).deserialize())

    def writable(self):
        return not self.outqueue.empty()

    def handle_write(self):
        while True:
            try:
                (pri, msg) = self.outqueue.get_nowait()
                self.send(msg.serialize())
            except Queue.Empty:
                break

class LLRPReaderThread (Thread):
    """ Thread object that connects input and output message queues to a socket
        (which is managed by an LLRPDispatcher)."""
    inq = Queue.PriorityQueue()
    outq = Queue.PriorityQueue()

    def __init__ (self, host, port):
        super(LLRPReaderThread, self).__init__()
        dispatcher = LLRPDispatcher(host, port, self.inq, self.outq)
    def run (self):
        asyncore.loop()

