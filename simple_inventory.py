#!/usr/bin/env python

from __future__ import print_function
import time
import logging
import Queue
from llrp import LLRPReaderThread, LLRPMessage
from llrp_proto import LLRPROSpec
import sys
from util import *

logging.basicConfig(level=logging.DEBUG)

def main():
    rv = LLRPReaderThread(sys.argv[1], 5084)
    rv.setDaemon(True)

    inq = rv.inq # put messages in here
    outq = rv.outq # collect messages from here

    rv.start()

    # add an ROspec
    time.sleep(1)
    rospec = LLRPROSpec(1)
    outq.put((0, LLRPMessage(msgdict={
        'ADD_ROSPEC': {
            'Ver':  1,
            'Type': 20,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
            'ROSpec': rospec['ROSpec'],
        }})))

    # enable the ROspec
    time.sleep(1)
    outq.put((0, LLRPMessage(msgdict={
        'ENABLE_ROSPEC': {
            'Ver':  1,
            'Type': 24,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    # start the ROspec
    time.sleep(1)
    outq.put((0, LLRPMessage(msgdict={
        'START_ROSPEC': {
            'Ver':  1,
            'Type': 22,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    time.sleep(30)

    # stop the ROspec
    time.sleep(1)
    outq.put((0, LLRPMessage(msgdict={
        'STOP_ROSPEC': {
            'Ver':  1,
            'Type': 23,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    # stop the ROspec
    time.sleep(1)
    outq.put((0, LLRPMessage(msgdict={
        'DISABLE_ROSPEC': {
            'Ver':  1,
            'Type': 25,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    # delete the ROspec
    time.sleep(1)
    outq.put((0, LLRPMessage(msgdict={
        'DELETE_ROSPEC': {
            'Ver':  1,
            'Type': 21,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    logging.debug('Size of inq: {}'.format(inq.qsize()))
    while True:
        try:
            print(inq.get(timeout=5))
        except Queue.Empty:
            break

if __name__ == '__main__':
    main()
