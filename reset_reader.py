#!/usr/bin/env python

from __future__ import print_function
import time
import logging
import Queue
import llrp
from llrp_proto import LLRPROSpec
import sys

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    args = parser.parse_args()

    logging.basicConfig(level=(args.debug and logging.DEBUG or logging.INFO))

    rv = llrp.LLRPReaderThread(args.host, args.port)
    rv.setDaemon(True)

    inq = rv.inq # put messages in here
    outq = rv.outq # collect messages from here

    rv.start()

    rospec = LLRPROSpec(1)

    # stop the ROspec
    time.sleep(1)
    outq.put((0, llrp.LLRPMessage(msgdict={
        'DISABLE_ROSPEC': {
            'Ver':  1,
            'Type': 25,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    # delete the ROspec
    time.sleep(1)
    outq.put((0, llrp.LLRPMessage(msgdict={
        'DELETE_ROSPEC': {
            'Ver':  1,
            'Type': 21,
            'ID':   0,
            'ROSpecID': rospec['ROSpec']['ROSpecID'],
        }})))

    while True:
        try:
            print(inq.get(timeout=5))
        except Queue.Empty:
            break

if __name__ == '__main__':
    main()
