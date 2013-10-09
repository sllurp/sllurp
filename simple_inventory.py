#!/usr/bin/env python

from __future__ import print_function
import argparse
import logging
import pprint
import time
from sllurp.util import *

import sllurp.llrp as llrp
from sllurp.llrp_proto import LLRPROSpec

def tagSeenCallback (llrpMsg):
    """Function to run each time the reader reports seeing one or more tags."""
    tagDict = llrpMsg.deserialize()
    logging.info('Saw tag(s): {}'.\
            format(pprint.pformat(tagDict['RO_ACCESS_REPORT']['TagReportData'])))

def main():
    parser = argparse.ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-t', '--time', default=10, type=float,
            help='number of seconds for which to inventory (default 10)')
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    args = parser.parse_args()

    logLevel = (args.debug and logging.DEBUG or logging.INFO)
    logging.basicConfig(level=logLevel,
            format='%(asctime)s: %(levelname)s: %(message)s')
    logging.log(logLevel, 'log level: {}'.format(logging.getLevelName(logLevel)))
    logging.getLogger('llrpc').setLevel(logLevel)

    # spawn a thread to talk to the reader
    reader = llrp.LLRPReaderThread(args.host, args.port)
    reader.setDaemon(True)
    reader.addCallback('RO_ACCESS_REPORT', tagSeenCallback)
    reader.start()
    time.sleep(3)

    logging.info('Will run for {} seconds'.format(args.time))
    reader.start_inventory()
    time.sleep(args.time)
    reader.stop_inventory()

    reader.disconnect()

if __name__ == '__main__':
    main()
