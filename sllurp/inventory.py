from __future__ import print_function
import argparse
import logging
import pprint
import time

import sllurp.llrp as llrp
from sllurp.llrp_proto import LLRPROSpec

tagsSeen = 0

def tagSeenCallback (llrpMsg):
    """Function to run each time the reader reports seeing one or more tags."""
    global tagsSeen
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    logging.info('Saw tag(s): {}'.format(pprint.pformat(tags)))
    for tag in tags:
        tagsSeen += tag['TagSeenCount'][0]

def main():
    parser = argparse.ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-t', '--time', default=10, type=float,
            help='number of seconds for which to inventory (default 10)')
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
            dest='every_n', metavar='N', help='issue a TagReport every N tags')
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
    logging.info('Will run inventory for {} seconds'.format(args.time))
    reader.start_inventory(delay=3, duration=args.time,
            report_every_n_tags=args.every_n)
    time.sleep(args.time + 3)
    reader.stop_inventory()
    time.sleep(1)

    reader.disconnect()
    reader.join()

    logging.info('Total # of tags seen by callback: {}'.format(tagsSeen))

if __name__ == '__main__':
    main()
