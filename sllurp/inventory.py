from __future__ import print_function
import argparse
import logging
import pprint
import time

import sllurp.llrp as llrp
from sllurp.llrp_proto import LLRPROSpec

tagsSeen = 0
logger = logging.getLogger('sllurp')
logger.propagate = False

def tagSeenCallback (llrpMsg):
    """Function to run each time the reader reports seeing one or more tags."""
    global tagsSeen
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    logger.info('Saw tag(s): {}'.format(pprint.pformat(tags)))
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
    parser.add_argument('-a', '--antennas', default='1',
            help='comma-separated list of antennas to enable')
    parser.add_argument('-l', '--logfile')
    args = parser.parse_args()

    logLevel = (args.debug and logging.DEBUG or logging.INFO)
    logger.setLevel(logLevel)
    logFormat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = logging.Formatter(logFormat)
    if args.logfile:
        fHandler = logging.FileHandler(args.logfile)
        fHandler.setFormatter(formatter)
        logger.addHandler(fHandler)
    else:
        sHandler = logging.StreamHandler()
        sHandler.setFormatter(formatter)
        logger.addHandler(sHandler)
    logger.log(logLevel, 'log level: {}'.format(logging.getLevelName(logLevel)))

    enabled_antennas = map(lambda x: int(x.strip()), args.antennas.split(','))

    # spawn a thread to talk to the reader
    reader = llrp.LLRPReaderThread(args.host, args.port, duration=args.time,
            report_every_n_tags=args.every_n, antennas=enabled_antennas,
            start_inventory=True, disconnect_when_done=True, standalone=True)
    reader.addCallback('RO_ACCESS_REPORT', tagSeenCallback)
    reader.start()

    reader.join()
    logger.info('Total # of tags seen by callback: {}'.format(tagsSeen))

if __name__ == '__main__':
    main()
