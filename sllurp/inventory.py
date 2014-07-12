from __future__ import print_function
import argparse
import logging
import pprint
import time
from twisted.internet import reactor, defer

import sllurp.llrp as llrp

numTags = 0
logger = logging.getLogger('sllurp')

args = None

def finish (_):
    logger.info('total # of tags seen: {}'.format(numTags))

def politeShutdown (factory):
    return factory.politeShutdown()

def tagReportCallback (llrpMsg):
    """Function to run each time the reader reports seeing tags."""
    global numTags
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(tags):
        logger.info('saw tag(s): {}'.format(pprint.pformat(tags)))
    else:
        logger.info('no tags seen')
        return
    for tag in tags:
        numTags += tag['TagSeenCount'][0]

def parse_args ():
    global args
    parser = argparse.ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
            nargs='+')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT, type=int,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-t', '--time', type=float,
            help='number of seconds for which to inventory (default forever)')
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
            dest='every_n', metavar='N', help='issue a TagReport every N tags')
    parser.add_argument('-a', '--antennas', default='1',
            help='comma-separated list of antennas to enable')
    parser.add_argument('-X', '--tx-power', default=0, type=int,
            dest='tx_power', help='Transmit power (default 0=max power)')
    parser.add_argument('-M', '--modulation', default='M8',
            help='modulation (default M8)')
    parser.add_argument('-T', '--tari', default=0, type=int,
            help='Tari value (default 0=auto)')
    parser.add_argument('-l', '--logfile')
    parser.add_argument('-r', '--reconnect', action='store_true',
            default=False, help='reconnect on connection failure or loss')
    args = parser.parse_args()

def init_logging ():
    logLevel = (args.debug and logging.DEBUG or logging.INFO)
    logFormat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = logging.Formatter(logFormat)
    stderr = logging.StreamHandler()
    stderr.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logLevel)
    root.handlers = [stderr,]

    if args.logfile:
        fHandler = logging.FileHandler(args.logfile)
        fHandler.setFormatter(formatter)
        root.addHandler(fHandler)

    logger.log(logLevel, 'log level: {}'.format(logging.getLevelName(logLevel)))

def main ():
    parse_args()
    init_logging()

    enabled_antennas = map(lambda x: int(x.strip()), args.antennas.split(','))

    # d.callback will be called when all connections have terminated normally.
    # use d.addCallback(<callable>) to define end-of-program behavior.
    d = defer.Deferred()
    d.addCallback(finish)

    fac = llrp.LLRPClientFactory(onFinish=d,
            duration=args.time,
            report_every_n_tags=args.every_n,
            antennas=enabled_antennas,
            disconnect_when_done=True,
            tx_power=args.tx_power,
            modulation=args.modulation,
            tari=args.tari,
            start_inventory=True,
            reconnect=args.reconnect,
            tag_content_selector={
                'EnableROSpecID': False,
                'EnableSpecIndex': False,
                'EnableInventoryParameterSpecID': False,
                'EnableAntennaID': True,
                'EnableChannelIndex': False,
                'EnablePeakRRSI': True,
                'EnableFirstSeenTimestamp': False,
                'EnableLastSeenTimestamp': True,
                'EnableTagSeenCount': True,
                'EnableAccessSpecID': False
            })

    # tagReportCallback will be called every time the reader sends a TagReport
    # message (i.e., when it has "seen" tags).
    fac.addTagReportCallback(tagReportCallback)

    for host in args.host:
        reactor.connectTCP(host, args.port, fac, timeout=3)

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', politeShutdown, fac)

    reactor.run()

if __name__ == '__main__':
    main()
