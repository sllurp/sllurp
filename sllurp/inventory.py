from __future__ import print_function
import argparse
import logging
import pprint
import time
from twisted.internet import reactor, defer

import sllurp.llrp as llrp
from sllurp.llrp_proto import LLRPROSpec, ModeIndex_Name2Type

tagReport = 0
logger = logging.getLogger('sllurp')
logger.propagate = False

def politeShutdown (factory):
    logger.info('shutting down')
    logger.info('total # of tags seen: {}'.format(tagReport))
    return factory.politeShutdown()

def tagReportCallback (llrpMsg):
    """Function to run each time the reader reports seeing tags."""
    global tagReport
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(tags):
        logger.info('saw tag(s): {}'.format(pprint.pformat(tags)))
    else:
        logger.info('no tags seen')
        return
    for tag in tags:
        tagReport += tag['TagSeenCount'][0]

def main():
    parser = argparse.ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
            nargs='*')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT, type=int,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-t', '--time', default=10, type=float,
            help='number of seconds for which to inventory (default 10)')
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
            dest='every_n', metavar='N', help='issue a TagReport every N tags')
    parser.add_argument('-a', '--antennas', default='1',
            help='comma-separated list of antennas to enable')
    parser.add_argument('-X', '--tx-power', default=0, type=int,
            dest='tx_power', help='Transmit power (default 0=max power)')
    parser.add_argument('-M', '--modulation', default='M4',
            choices=sorted(ModeIndex_Name2Type.keys()),
            help='modulation (default M4)')
    parser.add_argument('-T', '--tari', default=0, type=int,
            help='Tari value (default 0=auto)')
    parser.add_argument('-l', '--logfile')
    parser.add_argument('-r', '--reconnect', action='store_true',
            default=False, help='reconnect on connection failure or loss')
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

    # d.callback will be called when all connections have terminated normally.
    # use d.addCallback(<callable>) to define end-of-program behavior.
    d = defer.Deferred()

    fac = llrp.LLRPClientFactory(onFinish=d,
            duration=args.time,
            report_every_n_tags=args.every_n,
            antennas=enabled_antennas,
            disconnect_when_done=True,
            tx_power=args.tx_power,
            modulation=args.modulation,
            tari=args.tari,
            start_inventory=True,
            reconnect=args.reconnect)

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
