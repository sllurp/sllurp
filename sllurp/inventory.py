from __future__ import print_function
import argparse
import logging
import pprint
import time
from twisted.internet import reactor

import sllurp.llrp as llrp
from sllurp.llrp_proto import LLRPROSpec, ModeIndex_Name2Type

tagsSeen = 0
logger = logging.getLogger('sllurp')
logger.propagate = False

class MyProtoWrapper (llrp.ProtocolWrapper):
    def stop_all (self, _):
        for p in self.protocols:
            p.stopPolitely()

def tagSeenCallback (llrpMsg):
    """Function to run each time the reader reports seeing tags."""
    global tagsSeen
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(tags):
        logger.info('saw tag(s): {}'.format(pprint.pformat(tags)))
    else:
        logger.info('no tags seen')
        return
    for tag in tags:
        tagsSeen += tag['TagSeenCount'][0]

def disconnected (llrpMsg):
    logger.info('total # of tags seen by callback: {}'.format(tagsSeen))

def main():
    parser = argparse.ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader')
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

    cli_wrapper = MyProtoWrapper()
    cli_factory = llrp.LLRPClientFactory(cli_wrapper, duration=args.time,
            report_every_n_tags=args.every_n, antennas=enabled_antennas,
            start_inventory=True, disconnect_when_done=True, standalone=True,
            tx_power=args.tx_power, modulation=args.modulation, tari=args.tari,
            reconnect=args.reconnect)
    cli_factory.addTagReportCallback(tagSeenCallback)
    cli_factory.addStateCallback(llrp.LLRPClient.STATE_DISCONNECTED,
            disconnected)

    reactor.connectTCP(args.host, args.port, cli_factory, timeout=3)
    reactor.run()

if __name__ == '__main__':
    main()
