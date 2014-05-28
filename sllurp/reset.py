from __future__ import print_function
import argparse
import time
import logging
from twisted.internet import reactor, defer

import sllurp.llrp as llrp

logger = logging.getLogger('sllurp')
logger.propagate = False

args = None

def stopProtocol (proto):
    return proto.stopPolitely()

def shutdown (_):
    logger.info('shutting down')
    reactor.stop()

def parse_args ():
    global args
    parser = argparse.ArgumentParser(description='Reset RFID Reader')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
            nargs='+')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    parser.add_argument('-l', '--logfile')
    args = parser.parse_args()

def init_logging ():
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

def main ():
    parse_args()
    init_logging()

    # a Deferred to call when all connections have closed
    d = defer.Deferred()
    d.addCallback(shutdown)

    factory = llrp.LLRPClientFactory(start_inventory=False, onFinish=d)

    # when each protocol connects, stop it politely
    factory.addStateCallback(llrp.LLRPClient.STATE_CONNECTED, stopProtocol)

    for host in args.host:
        reactor.connectTCP(host, args.port, factory, timeout=3)

    reactor.run()

if __name__ == '__main__':
    main()
