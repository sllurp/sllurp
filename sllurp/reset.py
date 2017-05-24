from __future__ import print_function
import argparse
import time
import logging
from twisted.internet import reactor, defer

import sllurp.llrp as llrp
from sllurp.inventory import init_logging

logger = logging.getLogger('sllurp')

def shutdownReader (proto):
    logger.info('shutting down reader')
    return proto.stopPolitely(disconnect=True)

def finish (_):
    reactor.stop()

def parse_args ():
    parser = argparse.ArgumentParser(description='Reset RFID Reader')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
            nargs='+')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    return parser.parse_args()


def main(host, port):
    onFinish = defer.Deferred()
    onFinish.addCallback(finish)

    factory = llrp.LLRPClientFactory(reset_on_connect=False,
            start_inventory=False, onFinish=onFinish)
    factory.addStateCallback(llrp.LLRPClient.STATE_CONNECTED, shutdownReader)

    for host in host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = port
        reactor.connectTCP(host, port, factory, timeout=3)

    reactor.run()

if __name__ == '__main__':
    args = parse_args()
    init_logging(args)
    main(args)
