import time
import logging
from twisted.internet import reactor, defer

import sllurp.llrp as llrp

logger = logging.getLogger(__name__)


def shutdownReader(proto):
    host, port = proto.peername
    logger.info('Shutting down reader %s:%d', host, port)
    return proto.stopPolitely(disconnect=True)


def finish(*args):
    reactor.stop()


def main(host, port):
    onFinish = defer.Deferred()
    onFinish.addCallback(finish)

    factory = llrp.LLRPClientFactory(reset_on_connect=False,
                                     start_inventory=False,
                                     onFinish=onFinish)
    factory.addStateCallback(llrp.LLRPClient.STATE_CONNECTED,
                             shutdownReader)

    for host in host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        reactor.connectTCP(host, port, factory, timeout=3)

    reactor.run()
