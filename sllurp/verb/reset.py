"""Reset command.
"""

import logging
from twisted.internet import reactor, defer

from sllurp.llrp import LLRPClientFactory, LLRPClient

logger = logging.getLogger(__name__)


def shutdown(proto):
    host, port = proto.peername
    logger.info('Shutting down reader %s:%d', host, port)
    return proto.stopPolitely(disconnect=True)


def finish(*args):
    reactor.stop()


def main(host, port):
    if not host:
        logger.info('No readers specified.')
        return 0

    onFinish = defer.Deferred()
    onFinish.addCallback(finish)

    factory = LLRPClientFactory(reset_on_connect=False,
                                start_inventory=False,
                                onFinish=onFinish)
    factory.addStateCallback(LLRPClient.STATE_CONNECTED, shutdown)

    for host in host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        reactor.connectTCP(host, port, factory, timeout=3)

    reactor.run()
