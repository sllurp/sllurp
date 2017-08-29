"""Reset command.
"""

import logging
from twisted.internet import reactor

from sllurp.llrp import LLRPClientFactory, LLRPClient

logger = logging.getLogger(__name__)


def shutdown(proto):
    host, port = proto.peername
    logger.info('Shutting down reader %s:%d', host, port)
    d = proto.stopPolitely(disconnect=True)
    d.addCallback(lambda _: reactor.stop())
    return d


def main(host, port):
    if not host:
        logger.info('No readers specified.')
        return 0

    factory = LLRPClientFactory(reset_on_connect=False,
                                start_inventory=False)
    factory.addStateCallback(LLRPClient.STATE_CONNECTED, shutdown)

    for host in host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        reactor.connectTCP(host, port, factory, timeout=3)

    reactor.run()
