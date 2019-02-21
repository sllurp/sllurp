"""Reset command.
"""

import logging

from sllurp.llrp import LLRPReaderConfig, LLRPReaderClient, LLRPReaderState
from sllurp.log import get_logger

logger = get_logger(__name__)


def shutdown(reader, state):
    host, port = reader.get_peername()
    logger.info('Shutting down reader %s:%d', host, port)
    reader.disconnect()

def main(args):
    if not args.host:
        logger.info('No readers specified.')
        return 0

    factory_args = {
        'start_inventory': False,
        'reset_on_connect': False,
    }

    reader_clients = []
    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port

        config = LLRPReaderConfig(factory_args)
        reader = LLRPReaderClient(host, port, config, timeout=3)
        reader.add_state_callback(LLRPReaderState.STATE_CONNECTED, shutdown)
        # FYI, the reader connection is really finished and idle in the state
        # STATE_SENT_SET_CONFIG just before inventory because of the big state
        # machine. But for "reset", stopping after STATE_CONNECTED is enough
        reader_clients.append(reader)

    for reader in reader_clients:
        host, port = reader.get_peername()
        try:
            reader.connect()
        except:
            logger.error("Failed to connect to %s:%d. Skipping...",
                         host, port)

    while True:
        try:
            # Join all threads using a timeout so it doesn't block
            # Filter out threads which have been joined or are None
            alive_readers = [reader for reader in reader_clients if reader.is_alive()]
            if not alive_readers:
                break
            for reader in alive_readers:
                reader.join(1)
        except (KeyboardInterrupt, SystemExit):
            # catch ctrl-C and stop inventory before disconnecting
            logger.info("Exit detected! Stopping readers...")
            for reader in reader_clients:
                try:
                    reader.disconnect()
                except:
                    logger.exception("Error during disconnect. Ignoring...")
