from __future__ import print_function
import argparse
import time
import logging

import sllurp.llrp as llrp
from sllurp.llrp_proto import LLRPROSpec

def main():
    parser = argparse.ArgumentParser(description='Reset RFID Reader')
    parser.add_argument('host', help='hostname or IP address of RFID reader')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT,
            help='port to connect to (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-d', '--debug', action='store_true',
            help='show debugging output')
    args = parser.parse_args()

    logLevel = (args.debug and logging.DEBUG or logging.INFO)
    logging.basicConfig(level=logLevel,
            format='%(asctime)s: %(levelname)s: %(message)s')
    logging.log(logLevel, 'log level: {}'.format(logging.getLevelName(logLevel)))
    logging.getLogger('llrpc').setLevel(logLevel)

    # spawn a thread to talk to the reader
    reader = llrp.LLRPReaderThread(args.host, args.port)
    reader.setDaemon(True)
    reader.start()
    time.sleep(3)
    reader.delete_all_rospecs()
    time.sleep(3)
    reader.disconnect()
    reader.join()

if __name__ == '__main__':
    main()
