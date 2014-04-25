import binascii
import argparse
import logging
from sllurp.llrp import LLRPMessage

logger = logging.getLogger('sllurp')
logger.propagate = False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decode a single LLRP message')
    parser.add_argument('msg', help='message in hexadecimal encoding')
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    logLevel = (args.debug and logging.DEBUG or logging.INFO)
    logger.setLevel(logLevel)
    logger.addHandler(logging.StreamHandler())

    m = binascii.unhexlify(args.msg)
    msg = LLRPMessage(msgbytes=m)
    print 'Decoded message:\n=========='
    print msg
