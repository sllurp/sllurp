from __future__ import unicode_literals, print_function
import binascii
import argparse
import logging
from sllurp.llrp import LLRPMessage

logger = logging.getLogger('sllurp')

args = None


def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Decode an LLRP message')
    parser.add_argument('msg', help='message in hexadecimal encoding')
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()


def init_logging():
    logLevel = (args.debug and logging.DEBUG or logging.INFO)
    logFormat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = logging.Formatter(logFormat)
    stderr = logging.StreamHandler()
    stderr.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logLevel)
    root.handlers = [stderr]


if __name__ == '__main__':
    parse_args()
    init_logging()

    m = binascii.unhexlify(args.msg)
    msg = LLRPMessage(msgbytes=m)
    print('Decoded message:\n==========')
    print(msg)
