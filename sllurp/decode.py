from __future__ import print_function
import binascii
import logging
import click
from . import log
from .llrp import LLRPMessage


logger = logging.getLogger('sllurp')


def bytes_from_file(path, hex=False):
    mode = 'r' if hex else 'r'
    with open(path, mode) as fh:
        bts = fh.read()
    return binascii.unhexlify(bts) if hex else bts


@click.command()
@click.option('-m', '--message', type=str,
              help='Message in hexadecimal encoding')
@click.option('-f', '--infile-binary', type=click.Path(exists=True),
              help='File containing binary message')
@click.option('-A', '--infile-hex', type=click.Path(exists=True),
              help='File containing hexadecimal-encoded message')
@click.option('-d', '--debug', is_flag=True, default=False)
def main(message, infile_binary, infile_hex, debug):
    log.init_logging(debug)
    mbytes = None
    if message:
        mbytes = binascii.unhexlify(message)
    elif infile_binary:
        mbytes = bytes_from_file(infile_binary, hex=False)
    elif infile_hex:
        mbytes = bytes_from_file(infile_hex, hex=True)

    if mbytes:
        msg = LLRPMessage(msgbytes=mbytes)
        print('Decoded message:\n==========')
        print(msg)


if __name__ == '__main__':
    main()
