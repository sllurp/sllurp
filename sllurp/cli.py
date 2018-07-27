"""Command-line wrapper for sllurp commands.
"""

from __future__ import print_function, unicode_literals
from collections import namedtuple
import logging
import click
from . import __version__
from . import log as loggie
from .verb import reset as _reset
from .verb import inventory as _inventory
from .verb import log as _log
from .verb import access as _access
from .llrp_proto import Modulation_Name2Type

# Disable Click unicode warning since we use unicode string exclusively
click.disable_unicode_literals_warning = True

logger = logging.getLogger(__name__)
mods = sorted(Modulation_Name2Type.keys())


@click.group()
@click.option('-d', '--debug', is_flag=True, default=False)
@click.option('-l', '--logfile', type=click.Path())
def cli(debug, logfile):
    loggie.init_logging(debug, logfile)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
@click.option('-t', '--time', type=float, help='seconds to inventory')
@click.option('-n', '--report-every-n-tags', type=int,
              help='issue a TagReport every N tags')
@click.option('-a', '--antennas', type=str, default='1',
              help='comma-separated list of antennas to use (0=all;'
                   ' default 1)')
@click.option('-X', '--tx-power', type=int, default=0,
              help='transmit power (default 0=max power)')
@click.option('-M', '--modulation', type=click.Choice(mods),
              help='Reader-to-Tag Modulation')
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('-s', '--session', type=int, default=2,
              help='Gen2 session (default 2)')
@click.option('--mode-identifier', type=int, help='ModeIdentifier value')
@click.option('-P', '--tag-population', type=int, default=4,
              help="Tag Population value (default 4)")
@click.option('-r', '--reconnect', is_flag=True, default=False,
              help='reconnect on connection failure or loss')
@click.option('--impinj-search-mode', type=click.Choice(['1', '2']),
              help=('Impinj extension: inventory search mode '
                    ' (1=single, 2=double)'))
@click.option('--impinj-reports', is_flag=True, default=False,
              help='Enable Impinj tag report content '
              '(Phase angle, RSSI, Doppler)')
def inventory(host, port, time, report_every_n_tags, antennas, tx_power,
              modulation, tari, session, mode_identifier,
              tag_population, reconnect,
              impinj_search_mode, impinj_reports):
    # XXX band-aid hack to provide many args to _inventory.main
    Args = namedtuple('Args', ['host', 'port', 'time', 'every_n', 'antennas',
                               'tx_power', 'modulation', 'tari', 'session',
                               'population', 'mode_identifier',
                               'reconnect', 'impinj_search_mode',
                               'impinj_reports'])
    args = Args(host=host, port=port, time=time, every_n=report_every_n_tags,
                antennas=antennas, tx_power=tx_power, modulation=modulation,
                tari=tari, session=session, population=tag_population,
                mode_identifier=mode_identifier,
                reconnect=reconnect,
                impinj_search_mode=impinj_search_mode,
                impinj_reports=impinj_reports)
    logger.debug('inventory args: %s', args)
    _inventory.main(args)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-o', '--outfile', type=click.File('w'), default='-')
@click.option('-a', '--antennas', type=str, default='0',
              help='comma-separated list of antennas to use (default 0=all)')
@click.option('-e', '--epc', type=str, help='log only a specific EPC')
@click.option('-r', '--reader-timestamp', is_flag=True, default=False,
              help='Use reader-provided timestamps instead of our own')
def log(host, outfile, antennas, epc, reader_timestamp):
    _log.main(host, outfile, antennas, epc, reader_timestamp)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
@click.option('-t', '--time', type=float, help='seconds to inventory')
@click.option('-n', '--report-every-n-tags', type=int,
              help='issue a TagReport every N tags')
@click.option('-X', '--tx-power', type=int, default=0,
              help='transmit power (default 0=max power)')
@click.option('-M', '--modulation', type=click.Choice(mods),
              help='Reader-to-Tag Modulation')
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('-s', '--session', type=int, default=2,
              help='Gen2 session (default 2)')
@click.option('-P', '--tag-population', type=int, default=4,
              help='Tag Population value (default 4)')
@click.option('-r', '--read-words', type=int,
              help='Read N words from tag memory')
@click.option('-w', '--write-words', type=int,
              help='Write N words to tag memory')
@click.option('-c', '--count', type=int, default=0,
              help='Operation count for R/W (default 0=forever)')
@click.option('-mb', '--memory-bank', type=click.IntRange(0, 3),
              default=3,
              help='Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved')
@click.option('-wp', '--word-ptr', type=int, default=0,
              help='Word addresss of the first word to read/write')
@click.option('-ap', '--access-password', type=int, default=0,
              help='Access password for secure state if R/W locked')
def access(host, port, time, report_every_n_tags, tx_power, modulation, tari,
           session, tag_population, read_words, write_words, count,
           memory_bank, word_ptr, access_password):
    Args = namedtuple('Args', ['host', 'port', 'time', 'every_n',
                               'tx_power', 'modulation', 'tari', 'session',
                               'population', 'read_words', 'write_words',
                               'count', 'mb', 'word_ptr', 'access_password'])
    args = Args(host=host, port=port, time=time, every_n=report_every_n_tags,
                tx_power=tx_power, modulation=modulation, tari=tari,
                session=session, population=tag_population,
                read_words=read_words, write_words=write_words, count=count,
                mb=memory_bank, word_ptr=word_ptr,
                access_password=access_password)
    logger.debug('access args: %s', args)
    _access.main(args)


@cli.command()
def version():
    print(__version__)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
def reset(host, port):
    _reset.main(host, port)
