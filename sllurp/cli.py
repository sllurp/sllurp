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

# Disable Click unicode warning since we use unicode string exclusively
click.disable_unicode_literals_warning = True

logger = loggie.get_logger(__name__)


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
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('-s', '--session', type=int, default=2,
              help='Gen2 session (default 2)')
@click.option('--mode-identifier', type=int, help='ModeIdentifier value')
@click.option('-P', '--tag-population', type=int, default=4,
              help="Tag Population value (default 4)")
@click.option('-r', '--reconnect', is_flag=True, default=False,
              help='reconnect on connection failure or loss')
@click.option('--reconnect-retries', type=int, default=5,
              help='Max num of reconnect attempts on connection failure or loss. '
              'Set to -1 for unlimited attempts')
@click.option('--tag-filter-mask', type=str, default=[], multiple=True,
              help=('Filter inventory on EPC (or prefix of EPC); multiple'
                    ' args allowed'))
@click.option('--keepalive-interval', type=int, default=60000,
              help='Time(ms) between keepalive msgs send by the reader')
@click.option('--impinj-extended-configuration', is_flag=True, default=False,
              help=('Get Impinj extended configuration values'))
@click.option('--impinj-search-mode', type=click.Choice(['1', '2']),
              help=('Impinj extension: inventory search mode '
                    ' (1=single, 2=dual)'))
@click.option('--impinj-reports', is_flag=True, default=False,
              help='Enable Impinj tag report content '
              '(Phase angle, RSSI, Doppler)')
@click.option('-f', '--frequencies', type=str, default='1',
              help='comma-separated list of frequency indexes to use (0=all;'
                   ' default 1). Region and reader dependent')
@click.option('--hoptable-id', type=int, default=1,
              help='HopTableID to use (default 1) for regions '
              'with frequency hopping regulatory requirements')
def inventory(host, port, time, report_every_n_tags, antennas, tx_power,
              tari, session, mode_identifier,
              tag_population, reconnect, reconnect_retries,
              tag_filter_mask, keepalive_interval,
              impinj_extended_configuration,
              impinj_search_mode, impinj_reports, frequencies, hoptable_id):
    """Conduct inventory (searching the area around the antennas)."""
    # XXX band-aid hack to provide many args to _inventory.main
    Args = namedtuple('Args', ['host', 'port', 'time', 'every_n', 'antennas',
                               'tx_power', 'tari', 'session',
                               'population', 'mode_identifier',
                               'reconnect', 'reconnect_retries',
                               'tag_filter_mask', 'keepalive_interval',
                               'impinj_extended_configuration',
                               'impinj_search_mode',
                               'impinj_reports',
                               'frequencies', 'hoptable_id'])
    args = Args(host=host, port=port, time=time, every_n=report_every_n_tags,
                antennas=antennas, tx_power=tx_power,
                tari=tari, session=session, population=tag_population,
                mode_identifier=mode_identifier,
                reconnect=reconnect, reconnect_retries=reconnect_retries,
                tag_filter_mask=tag_filter_mask,
                keepalive_interval=keepalive_interval,
                impinj_extended_configuration=impinj_extended_configuration,
                impinj_search_mode=impinj_search_mode,
                impinj_reports=impinj_reports,
                frequencies=frequencies, hoptable_id=hoptable_id)
    logger.debug('inventory args: %s', args)
    _inventory.main(args)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
@click.option('-o', '--outfile', type=click.File('w'), default='-')
@click.option('-a', '--antennas', type=str, default='0',
              help='comma-separated list of antennas to use (default 0=all)')
@click.option('-X', '--tx-power', type=int, default=0,
              help='transmit power (default 0=max power)')
@click.option('-e', '--epc', type=str, help='log only a specific EPC')
@click.option('-r', '--reader-timestamp', is_flag=True, default=False,
              help='Use reader-provided timestamps instead of our own')
@click.option('-f', '--frequencies', type=str, default='1',
              help='comma-separated list of frequency indexes to use (0=all;'
                   ' default 1). Region and reader dependent')
@click.option('--hoptable-id', type=int, default=1,
              help='HopTableID to use (default 1) for regions '
              'with frequency hopping regulatory requirements')
def log(host, port, outfile, antennas, tx_power, epc, reader_timestamp,
        frequencies, hoptable_id):
    Args = namedtuple('Args', ['host', 'port', 'outfile', 'antennas',
                               'tx_power', 'epc', 'reader_timestamp',
                               'frequencies', 'hoptable_id'])
    args = Args(host=host, port=port, outfile=outfile, tx_power=tx_power,
                antennas=antennas, epc=epc, reader_timestamp=reader_timestamp)
    logger.debug('log args: %s', args)
    _log.main(args)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
@click.option('-t', '--time', type=float, help='seconds to inventory')
@click.option('-n', '--report-every-n-tags', type=int,
              help='issue a TagReport every N tags')
@click.option('-a', '--antennas', type=str, default='0',
              help='comma-separated list of antennas to use (default 0=all)')
@click.option('-X', '--tx-power', type=int, default=0,
              help='transmit power (default 0=max power)')
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('-s', '--session', type=int, default=2,
              help='Gen2 session (default 2)')
@click.option('--mode-identifier', type=int, help='ModeIdentifier value')
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
@click.option('-f', '--frequencies', type=str, default='1',
              help='comma-separated list of frequency indexes to use (0=all;'
                   ' default 1). Region and reader dependent')
@click.option('--hoptable-id', type=int, default=1,
              help='HopTableID to use (default 1) for regions '
              'with frequency hopping regulatory requirements')
def access(host, port, time, report_every_n_tags, antennas, tx_power,
           tari, session, mode_identifier, tag_population,
           read_words, write_words, count, memory_bank, word_ptr,
           access_password, frequencies, hoptable_id):
    Args = namedtuple('Args', ['host', 'port', 'time', 'every_n', 'antennas',
                               'tx_power', 'tari', 'session',
                               'mode_identifier', 'population', 'read_words',
                               'write_words', 'count', 'mb', 'word_ptr',
                               'access_password', 'frequencies',
                               'hoptable_id'])
    args = Args(host=host, port=port, time=time, every_n=report_every_n_tags,
                antennas=antennas, tx_power=tx_power, tari=tari,
                session=session, mode_identifier=mode_identifier,
                population=tag_population, read_words=read_words,
                write_words=write_words, count=count, mb=memory_bank,
                word_ptr=word_ptr, access_password=access_password,
                frequencies=frequencies, hoptable_id=hoptable_id)
    logger.debug('access args: %s', args)
    _access.main(args)


@cli.command()
def version():
    print(__version__)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
def reset(host, port):
    Args = namedtuple('Args', ['host', 'port'])
    args = Args(host=host, port=port)
    _reset.main(args)
