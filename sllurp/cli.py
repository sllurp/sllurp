"""Command-line wrapper for sllurp commands.
"""

from collections import namedtuple
import logging
import click
from . import log
from .verb import reset as _reset
from .verb import inventory as _inventory
from .llrp_proto import Modulation_Name2Type, DEFAULT_MODULATION


logger = logging.getLogger(__name__)
mods = sorted(Modulation_Name2Type.keys())


@click.group()
@click.option('-d', '--debug', is_flag=True, default=False)
@click.option('-l', '--logfile', type=click.Path())
def cli(debug, logfile):
    log.init_logging(debug, logfile)


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
              default=DEFAULT_MODULATION,
              help='modulation (default={})'.format(DEFAULT_MODULATION))
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('-s', '--session', type=int, default=2,
              help='Gen2 session (default 2)')
@click.option('--mode-index', type=int, default=0,
              help='ModeIndex value (default 0)')
@click.option('-P', '--tag-population', type=int, default=4,
              help="Tag Population value (default 4)")
@click.option('-r', '--reconnect', is_flag=True, default=False,
              help='reconnect on connection failure or loss')
def inventory(host, port, time, report_every_n_tags, antennas, tx_power,
              modulation, tari, session, mode_index, tag_population,
              reconnect):
    # XXX band-aid hack to provide many args to _inventory.main
    Args = namedtuple('Args', ['host', 'port', 'time', 'every_n', 'antennas',
                               'tx_power', 'modulation', 'tari', 'session',
                               'population', 'mode_index', 'reconnect'])
    args = Args(host=host, port=port, time=time, every_n=report_every_n_tags,
                antennas=antennas, tx_power=tx_power, modulation=modulation,
                tari=tari, session=session, population=tag_population,
                mode_index=mode_index, reconnect=reconnect)
    logger.debug('inventory args: %s', args)
    _inventory.main(args)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
def reset(host, port):
    _reset.main(host, port)
