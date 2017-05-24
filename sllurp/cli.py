import logging
import click
from . import log
from .verb import reset as _reset


logger = logging.getLogger(__name__)


@click.group()
@click.option('-d', '--debug', is_flag=True, default=False)
@click.option('-l', '--logfile', type=click.Path())
def cli(debug, logfile):
    log.init_logging(debug, logfile)


@cli.command()
def inventory():
    click.echo('inventory')


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
def reset(host, port):
    _reset.main(host, port)
