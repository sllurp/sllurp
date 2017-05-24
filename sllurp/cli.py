import logging
import click
import sllurp.reset
import sllurp.log


logger = logging.getLogger(__name__)


@click.group()
@click.option('-d', '--debug', is_flag=True, default=False)
@click.option('-l', '--logfile', type=click.Path())
def cli(debug, logfile):
    sllurp.log.init_logging(debug, logfile)


@cli.command()
def inventory():
    click.echo('inventory')


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
def reset(host, port):
    click.echo('reset')
    sllurp.reset.main(host, port)
