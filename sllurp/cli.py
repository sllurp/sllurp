import click


@click.group()
def cli():
    click.echo('hello')


@cli.command()
def inventory():
    click.echo('inventory')


@cli.command()
def reset():
    click.echo('reset')
