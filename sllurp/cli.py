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
from .verb import location as _location
from .verb import direction as _direction
from .llrp_proto import Modulation_Name2Type
import ast

# Disable Click unicode warning since we use unicode string exclusively
click.disable_unicode_literals_warning = True

logger = logging.getLogger(__name__)
mods = sorted(Modulation_Name2Type.keys())


class PythonLiteralOption(click.Option):

    def type_cast_value(self, ctx, value):
        try:
            return ast.literal_eval(value)
        except:
            raise click.BadParameter(value)

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
@click.option('--impinj-extended-configuration', is_flag=True, default=False,
              help=('Get Impinj extended configuration values'))
@click.option('--impinj-search-mode', type=click.Choice(['1', '2']),
              help=('Impinj extension: inventory search mode '
                    ' (1=single, 2=dual)'))
@click.option('--impinj-reports', is_flag=True, default=False,
              help='Enable Impinj tag report content '
              '(Phase angle, RSSI, Doppler)')
@click.option('--mqtt-broker', type=str,
               help="Address of MQTT broker")
@click.option('--mqtt-port', type=int,default=1883,
               help="Port of MQTT broker")
@click.option('--mqtt-topic',type=str,
               help="MQTT topic to publish data")
@click.option('--mqtt-username',type=str,
               help="MQTT broker username")
@click.option('--mqtt-password',type=str,
               help="MQTT broker password")
@click.option('--mqtt-status-topic',type=str,
                help="MQTT topic to publish status")
@click.option('--mqtt-status-interval', type=int, default=10000,
                help="How often is the mqtt status is sent")
@click.option('--http-server',is_flag=True,default=False,
               help="enable HTTP server with REST endpoint")
@click.option('--http-port', default=8080)
@click.option('--tag-age-interval',type=int,default=10,
               help="Time in seconds for which the tag must \
               not be read (seen) before it is considered to \
               have exited from the field of view.")
def inventory(host, port, time, report_every_n_tags, antennas, tx_power,
              modulation, tari, session, mode_identifier,
              tag_population, reconnect,
              impinj_extended_configuration,
              impinj_search_mode, impinj_reports, 
              mqtt_broker, mqtt_port, mqtt_topic, mqtt_status_interval,mqtt_username,mqtt_password,
              mqtt_status_topic,http_server, http_port, tag_age_interval):
    """Conduct inventory (searching the area around the antennas)."""
    # XXX band-aid hack to provide many args to _inventory.main
    Args = namedtuple('Args', ['host', 'port', 'time', 'every_n', 'antennas',
                               'tx_power', 'modulation', 'tari', 'session',
                               'population', 'mode_identifier',
                               'reconnect',
                               'impinj_extended_configuration',
                               'impinj_search_mode',
                               'impinj_reports',
                               'mqtt_broker', 'mqtt_port', 'mqtt_topic', 'mqtt_status_topic', 'mqtt_status_interval',
                               'mqtt_username','mqtt_password',
                               'http_server', 'http_port', 'tag_age_interval'])
    args = Args(host=host, port=port, time=time, every_n=report_every_n_tags,
                antennas=antennas, tx_power=tx_power, modulation=modulation,
                tari=tari, session=session, population=tag_population,
                mode_identifier=mode_identifier,
                reconnect=reconnect,
                impinj_extended_configuration=impinj_extended_configuration,
                impinj_search_mode=impinj_search_mode,
                impinj_reports=impinj_reports,
                mqtt_broker=mqtt_broker,
                mqtt_port=mqtt_port,
                mqtt_topic=mqtt_topic,
                http_server=http_server,
                http_port=str(http_port),
                tag_age_interval=tag_age_interval,
                mqtt_status_topic=mqtt_status_topic,
                mqtt_status_interval=mqtt_status_interval,
                mqtt_username=str(mqtt_username),
                mqtt_password=str(mqtt_password))
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
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
@click.option('-a', '--antennas', type=str, default='1',
              help='comma-separated list of antennas to use (0=all;'
                   ' default 1)')
@click.option('-X', '--tx-power', type=int, default=0,
              help='transmit power (default 0=max power)')
@click.option('-M', '--modulation', type=click.Choice(mods),
              help='Reader-to-Tag Modulation')
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('--mode-identifier', type=int, help='ModeIdentifier value')
@click.option('-r', '--reconnect', is_flag=True, default=False,
              help='reconnect on connection failure or loss')
@click.option('--mqtt-broker', type=str,
               help="Address of MQTT broker")
@click.option('--mqtt-port', type=int,default=1883,
               help="Port of MQTT broker")
@click.option('--mqtt-username',type=str,
               help="MQTT broker username")
@click.option('--mqtt-password',type=str,
               help="MQTT broker password")
@click.option('--mqtt-topic',type=str,
               help="MQTT topic to publish")
@click.option('--mqtt-status-topic',type=str,
                help="MQTT topic to publish status")
@click.option('--mqtt-status-interval', type=int, default=10000,
                help="How often is the mqtt status is sent")
@click.option('--tag_age_interval',type=int,default=2,
               help="Time in seconds for which the tag must \
               not be read (seen) before it is considered to \
               have exited from the field of view.")
@click.option('-t','--time',type=int,default=20,
                help="How fast in seconds do we want an update")
@click.option('--compute_window',type=int,default=5,
                help="Duration of the smoothing window in\
                seconds over which tag location estimates are computed")
@click.option('--height',type=int,default=100,help='Height in centimeters with respect to the average tag \
                height')
@click.option('--facility_x_loc',type=int,default=0,
                help=" The relative position of the antenna in centimeters within \
                the facility. This is used by the antenna when computing location and might be useful for \
                multi-antennas deployments")
@click.option('--facility_y_loc',type=int,default=0,
                help="The relative position of the antennas in centimeters within \
                the facility. This is used by the antennas when computing location and might be useful for \
                multi-antennas deployments")
@click.option('--orientation',type=int,default=0,
                help="The relative orientation of the antennas X-Y coordinates \
                relative to the Store X-Y coordinates in degrees")
@click.option('--impinj-search-mode', type=click.Choice(['1', '2']),
              help=('Impinj extension: inventory search mode '
                    ' (1=single, 2=dual)'))
def location(host, port, antennas, tx_power,modulation, tari,
              reconnect, mode_identifier, mqtt_broker, mqtt_port, mqtt_topic, mqtt_status_topic, mqtt_status_interval,mqtt_username,mqtt_password,
              tag_age_interval, time, compute_window,height, facility_x_loc, facility_y_loc, orientation, impinj_search_mode):
    """Conduct tag localization (Impinj xArray)."""
    # XXX band-aid hack to provide many args to _inventory.main
    Args = namedtuple('Args', ['host', 'port', 'antennas',
                               'tx_power', 'modulation', 'tari', 'mode_identifier','reconnect',
                               'mqtt_broker', 'mqtt_port', 'mqtt_topic', 'mqtt_status_topic', 'mqtt_status_interval',
                               'mqtt_username','mqtt_password',
                               'time', 'compute_window','tag_age_interval','height','facility_x_loc','facility_y_loc',
                               'orientation','impinj_search_mode'])
    args = Args(host=host, port=port,
                antennas=antennas,
                tx_power=tx_power,
                modulation=modulation,
                tari=tari,
                mode_identifier=mode_identifier,
                reconnect=reconnect,
                mqtt_broker=mqtt_broker,
                mqtt_port=mqtt_port,
                mqtt_topic=mqtt_topic,
                mqtt_status_topic=mqtt_status_topic,
                mqtt_status_interval=mqtt_status_interval,
                mqtt_username=str(mqtt_username),
                mqtt_password=str(mqtt_password),
                tag_age_interval=tag_age_interval,
                time=time,
                compute_window=compute_window,
                height=height,
                facility_x_loc=facility_x_loc,
                facility_y_loc=facility_y_loc,
                orientation=orientation,
                impinj_search_mode=impinj_search_mode)
    logger.debug('location args: %s', args)
    _location.main(args)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
@click.option('-a', '--antennas', type=str, default='1',
              help='comma-separated list of antennas to use (0=all;'
                   ' default 1)')
@click.option('-X', '--tx-power', type=int, default=81,
              help='transmit power (default 0=max power)')
@click.option('-M', '--modulation', type=click.Choice(mods),
              help='Reader-to-Tag Modulation')
@click.option('-T', '--tari', type=int, default=0,
              help='Tari value (default 0=auto)')
@click.option('--mode-identifier', type=int, help='ModeIdentifier value',default=1000)
@click.option('-r', '--reconnect', is_flag=True, default=False,
              help='reconnect on connection failure or loss')
@click.option('--mqtt-broker', type=str,
               help="Address of MQTT broker")
@click.option('--mqtt-port', type=int,default=1883,
               help="Port of MQTT broker")
@click.option('--mqtt-username',type=str,
               help="MQTT broker username")
@click.option('--mqtt-password',type=str,
               help="MQTT broker password")
@click.option('--mqtt-topic',type=str,
               help="MQTT topic to publish")
@click.option('--mqtt-status-topic',type=str,
                help="MQTT topic to publish status")
@click.option('--mqtt-status-interval', type=int, default=10000,
                help="How often is the mqtt status is sent")
@click.option('--tag_age_interval',type=int,default=2,
               help="Time in seconds for which the tag must \
               not be read (seen) before it is considered to \
               have exited from the field of view.")
@click.option('-t','--time',type=int,default=20,
                help="How fast in seconds do we want an update")
@click.option('--enable_sector_id',cls=PythonLiteralOption, default=[2,2,6],
                help="List of sector id to enable to detecting tags (4 max)")
@click.option('--field_of_view',type=int, default=0,
                help="field of view of the antenna : 0 = auto, 1 = narrow, 2 = wide")
def direction(host, port, antennas, tx_power, modulation, tari,
              reconnect, mode_identifier,
              mqtt_broker, mqtt_port, mqtt_topic,mqtt_status_topic, mqtt_status_interval,mqtt_username,mqtt_password,
              tag_age_interval, time, enable_sector_id,field_of_view):
    """1D tag tracking (Impinj xArray/xSpan)."""
    # XXX band-aid hack to provide many args to _inventory.main
    Args = namedtuple('Args', ['host', 'port', 'antennas',
                               'tx_power','modulation','tari','mode_identifier','reconnect',
                               'mqtt_broker', 'mqtt_port', 'mqtt_topic', 'mqtt_status_topic', 'mqtt_status_interval',
                               'mqtt_username','mqtt_password',
                               'time', 'tag_age_interval', 'enable_sector_id', 'field_of_view'])
    args = Args(host=host, port=port,
                antennas=antennas,
                tx_power=tx_power,
                modulation=modulation,
                tari=tari,
                mode_identifier=mode_identifier,
                reconnect=reconnect,
                mqtt_broker=mqtt_broker,
                mqtt_port=mqtt_port,
                mqtt_topic=mqtt_topic,
                mqtt_status_topic=mqtt_status_topic,
                mqtt_status_interval=mqtt_status_interval,
                mqtt_username=str(mqtt_username),
                mqtt_password=str(mqtt_password),
                tag_age_interval=tag_age_interval,
                time=time,
                enable_sector_id=enable_sector_id,
                field_of_view=field_of_view)
    logger.debug('direction args: %s', args)
    _direction.main(args)


@cli.command()
def version():
    print(__version__)


@cli.command()
@click.argument('host', type=str, nargs=-1)
@click.option('-p', '--port', type=int, default=5084)
def reset(host, port):
    _reset.main(host, port)