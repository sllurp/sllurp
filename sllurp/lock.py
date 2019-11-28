from __future__ import print_function, unicode_literals
import argparse
import logging
import pprint

from sllurp.util import monotonic
from sllurp.llrp import (LLRPReaderConfig, LLRPReaderClient, LLRPReaderState,
                         C1G2Lock, C1G2LockPayload, LLRP_DEFAULT_PORT)
from sllurp.llrp_proto import Modulation_DefaultTari
from sllurp.log import get_logger

startTime = None
endTime = None

tagReport = 0
logger = get_logger(__name__)

args = None


def startTimeMeasurement():
    global startTime
    startTime = monotonic()


def stopTimeMeasurement():
    global endTime
    endTime = monotonic()


def finish_cb(_):
    # stop runtime measurement to determine rates
    stopTimeMeasurement()
    runTime = endTime - startTime

    logger.info('total # of tags seen: %d (%d tags/second)', tagReport,
                tagReport/runTime)

def access_cb(reader, state):
    lock_payload = C1G2LockPayload(args.privilege, args.data_field)
    opspec = C1G2Lock(AccessPassword=args.access_password,
                      LockPayload=lock_payload)
    return reader.start_access_spec(opspec, stop_after_count=args.count)



def tag_report_cb(reader, tags):
    """Function to run each time the reader reports seeing tags."""
    global tagReport
    if len(tags):
        logger.info('saw tag(s): %s', pprint.pformat(tags))
    else:
        logger.info('no tags seen')
        return
    for tag in tags:
        tagReport += tag['TagSeenCount']
        if "C1G2LockOpSpecResult" in tag:
            result = tag["C1G2LockOpSpecResult"].get("Result")
            logger.debug("result: %s", result)


def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Simple RFID Lock')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
                        nargs='*')
    parser.add_argument('-p', '--port', default=LLRP_DEFAULT_PORT, type=int,
                        help='port (default {})'.format(LLRP_DEFAULT_PORT))
    parser.add_argument('-t', '--time', default=10, type=float,
                        help='number of seconds to inventory (default 10)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='show debugging output')
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
                        dest='every_n', metavar='N',
                        help='issue a TagReport every N tags')
    parser.add_argument('-a', '--antennas', type=str, default='0',
                        help='comma-separated list of antennas to use (default 0=all)')
    parser.add_argument('-X', '--tx-power', default=0, type=int,
                        dest='tx_power',
                        help='Transmit power (default 0=max power)')
    parser.add_argument('-T', '--tari', default=0, type=int,
                        help='Tari value (default 0=auto)')
    parser.add_argument('-s', '--session', default=2, type=int,
                        help='Gen2 session (default 2)')
    parser.add_argument('--mode-identifier', type=int,
                        help='ModeIdentifier value')
    parser.add_argument('-P', '--tag-population', default=4, type=int,
                        dest='population',
                        help='Tag Population value (default 4)')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Operation count for R/W (default 0=forever)')

    # C1G2 Lock Payload parameters:
    parser.add_argument('-priv', '--privilege', default=0, type=int,
                        help='Access privilege: '
                             '0 RW, 1 Permalock, 2 Permaunlock, 3 Unlock')
    parser.add_argument('-df', '--data-field', default=0, type=int,
                        dest='data_field',
                        help='Access Data Field: 0 KILL passwd, '
                             '1 ACCESS passwd, 2 EPC, 3 TID, 4 User memory')

    parser.add_argument('-ap', '--access_password', default=0, type=int,
                        dest='access_password',
                        help='Access password for secure state if R/W locked')

    parser.add_argument('-l', '--logfile')

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

    if args.logfile:
        fHandler = logging.FileHandler(args.logfile)
        fHandler.setFormatter(formatter)
        root.addHandler(fHandler)

    logger.log(logLevel, 'log level: %s', logging.getLevelName(logLevel))


def main():
    parse_args()
    init_logging()

    if not args.host:
        logger.info('No readers specified.')
        return 0

    enabled_antennas = [int(x.strip()) for x in args.antennas.split(',')]

    factory_args = dict(
        report_every_n_tags=args.every_n,
        antennas=enabled_antennas,
        tx_power=args.tx_power,
        tari=args.tari,
        session=args.session,
        mode_identifier=args.mode_identifier,
        tag_population=args.population,
        start_inventory=True,
        disconnect_when_done=True,
        tag_content_selector={
            'EnableROSpecID': False,
            'EnableSpecIndex': False,
            'EnableInventoryParameterSpecID': False,
            'EnableAntennaID': True,
            'EnableChannelIndex': False,
            'EnablePeakRSSI': True,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': True,
        }
    )

    reader_clients = []
    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port

        config = LLRPReaderConfig(factory_args)
        reader = LLRPReaderClient(host, port, config)
        reader.add_disconnected_callback(finish_cb)
        # tagReportCallback will be called every time the reader sends a TagReport
        # message (i.e., when it has "seen" tags).
        reader.add_tag_report_callback(tag_report_cb)
        # start tag access once inventorying
        reader.add_state_callback(LLRPReaderState.STATE_INVENTORYING, access_cb)

        reader_clients.append(reader)

    # start runtime measurement to determine rates
    startTimeMeasurement()

    try:
        for reader in reader_clients:
            reader.connect()
    except:
        # On one error, abort all
        for reader in reader_clients:
            reader.disconnect()

    while True:
        try:
            # Join all threads using a timeout so it doesn't block
            # Filter out threads which have been joined or are None
            alive_readers = [reader for reader in reader_clients if reader.is_alive()]
            if not alive_readers:
                break
            for reader in alive_readers:
                reader.join(1)
        except (KeyboardInterrupt, SystemExit):
            # catch ctrl-C and stop inventory before disconnecting
            logger.info("Exit detected! Stopping readers...")
            for reader in reader_clients:
                try:
                    reader.disconnect()
                except:
                    logger.exception("Error during disconnect. Ignoring...")
                    pass

if __name__ == '__main__':
    main()
