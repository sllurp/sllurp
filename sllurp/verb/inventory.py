"""Inventory command.
"""

from __future__ import print_function, division
import logging
import pprint
import time

from sllurp.util import monotonic
from sllurp.llrp import LLRPReaderConfig, LLRPReaderClient, LLRPReaderState
from sllurp.log import get_logger
from sllurp.log import is_general_debug_enabled, set_general_debug

start_time = None

numtags = 0
logger = get_logger(__name__)

def finish_cb(reader):
    runtime = monotonic() - start_time
    logger.info('total # of tags seen: %d (%d tags/second)', numtags,
                numtags/runtime)

def inventory_start_cb(reader, state):
    global start_time
    start_time = monotonic()


def tag_report_cb(reader, tags):
    """Function to run each time the reader reports seeing tags."""
    global numtags
    if len(tags):
        logger.info('saw tag(s): %s', pprint.pformat(tags))
        for tag in tags:
            numtags += tag['TagSeenCount']
    else:
        logger.info('no tags seen')
        return

def main(args):
    global start_time

    if not args.host:
        logger.info('No readers specified.')
        return 0

    enabled_antennas = [int(x.strip()) for x in args.antennas.split(',')]
    frequency_list = [int(x.strip()) for x in args.frequencies.split(',')]

    factory_args = dict(
        duration=args.time,
        report_every_n_tags=args.every_n,
        antennas=enabled_antennas,
        tx_power=args.tx_power,
        tari=args.tari,
        session=args.session,
        mode_identifier=args.mode_identifier,
        tag_population=args.population,
        start_inventory=True,
        disconnect_when_done=args.time and args.time > 0,
        reconnect=args.reconnect,
        reconnect_retries=args.reconnect_retries,
        tag_filter_mask=args.tag_filter_mask,
        tag_content_selector={
            'EnableROSpecID': False,
            'EnableSpecIndex': False,
            'EnableInventoryParameterSpecID': False,
            'EnableAntennaID': False,
            'EnableChannelIndex': True,
            'EnablePeakRSSI': False,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': False,
            'C1G2EPCMemorySelector': {
                'EnableCRC': False,
                'EnablePCBits': False,
            }
        },
        frequencies={
            'HopTableId': args.hoptable_id,
            'ChannelList': frequency_list,
            'Automatic': False
        },
        keepalive_interval=args.keepalive_interval,
        impinj_extended_configuration=args.impinj_extended_configuration,
        impinj_search_mode=args.impinj_search_mode,
        impinj_tag_content_selector=None,
    )
    if args.impinj_reports:
        factory_args['impinj_tag_content_selector'] = {
            'EnableRFPhaseAngle': True,
            'EnablePeakRSSI': True,
            'EnableRFDopplerFrequency': True
        }
    if frequency_list[0] == 0:
        factory_args['frequencies']['Automatic'] = True
        factory_args['frequencies']['ChannelList'] = [1]


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
        reader.add_tag_report_callback(tag_report_cb)
        reader.add_state_callback(LLRPReaderState.STATE_INVENTORYING, inventory_start_cb)
        reader_clients.append(reader)


    start_time = monotonic()
    try:
        for reader in reader_clients:
            reader.connect()
    except Exception:
        if reader:
            logger.error("Failed to establish a connection with: %r",
                         reader.get_peername())
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
            break


    LLRPReaderClient.disconnect_all_readers()
