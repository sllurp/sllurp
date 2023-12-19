from __future__ import print_function, unicode_literals
import binascii
import logging
import pprint
import sys

from sllurp.util import monotonic
from sllurp.llrp import (LLRPReaderConfig, LLRPReaderClient, LLRPReaderState,
                         C1G2Read, C1G2Write)
from sllurp.log import get_logger

start_time = None

tagReport = 0
logger = get_logger(__name__)

args = None


def finish_cb(_):
    # stop runtime measurement to determine rates
    runTime = monotonic() - start_time

    logger.info('total # of tags seen: %d (%d tags/second)', tagReport,
                tagReport/runTime)


def access_cb(reader, state):
    if args.read_words:
        opspec = C1G2Read(AccessPassword=args.access_password, MB=args.mb,
                          WordPtr=args.word_ptr, WordCount=args.read_words)
    elif args.write_words:
        if sys.version_info.major < 3:
            data = sys.stdin.read(args.write_words * 2)
        else:
            # bytes
            data = sys.stdin.buffer.read(args.write_words * 2)

        opspec = C1G2Write(AccessPassword=args.access_password, MB=args.mb,
                           WordPtr=args.word_ptr,
                           WriteDataWordCount=args.write_words,
                           WriteData=data)
    else:
        # Unexpected situation
        return

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
        if "C1G2ReadOpSpecResult" in tag:
            # copy the binary data to the standard output stream
            data = tag["C1G2ReadOpSpecResult"].get("ReadData")
            if data:
                if sys.version_info.major < 3:
                    sys.stdout.write(data)
                else:
                    sys.stdout.buffer.write(data) # bytes
                logger.debug("hex data: %s", binascii.hexlify(data))


def main(main_args):
    global start_time
    global args
    args = main_args

    if not args.host:
        logger.info('No readers specified.')
        return 0

    if not args.read_words and not args.write_words:
        logger.info("Error: Either --read-words or --write-words has to be"
                    " chosen.")
        return 0

    enabled_antennas = [int(x.strip()) for x in args.antennas.split(',')]
    frequency_list = [int(x.strip()) for x in args.frequencies.split(',')]

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
        },
        frequencies={
            'HopTableId': args.hoptable_id,
            'ChannelList': frequency_list,
            'Automatic': False
        },
    )

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
        # tagReportCallback will be called every time the reader sends a TagReport
        # message (i.e., when it has "seen" tags).
        reader.add_tag_report_callback(tag_report_cb)
        # start tag access once inventorying
        reader.add_state_callback(LLRPReaderState.STATE_INVENTORYING, access_cb)

        reader_clients.append(reader)

    # start runtime measurement to determine rates
    start_time = monotonic()
    try:
        for reader in reader_clients:
            reader.connect()
    except:
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



