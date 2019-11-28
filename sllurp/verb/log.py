"""Simple tag logger.

Logs tag sightings at one or more readers to a CSV file.
"""


from __future__ import print_function, unicode_literals
import csv
import datetime
import logging

from sllurp.llrp import LLRPReaderConfig, LLRPReaderClient
from sllurp.log import get_logger


numTags = 0
logger = get_logger(__name__)
csvlogger = None


class CsvLogger(object):
    def __init__(self, filehandle, epc=None, reader_timestamp=False):
        self.rows = []
        self.filehandle = filehandle
        self.num_tags = 0
        self.epc = epc
        self.reader_timestamp = reader_timestamp

    def tag_cb(self, reader, tags):
        host, port = reader.get_peername()
        reader = '{}:{}'.format(host, port)
        logger.info('RO_ACCESS_REPORT from %s', reader)
        for tag in tags:
            epc = tag['EPC']
            if self.epc is not None and epc != self.epc:
                continue
            if self.reader_timestamp:
                timestamp = tag['LastSeenTimestampUTC'] / 1e6
            else:
                timestamp = (datetime.datetime.utcnow() -
                             datetime.datetime(1970, 1, 1)).total_seconds()
            antenna = tag['AntennaID']
            rssi = tag['PeakRSSI']
            self.rows.append((timestamp, reader, antenna, rssi, epc))
            self.num_tags += tag['TagSeenCount']

    def flush(self):
        logger.info('Writing %d rows...', len(self.rows))
        wri = csv.writer(self.filehandle, dialect='excel')
        wri.writerow(('timestamp', 'reader', 'antenna', 'rssi', 'epc'))
        wri.writerows(self.rows)


def finish_cb(reader):
    # Following would be possible, but then concurrent file write would have
    # to be handled. So it is more convenient to do it at the end of main.
    #csvlogger.flush()
    logger.info('Total tags seen: %d', csvlogger.num_tags)


def main(args):
    global csvlogger

    # Arguments:
    # host, port, outfile, antennas, tx_power, epc, reader_timestamp
    if not args.host:
        logger.info('No readers specified.')
        return 0

    if not args.outfile:
        logger.info('No output file specified.')
        return 0

    enabled_antennas = [int(x.strip()) for x in args.antennas.split(',')]
    frequency_list = [int(x.strip()) for x in args.frequencies.split(',')]

    factory_args = dict(
        antennas=enabled_antennas,
        tx_power=args.tx_power,
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
    )
    if frequency_list[0] == 0:
        factory_args['frequencies']['Automatic'] = True
        factory_args['frequencies']['ChannelList'] = [1]

    csvlogger = CsvLogger(args.outfile, epc=args.epc,
                          reader_timestamp=args.reader_timestamp)

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
        reader.add_tag_report_callback(csvlogger.tag_cb)
        reader_clients.append(reader)

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

    csvlogger.flush()

