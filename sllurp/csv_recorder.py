from __future__ import print_function
import argparse
import csv
import logging
from twisted.internet import reactor, defer, task

import sllurp.llrp as llrp
from sllurp.llrp_proto import Modulation_Name2Type, DEFAULT_MODULATION, \
    Modulation_DefaultTari
from sllurp.inventory import init_logging


numTags = 0
args = None
logger = logging.getLogger('sllurp')
csvlogger = None


class CsvLogger(object):
    def __init__(self, filename):
        self.rows = []
        self.filename = filename
        self.num_tags = 0

    def tag_cb(self, llrp_msg):
        reader = llrp_msg.peername[0]
        tags = llrp_msg.msgdict['RO_ACCESS_REPORT']['TagReportData']
        for tag in tags:
            timestamp_us = tag['LastSeenTimestampUTC'][0]
            antenna = tag['AntennaID'][0]
            epc = tag['EPCData']['EPC'] if 'EPCData' in tag else tag['EPC-96']
            rssi = tag['PeakRSSI'][0]
            self.rows.append((timestamp_us, reader, antenna, rssi, epc))
            self.num_tags += tag['TagSeenCount'][0]

    def flush(self):
        logging.info('Writing %d rows to %s...', len(self.rows), self.filename)
        with open(self.filename, 'w') as csv_out:
            wri = csv.writer(csv_out, dialect='excel')
            wri.writerow(('timestamp_us', 'reader', 'antenna', 'rssi', 'epc'))
            wri.writerows(self.rows)


def finish():
    csvlogger.flush()
    #if reactor.running:
    #    reactor.stop()
    logging.info('Total tags seen: %d', csvlogger.num_tags)


def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Simple RFID Inventory')
    parser.add_argument('csvfile', help='CSV file to write')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
                        nargs='+')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT, type=int,
                        help='port (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-t', '--time', type=float,
                        help='seconds to inventory (default forever)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='show debugging output')
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
                        dest='every_n', metavar='N',
                        help='issue a TagReport every N tags')
    parser.add_argument('-a', '--antennas', default='1',
                        help='comma-separated list of antennas to use (0=all;'
                        ' default 1)')
    parser.add_argument('-X', '--tx-power', default=0, type=int,
                        dest='tx_power',
                        help='transmit power (default 0=max power)')
    mods = sorted(Modulation_Name2Type.keys())
    parser.add_argument('-M', '--modulation', default=DEFAULT_MODULATION,
                        choices=mods,
                        help='modulation (default={})'.format(
                            DEFAULT_MODULATION))
    parser.add_argument('-T', '--tari', default=0, type=int,
                        help='Tari value (default 0=auto)')
    parser.add_argument('-s', '--session', default=2, type=int,
                        help='Gen2 session (default 2)')
    parser.add_argument('-P', '--tag-population', default=4, type=int,
                        dest='population',
                        help="Tag Population value (default 4)")
    parser.add_argument('-l', '--logfile')
    parser.add_argument('-r', '--reconnect', action='store_true',
                        default=False,
                        help='reconnect on connection failure or loss')
    parser.add_argument('-i', '--start-period', type=int,
                        help='period (ms) between inventory starts')
    parser.add_argument('-g', '--stagger', type=int,
                        help='delay (ms) between connecting to readers')
    args = parser.parse_args()


def main():
    global csvlogger
    parse_args()
    init_logging(args)

    # special case default Tari values
    if args.modulation in Modulation_DefaultTari:
        t_suggested = Modulation_DefaultTari[args.modulation]
        if not args.tari:
            args.tari = t_suggested

    enabled_antennas = map(lambda x: int(x.strip()), args.antennas.split(','))

    fac = llrp.LLRPClientFactory(duration=args.time,
                                 report_every_n_tags=args.every_n,
                                 antennas=enabled_antennas,
                                 tx_power=args.tx_power,
                                 modulation=args.modulation,
                                 tari=args.tari,
                                 session=args.session,
                                 tag_population=args.population,
                                 start_inventory=True,
                                 disconnect_when_done=(args.time > 0),
                                 reconnect=args.reconnect,
                                 tag_content_selector={
                                     'EnableROSpecID': False,
                                     'EnableSpecIndex': False,
                                     'EnableInventoryParameterSpecID': False,
                                     'EnableAntennaID': True,
                                     'EnableChannelIndex': False,
                                     'EnablePeakRRSI': True,
                                     'EnableFirstSeenTimestamp': False,
                                     'EnableLastSeenTimestamp': True,
                                     'EnableTagSeenCount': True,
                                     'EnableAccessSpecID': False
                                 },
                                 rospec_period=args.start_period)

    csvlogger = CsvLogger(args.csvfile)
    fac.addTagReportCallback(csvlogger.tag_cb)

    delay = 0
    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port
        logging.info('Connecting to %s:%d...', host, port)
        if args.stagger is not None:
            task.deferLater(reactor, delay,
                            reactor.connectTCP,
                            host, port, fac, timeout=3)
            delay += args.stagger
        else:
            reactor.connectTCP(host, port, fac, timeout=3)

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', finish)

    reactor.run()


if __name__ == '__main__':
    main()
