from __future__ import print_function
import argparse
import csv
import logging
import threading
from twisted.internet import reactor, task

import sllurp.llrp as llrp
from sllurp.llrp_proto import Modulation_Name2Type, DEFAULT_MODULATION, \
    Modulation_DefaultTari
from sllurp.log import init_logging


numTags = 0
logger = logging.getLogger('sllurp')
csvlogger = None


class CsvLogger(object):
    def __init__(self, filename, epc=None, factory=None):
        self.rows = []
        self.filename = filename
        self.num_tags = 0
        self.epc = epc
        self.factory = factory
        self.lock = threading.Lock()

    def next_proto(self, curr_proto):
        protos = self.factory.protocols
        next_p = protos[(protos.index(curr_proto) + 1) % len(protos)]
        logger.debug('After %s comes %s', curr_proto.peername, next_p.peername)
        return next_p

    def tag_cb(self, llrp_msg):
        host, port = llrp_msg.peername
        reader = '{}:{}'.format(host, port)
        logger.info('RO_ACCESS_REPORT from %s', reader)
        tags = llrp_msg.msgdict['RO_ACCESS_REPORT']['TagReportData']
        for tag in tags:
            epc = tag['EPCData']['EPC'] if 'EPCData' in tag else tag['EPC-96']
            if self.epc is not None and epc != self.epc:
                return
            timestamp_us = tag['LastSeenTimestampUTC'][0]
            antenna = tag['AntennaID'][0]
            rssi = tag['PeakRSSI'][0]
            self.rows.append((timestamp_us, reader, antenna, rssi, epc))
            self.num_tags += tag['TagSeenCount'][0]
        with self.lock:
            logger.debug('This proto: %r (%s)', llrp_msg.proto,
                         llrp.LLRPClient.getStateName(llrp_msg.proto.state))
            next_p = self.next_proto(llrp_msg.proto)
            logger.debug('Next proto: %r (%s)', next_p,
                         llrp.LLRPClient.getStateName(next_p.state))
            d = llrp_msg.proto.pause()
            if d is not None:
                d.addCallback(lambda _: next_p.resume())
                d.addErrback(print, 'argh')

    def flush(self):
        logging.info('Writing %d rows to %s...', len(self.rows), self.filename)
        with open(self.filename, 'w') as csv_out:
            wri = csv.writer(csv_out, dialect='excel')
            wri.writerow(('timestamp_us', 'reader', 'antenna', 'rssi', 'epc'))
            wri.writerows(self.rows)


def finish():
    csvlogger.flush()
    # if reactor.running:
    #     reactor.stop()
    logging.info('Total tags seen: %d', csvlogger.num_tags)


def parse_args():
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
    parser.add_argument('-n', '--report-every-n-tags', type=int,
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
    parser.add_argument('-g', '--stagger', type=int,
                        help='delay (ms) between connecting to readers')
    parser.add_argument('-e', '--epc', type=str,
                        help='log only a specific epc')
    return parser.parse_args()


def main():
    global csvlogger
    args = parse_args()
    init_logging(debug=args.debug, logfile=args.logfile)

    # special case default Tari values
    if args.modulation in Modulation_DefaultTari:
        t_suggested = Modulation_DefaultTari[args.modulation]
        if not args.tari:
            args.tari = t_suggested

    enabled_antennas = map(lambda x: int(x.strip()), args.antennas.split(','))

    fac = llrp.LLRPClientFactory(start_first=True,
                                 duration=args.time,
                                 report_every_n_tags=args.every_n,
                                 antennas=enabled_antennas,
                                 tx_power=args.tx_power,
                                 modulation=args.modulation,
                                 tari=args.tari,
                                 session=args.session,
                                 tag_population=args.population,
                                 start_inventory=False,
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
                                 })

    csvlogger = CsvLogger(args.csvfile, epc=args.epc, factory=fac)
    fac.addTagReportCallback(csvlogger.tag_cb)

    delay = 0
    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port
        if args.stagger is not None:
            logging.debug('Will connect to %s:%d in %d ms', host, port, delay)
            task.deferLater(reactor, delay/1000.0,
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
