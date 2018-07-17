"""Simple tag logger.

Logs tag sightings at one or more readers to a CSV file.
"""


from __future__ import print_function, unicode_literals
import csv
import datetime
import logging
import threading
from twisted.internet import reactor

import sllurp.llrp as llrp


numTags = 0
logger = logging.getLogger(__name__)
csvlogger = None


class CsvLogger(object):
    def __init__(self, filehandle, epc=None, factory=None,
                 reader_timestamp=False):
        self.rows = []
        self.filehandle = filehandle
        self.num_tags = 0
        self.epc = epc
        self.factory = factory
        self.lock = threading.Lock()
        self.reader_timestamp = reader_timestamp

    def tag_cb(self, llrp_msg):
        host, port = llrp_msg.peername
        reader = '{}:{}'.format(host, port)
        logger.info('RO_ACCESS_REPORT from %s', reader)
        tags = llrp_msg.msgdict['RO_ACCESS_REPORT']['TagReportData']
        for tag in tags:
            epc = tag['EPCData']['EPC'] if 'EPCData' in tag else tag['EPC-96']
            if self.epc is not None and epc != self.epc:
                continue
            if self.reader_timestamp:
                timestamp = tag['LastSeenTimestampUTC'][0] / 1e6
            else:
                timestamp = (datetime.datetime.utcnow() -
                             datetime.datetime(1970, 1, 1)).total_seconds()
            antenna = tag['AntennaID'][0]
            rssi = tag['PeakRSSI'][0]
            self.rows.append((timestamp, reader, antenna, rssi, epc))
            self.num_tags += tag['TagSeenCount'][0]

    def flush(self):
        logger.info('Writing %d rows...', len(self.rows))
        wri = csv.writer(self.filehandle, dialect='excel')
        wri.writerow(('timestamp', 'reader', 'antenna', 'rssi', 'epc'))
        wri.writerows(self.rows)


def finish():
    csvlogger.flush()
    # if reactor.running:
    #     reactor.stop()
    logger.info('Total tags seen: %d', csvlogger.num_tags)


def main(hosts, outfile, antennas, epc, reader_timestamp):
    global csvlogger

    enabled_antennas = map(lambda x: int(x.strip()), antennas.split(','))

    fac = llrp.LLRPClientFactory(start_first=True,
                                 antennas=enabled_antennas,
                                 start_inventory=False,
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
                                     'EnableAccessSpecID': False
                                 })

    csvlogger = CsvLogger(outfile, epc=epc, factory=fac,
                          reader_timestamp=reader_timestamp)
    fac.addTagReportCallback(csvlogger.tag_cb)

    for host in hosts:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = 5084
        reactor.connectTCP(host, port, fac, timeout=3)

    # catch ctrl-C and stop logging before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', finish)

    reactor.run()


if __name__ == '__main__':
    main()
