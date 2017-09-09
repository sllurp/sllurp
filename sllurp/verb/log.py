"""Simple tag logger.

Logs tag sightings at one or more readers to a CSV file.
"""


from __future__ import print_function, unicode_literals
import csv
import logging
import threading
from twisted.internet import reactor, task

import sllurp.llrp as llrp


numTags = 0
logger = logging.getLogger('sllurp')
csvlogger = None


class CsvLogger(object):
    def __init__(self, filehandle, epc=None, factory=None):
        self.rows = []
        self.filehandle = filehandle
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
        logger.info('Writing %d rows...', len(self.rows))
        wri = csv.writer(self.filehandle, dialect='excel')
        wri.writerow(('timestamp_us', 'reader', 'antenna', 'rssi', 'epc'))
        wri.writerows(self.rows)


def finish():
    csvlogger.flush()
    # if reactor.running:
    #     reactor.stop()
    logger.info('Total tags seen: %d', csvlogger.num_tags)


def main(hosts, outfile, antennas, epc):
    global csvlogger

    enabled_antennas = map(lambda x: int(x.strip()), antennas.split(','))

    fac = llrp.LLRPClientFactory(start_first=True,
                                 report_every_n_tags=1,
                                 antennas=enabled_antennas,
                                 start_inventory=False,
                                 disconnect_when_done=True,
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

    csvlogger = CsvLogger(outfile, epc=epc, factory=fac)
    fac.addTagReportCallback(csvlogger.tag_cb)

    delay = 0
    for host in hosts:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = 5084
        reactor.connectTCP(host, port, fac, timeout=3)

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', finish)

    reactor.run()


if __name__ == '__main__':
    main()
