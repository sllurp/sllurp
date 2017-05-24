from __future__ import print_function
import argparse
import logging
import pprint
import time
from twisted.internet import reactor, defer

import sllurp.llrp as llrp
from sllurp.llrp_proto import Modulation_Name2Type, DEFAULT_MODULATION, \
    Modulation_DefaultTari

startTime = None
endTime = None

numTags = 0
logger = logging.getLogger('sllurp')


def startTimeMeasurement():
    global startTime
    startTime = time.time()


def stopTimeMeasurement():
    global endTime
    endTime = time.time()


def finish(_):
    global startTime
    global endTime

    # stop runtime measurement to determine rates
    stopTimeMeasurement()
    runTime = (endTime - startTime) if (endTime > startTime) else 0

    logger.info('total # of tags seen: %d (%d tags/second)', numTags,
                numTags/runTime)
    if reactor.running:
        reactor.stop()


def politeShutdown(factory):
    return factory.politeShutdown()


def tagReportCallback(llrpMsg):
    """Function to run each time the reader reports seeing tags."""
    global numTags
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(tags):
        logger.info('saw tag(s): %s', pprint.pformat(tags))
    else:
        logger.info('no tags seen')
        return
    for tag in tags:
        numTags += tag['TagSeenCount'][0]


def main(args):
    # special case default Tari values
    if args.modulation in Modulation_DefaultTari:
        t_suggested = Modulation_DefaultTari[args.modulation]
        if args.tari:
            logger.warn('recommended Tari for %s is %d', args.modulation,
                        t_suggested)
        else:
            args.tari = t_suggested
            logger.info('selected recommended Tari of %d for %s', args.tari,
                        args.modulation)

    enabled_antennas = map(lambda x: int(x.strip()), args.antennas.split(','))

    # d.callback will be called when all connections have terminated normally.
    # use d.addCallback(<callable>) to define end-of-program behavior.
    d = defer.Deferred()
    d.addCallback(finish)

    fac = llrp.LLRPClientFactory(onFinish=d,
                                 duration=args.time,
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
                                 })

    # tagReportCallback will be called every time the reader sends a TagReport
    # message (i.e., when it has "seen" tags).
    fac.addTagReportCallback(tagReportCallback)

    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port
        reactor.connectTCP(host, port, fac, timeout=3)

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', politeShutdown, fac)

    # start runtime measurement to determine rates
    startTimeMeasurement()

    reactor.run()
