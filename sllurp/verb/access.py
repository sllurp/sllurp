from __future__ import print_function, unicode_literals
import binascii
import logging
import pprint
import sys
from monotonic import monotonic
from twisted.internet import reactor, defer

import sllurp.llrp as llrp

startTime = None

tagReport = 0
logger = logging.getLogger('sllurp')

args = None


def finish(_):
    # stop runtime measurement to determine rates
    runTime = monotonic() - startTime

    logger.info('total # of tags seen: %d (%d tags/second)', tagReport,
                tagReport/runTime)
    if reactor.running:
        reactor.stop()


def access(proto):
    readSpecParam = None
    if args.read_words:
        readSpecParam = {
            'OpSpecID': 0,
            'MB': args.mb,
            'WordPtr': args.word_ptr,
            'AccessPassword': args.access_password,
            'WordCount': args.read_words
        }

    writeSpecParam = None
    if args.write_words:
        # get the binary data from the standard input stream
        if sys.version_info.major < 3:
            data = sys.stdin.read(args.write_words * 2)
        else:
            data = sys.stdin.buffer.read(args.write_words * 2)        # bytes
        writeSpecParam = {
            'OpSpecID': 0,
            'MB': args.mb,
            'WordPtr': args.word_ptr,
            'AccessPassword': args.access_password,
            'WriteDataWordCount': args.write_words,
            'WriteData': data,
        }

    accessStopParam = {
        'AccessSpecStopTriggerType': 1 if args.count > 0 else 0,
        'OperationCountValue': args.count,
    }
    return proto.startAccess(readWords=readSpecParam,
                             writeWords=writeSpecParam,
                             accessStopParam=accessStopParam)


def politeShutdown(factory):
    return factory.politeShutdown()


def tagReportCallback(llrpMsg):
    """Function to run each time the reader reports seeing tags."""
    global tagReport
    tags = llrpMsg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(tags):
        logger.info('saw tag(s): %s', pprint.pformat(tags))
    else:
        logger.info('no tags seen')
        return
    for tag in tags:
        tagReport += tag['TagSeenCount'][0]
        if "OpSpecResult" in tag:
            # copy the binary data to the standard output stream
            data = tag["OpSpecResult"].get("ReadData")
            if data:
                if sys.version_info.major < 3:
                    sys.stdout.write(data)
                else:
                    sys.stdout.buffer.write(data)                     # bytes
                logger.debug("hex data: %s", binascii.hexlify(data))


def main(main_args):
    global startTime
    global args
    args = main_args

    # will be called when all connections have terminated normally
    onFinish = defer.Deferred()
    onFinish.addCallback(finish)

    fac = llrp.LLRPClientFactory(onFinish=onFinish,
                                 disconnect_when_done=True,
                                 modulation=args.modulation,
                                 tari=args.tari,
                                 session=args.session,
                                 tag_population=args.population,
                                 start_inventory=True,
                                 tx_power=args.tx_power,
                                 report_every_n_tags=args.every_n,
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
                                     'EnableAccessSpecID': True
                                 })

    # tagReportCallback will be called every time the reader sends a TagReport
    # message (i.e., when it has "seen" tags).
    fac.addTagReportCallback(tagReportCallback)

    # start tag access once inventorying
    fac.addStateCallback(llrp.LLRPClient.STATE_INVENTORYING, access)

    for host in args.host:
        reactor.connectTCP(host, args.port, fac, timeout=3)

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', politeShutdown, fac)

    # start runtime measurement to determine rates
    startTime = monotonic()

    reactor.run()


if __name__ == '__main__':
    main()
