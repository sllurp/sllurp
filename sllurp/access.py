from __future__ import print_function
import argparse
import binascii
import logging
import pprint
import sys
import time
from twisted.internet import reactor, defer

import sllurp.llrp as llrp

startTime = None
endTime = None

tagReport = 0
logger = logging.getLogger('sllurp')

args = None


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

    return proto.startAccess(readWords=readSpecParam,
                             writeWords=writeSpecParam)


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


def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Simple RFID Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
                        nargs='*')
    parser.add_argument('-p', '--port', default=llrp.LLRP_PORT, type=int,
                        help='port (default {})'.format(llrp.LLRP_PORT))
    parser.add_argument('-t', '--time', default=10, type=float,
                        help='number of seconds to inventory (default 10)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='show debugging output')
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
                        dest='every_n', metavar='N',
                        help='issue a TagReport every N tags')
    parser.add_argument('-X', '--tx-power', default=0, type=int,
                        dest='tx_power',
                        help='Transmit power (default 0=max power)')
    parser.add_argument('-M', '--modulation', default='M8',
                        help='modulation (default M8)')
    parser.add_argument('-T', '--tari', default=0, type=int,
                        help='Tari value (default 0=auto)')
    parser.add_argument('-s', '--session', default=2, type=int,
                        help='Gen2 session (default 2)')
    parser.add_argument('-P', '--tag-population', default=4, type=int,
                        dest='population',
                        help='Tag Population value (default 4)')

    # read or write
    op = parser.add_mutually_exclusive_group(required=True)
    op.add_argument('-r', '--read-words', type=int,
                    help='Number of words to read')
    op.add_argument('-w', '--write-words', type=int,
                    help='Number of words to write')

    # C1G2 Read / Write parameters:
    parser.add_argument('-mb', '--memory-bank', default=3, type=int,
                        dest='mb',
                        help='Memory bank: 3 User, 2 TID, 1 EPC, 0 Reserved')
    parser.add_argument('-wp', '--word-ptr', default=0, type=int,
                        dest='word_ptr',
                        help='Word addresss of the first word to read/write')

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
                                     'EnablePeakRRSI': True,
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
    startTimeMeasurement()

    reactor.run()


if __name__ == '__main__':
    main()
