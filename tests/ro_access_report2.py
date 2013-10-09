#!/usr/bin/env python

import llrp_proto
import logging
import pprint

RO_ACCESS_REPORT = \
    '00f0001f8d35e0170043babbce0000142581000186d8820003dc466a8af0d0'.decode('hex')

logLevel = logging.DEBUG
logging.basicConfig(level=logLevel,
        format='%(asctime)s: %(levelname)s: %(message)s')
logging.log(logLevel, 'log level: {}'.format(logging.getLevelName(logLevel)))
logging.getLogger('llrpc').setLevel(logLevel)

llrp_proto.decode_ROAccessReport(RO_ACCESS_REPORT)
