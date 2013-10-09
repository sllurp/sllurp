#!/usr/bin/env python

import logging
from llrp_proto import LLRPROSpec

logLevel = logging.DEBUG
logging.basicConfig(level=logLevel,
        format='%(asctime)s: %(levelname)s: %(message)s')
logging.log(logLevel, 'log level: {}'.format(logging.getLevelName(logLevel)))
logging.getLogger('llrpc').setLevel(logLevel)

rospec = LLRPROSpec(1)
print rospec
