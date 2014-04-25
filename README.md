# sllurp

This repository began in August 2013 as a snapshot of the dormant [LLRPyC
project][]'s [code][] on SourceForge.  It has been updated to work with Impinj
Speedway readers (and probably still other readers), and to provide a simple
callback-based API to clients.

[LLRPyC project]: http://wiki.enneenne.com/index.php/LLRPyC
[code]: http://sourceforge.net/projects/llrpyc/

## Quick Start

Install a version of [Twisted][] appropriate for your Python installation.  For
Windows users, choose the appropriate `.exe` installer at the Twisted website,
and install [zope.interface][] with the same parameters.

To connect to a reader and perform EPC Gen 2 inventory for 10 seconds:

1. Figure out your reader's IP address `ip.add.re.ss`
2. `bin/inventory ip.add.re.ss`

Run `bin/inventory -h` to see options.

If the reader gets into a funny state because you're debugging against it, you
can stop all ROSpecs by running `bin/reset ip.add.re.ss`.

(On Windows, substitute `bin\windows\inventory.bat` for the inventory script,
and do the same for the reset script.)

[Twisted]: http://twistedmatrix.com/
[zope.interface]: https://pypi.python.org/pypi/zope.interface#download

## Reader API

sllurp relies on Twisted for network interaction with the reader.  To make a
connection, create an `LLRPClientFactory` and hand it to Twisted:

```python
# Minimal example; see inventory.py for more.
from sllurp import llrp
from twisted.internet import reactor
import logging

logger = logging.getLogger('sllurp')
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())
logger.propagate = False

host = 's2'
wrapper = llrp.ProtocolWrapper()
factory = llrp.LLRPClientFactory(wrapper)
reactor.connectTCP(host, llrp.LLRP_PORT, factory)
reactor.run()
```

[Twisted]: http://twistedmatrix.com/

## Getting More Information From Tag Reports

Edit `sllurp/llrp_proto.py` and configure the `ROSpec` in `LLRPROSpec.__init__`
to your liking.  E.g., you can change
`self['ROSpec']['ROReportSpec']['TagReportContentSelector']['EnableFirstSeenTimestamp']`
to `True`.

XXX Note: this hackish method will go away.

## Logging

sllurp logs under the name `sllurp`, so if you wish to log its output, you can
do this the application that imports sllurp:

    sllurp_logger = logging.getLogger('sllurp')
    sllurp_logger.setLevel(logging.DEBUG)
    sllurp_logger.setHandler(logging.FileHandler('sllurp.log'))
    # or .setHandler(logging.StreamHandler()) to log to stderr...

## Handy Reader Commands

To see what inventory settings an Impinj reader is currently using (i.e., to
fetch the current ROSpec), ssh to the reader and

    > show rfid llrp rospec 0

You can dump the reader's entire configuration, including the current ROSpec,
to a set of files by running `bin/get_reader_config`.

The "nuclear option" for resetting a reader is:

    > reboot

## Contributing

Want to contribute?  Here are some areas that need improvement:

 * Reduce redundancy in the `encode_*` and `decode_*` functions in
   `llrp_proto.py`.
 * Support the AccessSpec primitive (basis for tag read and write).
 * Write tests for common encoding and decoding tasks.
