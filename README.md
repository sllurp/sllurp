# sllurp

**IMPORTANT:** This is beta-quality software that changes frequently.  Use at
your own risk.

This repository began in August 2013 as a snapshot of the dormant [LLRPyC
project][]'s [code][] on SourceForge.  It has been updated to work with Impinj
Speedway readers (and probably still other readers), and to provide a simple
callback-based API to clients.

These readers are known to work well with sllurp, but it should be adaptable
with not much effort to other LLRP-compatible readers:

 * Impinj Speedway (R1000)
 * Impinj Speedway Revolution (R220, R420)
 * Impinj Speedway xPortal

File an issue on this GitHub project if you would like help getting another
kind of reader to work.

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
logging.getLogger().setLevel(logging.INFO)

def cb (tagReport):
    tags = tagReport.msgdict['RO_ACCESS_REPORT']['TagReportData']
    print 'tags:', tags

factory = llrp.LLRPClientFactory()
factory.addTagReportCallback(cb)
reactor.connectTCP('myreader', llrp.LLRP_PORT, factory)
reactor.run()
```

[Twisted]: http://twistedmatrix.com/

## Getting More Information From Tag Reports
When initializing LLRPClientFactory, pass in tag_content_selector:
```python
llrp.LLRPClientFactory(tag_content_selector={
    'EnableROSpecID': False,
    'EnableSpecIndex': False,
    'EnableInventoryParameterSpecID': False,
    'EnableAntennaID': True,
    'EnableChannelIndex': False,
    'EnablePeakRRSI': True,
    'EnableFirstSeenTimestamp': False,
    'EnableLastSeenTimestamp': True,
    'EnableTagSeenCount': True,
    'EnableAccessSpecID': False,
}

```

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

## If You Find a Bug

Start an issue on this GitHub project!

Bug reports are most useful when they're accompanied by verbose error messages.
Turn sllurp's log level up to DEBUG, which you can do by specifying the `-d`
command-line option if you're using the `inventory` or `reset` scripts.  You
can log to a logfile with the `-l [filename]` option.  Or simply put this at
the beginning of your own code:

    import logger
    sllurp_logger = logging.getLogger('sllurp')
    sllurp_logger.setLevel(logging.DEBUG)

## Contributing

Want to contribute?  Here are some areas that need improvement:

 * Reduce redundancy in the `encode_*` and `decode_*` functions in
   `llrp_proto.py`.
 * Support the AccessSpec primitive (basis for tag read and write).
 * Write tests for common encoding and decoding tasks.
 * Make `get_reader_config` use the `fabric` library to connect to readers via
   SSH.
 * Generalize LLRP support beyond Impinj readers.  Remove Impinj-specific
   assumptions.
