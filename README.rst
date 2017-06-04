.. image:: http://img.shields.io/pypi/v/sllurp.svg
    :target: https://pypi.python.org/pypi/sllurp

.. image:: https://travis-ci.org/ransford/sllurp.svg?branch=master
    :target: https://travis-ci.org/ransford/sllurp

sllurp is a Python library to interface with RFID readers.  It is a pure-Python
implementation of the Low Level Reader Protocol (LLRP).

These readers are known to work well with sllurp, but it should be adaptable
with not much effort to other LLRP-compatible readers:

- Impinj Speedway (R1000)
- Impinj Speedway Revolution (R220, R420)
- Impinj Speedway xPortal
- Motorola MC9190-Z (handheld)

File an issue on GitHub_ if you would like help getting another kind of reader
to work.

sllurp is distributed under version 3 of the GNU General Public License.  See
``LICENSE.txt`` for details.

.. _GitHub: https://github.com/ransford/sllurp/

Quick Start
-----------

Install from PyPI_::

    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install sllurp
    $ sllurp inventory ip.add.re.ss

Run ``sllurp --help`` and ``sllurp inventory --help`` to see options.

Or install from GitHub_::

    $ git clone https://github.com/ransford/sllurp.git
    $ cd sllurp
    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install .
    $ sllurp inventory ip.add.re.ss

If the reader gets into a funny state because you're debugging against it
(e.g., if your program or sllurp has crashed), you can set it back to an idle
state by running ``sllurp reset ip.add.re.ss``.

.. _PyPI: https://pypi.python.org/pypi/sllurp
.. _GitHub: https://github.com/ransford/sllurp/

Reader API
----------

sllurp relies on Twisted_ for network interaction with the reader.  To make a
connection, create an `LLRPClientFactory` and hand it to Twisted:

.. code:: python

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

.. _Twisted: http://twistedmatrix.com/

Getting More Information From Tag Reports
-----------------------------------------

When initializing ``LLRPClientFactory``, set flags in the
``tag_content_selector`` dictionary argument:

.. code:: python

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
    }, ...)


Logging
-------

sllurp logs under the name ``sllurp``, so if you wish to log its output, you
can do this the application that imports sllurp:

.. code:: python

    sllurp_logger = logging.getLogger('sllurp')
    sllurp_logger.setLevel(logging.DEBUG)
    sllurp_logger.setHandler(logging.FileHandler('sllurp.log'))
    # or .setHandler(logging.StreamHandler()) to log to stderr...

Handy Reader Commands
---------------------

To see what inventory settings an Impinj reader is currently using (i.e., to
fetch the current ROSpec), ssh to the reader and

::

    > show rfid llrp rospec 0

The "nuclear option" for resetting a reader is:

::

    > reboot

If You Find a Bug
-----------------

Start an issue on GitHub_!

Bug reports are most useful when they're accompanied by verbose error messages.
Turn sllurp's log level up to DEBUG, which you can do by specifying the `-d`
command-line option to ``sllurp``.  You can log to a logfile with the ``-l
[filename]`` option.  Or simply put this at the beginning of your own code:

.. code:: python

  import logger
  sllurp_logger = logging.getLogger('sllurp')
  sllurp_logger.setLevel(logging.DEBUG)

.. _GitHub: https://github.com/ransford/sllurp/

Contributing
------------

Want to contribute?  Here are some areas that need improvement:

- Reduce redundancy in the ``encode_*`` and ``decode_*`` functions in
  ``llrp_proto.py``.
- Support the AccessSpec primitive (basis for tag read and write).
- Write tests for common encoding and decoding tasks.
- Make ``get_reader_config`` use the ``fabric`` library to connect to readers
  via SSH.
- Generalize LLRP support beyond Impinj readers.  Remove Impinj-specific
  assumptions.

Authors
-------

Much of the code in sllurp is by `Ben Ransford`_, although it began its life in
August 2013 as a fork of LLRPyC_.  Many fine citizens of GitHub have
contributed code to sllurp since the fork.

.. _Ben Ransford: https://ben.ransford.org/
.. _LLRPyC: https://sourceforge.net/projects/llrpyc/
