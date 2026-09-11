======================================================================
sllurp is a pure-python client and library for LLRP-based RFID readers
======================================================================


.. image:: http://img.shields.io/pypi/v/sllurp.svg
    :target: https://pypi.python.org/pypi/sllurp

.. image:: https://img.shields.io/pypi/pyversions/sllurp.svg
    :target: https://pypi.python.org/pypi/sllurp

.. image:: https://github.com/sllurp/sllurp/actions/workflows/test.yml/badge.svg
    :target: https://github.com/sllurp/sllurp/actions/workflows/test.yml

sllurp is a Python library to interface with RFID readers.  It is a pure-Python
implementation of the Low Level Reader Protocol (LLRP).

These readers are known to work well with sllurp, but it should be adaptable
with not much effort to other LLRP-compatible readers:

- Impinj Speedway (R1000)
- Impinj Speedway Revolution (R220, R420)
- Impinj Speedway xPortal
- Motorola MC9190-Z (handheld)
- Zebra Fixed RFID Reader (FX7500, FX9600, FXR90 family)

Zebra HTTP/HTTPS management adapters additionally cover the documented RM
interface on FX7400, FX7500, FX9500, FX9600, and ATR7000, plus Zebra IoT
Connector local REST on supported FX7500/FX9600/ATR7000 firmware and FXR90.
See ``docs/reader-management.rst`` for the model capability matrix and examples.

File an issue on GitHub_ if you would like help getting another kind of reader
to work.

sllurp is distributed under version 3 of the GNU General Public License.  See
``LICENSE.txt`` for details.

Quick Start
-----------

Install from PyPI_::

    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip install sllurp
    $ sllurp inventory ip.add.re.ss

Run ``sllurp --help`` and ``sllurp inventory --help`` to see options.

Or install from GitHub_::

    $ git clone https://github.com/sllurp/sllurp.git
    $ cd sllurp
    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip install .
    $ sllurp inventory ip.add.re.ss

If the reader gets into a funny state because you're debugging against it
(e.g., if your program or sllurp has crashed), you can set it back to an idle
state by running ``sllurp reset ip.add.re.ss``.

.. _PyPI: https://pypi.python.org/pypi/sllurp


Zebra FXR90
-----------

The FXR90 family can be used through its LLRP interface.  sllurp keeps antenna
handling capability-driven rather than hard-coding a particular FXR90 SKU, so
the same code works with the 4-port, integrated-antenna plus external-port, and
8-port variants.  Use antenna ``0`` to request all antennas exposed by the
reader::

    $ sllurp inventory -a 0 fxr90.example

For readers configured for secure LLRP, enable TLS.  The default is to verify
the reader certificate using the operating system trust store; a private CA
bundle can be supplied explicitly::

    $ sllurp inventory --tls --tls-ca-file /path/to/reader-ca.pem -a 0 fxr90.example

If the reader requires client-certificate authentication, also provide a
certificate and its private key::

    $ sllurp inventory --tls --tls-client-cert client.pem --tls-client-key client.key fxr90.example

When connecting to an IP address while the certificate is issued to a DNS
name, use ``--tls-server-hostname`` to set the TLS SNI/certificate hostname.
``--tls-no-verify`` is available for controlled test environments, but disables
certificate validation and should not be used as the normal production setup.

FXR90 management is also available through Zebra IoT Connector local REST using
``sllurp.zebra_management.ZebraIoTConnectorManager``.  LLRP remains the reader
inventory/control protocol; the REST adapter is for the reader's separate web
management surface.

Reader API
----------

sllurp spawn his own "thread" to manage network interaction with the reader.
To make a connection, create a ``LLRPReaderClient`` and ``connect()`` it:

.. code:: python

    # Minimal example; see sllurp/verb/inventory.py for more.
    from sllurp import llrp
    from sllurp.llrp import LLRPReaderConfig, LLRPReaderClient, LLRP_DEFAULT_PORT
    import logging
    logging.getLogger().setLevel(logging.INFO)

    def tag_report_cb (reader, tag_reports):
        for tag in tag_reports:
            print('tag: %r' % tag)

    config = LLRPReaderConfig()
    reader = LLRPReaderClient(host, LLRP_DEFAULT_PORT, config)
    reader.add_tag_report_callback(tag_report_cb)

    reader.connect()
    # We are now connected to the reader and inventory is running.

    try:
        # Block forever or until a disconnection of the reader
        reader.join(None)
    except (KeyboardInterrupt, SystemExit):
        # catch ctrl-C and stop inventory before disconnecting
        reader.disconnect()

.. note::

    Sllurp used to depend on python twisted and was using its mainloop.
    This is not the case anymore.
    Once connected to a reader, Sllurp will spawn his own "thread" to process
    the received messages and to call user defined callbacks.
    ``is_alive()`` and ``join(timeout)`` thread api are exposed by the
    ``LLRPReaderClient`` instance.


Getting More Information From Tag Reports
-----------------------------------------

When initializing ``LLRPReaderConfig``, set flags in the
``tag_content_selector`` dictionary argument:

.. code:: python

    llrp.LLRPReaderConfig({
        'tag_content_selector': {
            'EnableROSpecID': False,
            'EnableSpecIndex': False,
            'EnableInventoryParameterSpecID': False,
            'EnableAntennaID': True,
            'EnableChannelIndex': False,
            'EnablePeakRSSI': True,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': False,
        }
    })


Logging
-------

sllurp logs under the name ``sllurp``, so if you wish to log its output, you
can do this the application that imports sllurp:

.. code:: python

    sllurp_logger = logging.getLogger('sllurp')
    sllurp_logger.setLevel(logging.DEBUG)
    sllurp_logger.setHandler(logging.FileHandler('sllurp.log'))
    # or .setHandler(logging.StreamHandler()) to log to stderr...


Vendor Extensions
-----------------

sllurp has limited support for vendor extensions through LLRP's custom message
facilities.  For example, `sllurp inventory --impinj-search-mode N` allows you
to set the Impinj_ search mode to single target (1) or dual target (2).

.. _Impinj: https://support.impinj.com/hc/en-us/articles/202756158-Understanding-EPC-Gen2-Search-Modes-and-Sessions

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

Start an issue on GitHub_!  Please follow Simon Tatham's guide_ on writing good
bug reports.

Bug reports are most useful when they're accompanied by verbose error messages.
Turn sllurp's log level up to DEBUG, which you can do by specifying the `-d`
command-line option to ``sllurp``.  You can log to a logfile with the ``-l
[filename]`` option.  Or simply put this at the beginning of your own code:

.. code:: python

  import logging
  logging.getLogger('sllurp').setLevel(logging.DEBUG)

.. _GitHub: https://github.com/sllurp/sllurp/
.. _guide: https://www.chiark.greenend.org.uk/~sgtatham/bugs.html

Known Issues
------------

Reader mode selection is confusing_, not least because most readers seem to
conflate ``ModeIndex`` and ``ModeIdentifier``.  If you're using ``sllurp
inventory``, use ``--mode-identifier N``.  Check your reader's manual to see
what mode identifiers it supports via the ``C1G2RFControl`` parameter, or run
``sllurp --debug inventory`` against a reader to see a dump of the supported
modes in the capabilities description.

.. _confusing: https://github.com/sllurp/sllurp/issues/63#issuecomment-309233937

Contributing
------------

Want to contribute?  Here are some areas that need improvement:

- Encode more protocol messages in the ``construct`` branch.
- Write tests for common encoding and decoding tasks.

Authors
-------

Much of the code in sllurp is by `Ben Ransford`_, although it began its life in
August 2013 as a fork of LLRPyC_.  Many fine citizens of GitHub have
contributed code to sllurp since the fork, including `Florent Viard`_,
`Bogdan-Marius Pradatu`_, `Jonas Gröger`_, and `Qifan Lu`_.

.. _Ben Ransford: https://ben.ransford.org/
.. _LLRPyC: https://sourceforge.net/projects/llrpyc/
.. _Florent Viard: https://github.com/fviard
.. _Bogdan-Marius Pradatu: https://github.com/BogdanPradatu
.. _Jonas Gröger: https://github.com/JonasGroeger
.. _Qifan Lu: https://github.com/lqf96
