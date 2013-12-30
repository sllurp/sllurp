# sllurp

This repository began in August 2013 as a snapshot of the dormant
[LLRPyC project][]'s [code][] on SourceForge.  It has been violently updated to
work with Impinj Speedway readers (and probably still other readers), and to
provide a simple callback-based API to clients.

[LLRPyC project]: http://wiki.enneenne.com/index.php/LLRPyC
[code]: http://sourceforge.net/projects/llrpyc/

## Quick Start

Make sure you have the prerequisite Python modules installed.  Use the `pip`
package manager to load the requirements:

    pip install -r requirements.txt

To connect to a reader and perform EPC Gen 2 inventory for 10 seconds:

1. Figure out your reader's IP address `ip.add.re.ss`
2. `bin/inventory ip.add.re.ss`

Run `bin/inventory -h` to see options.

If the reader gets into a funny state because you're debugging against it, you
can stop all ROSpecs by running `bin/reset ip.add.re.ss`.

## Reader API

Interactions with the reader are brokered by a `llrp.LLRPReaderThread` object;
see `sllurp/inventory.py` for an example.  The `llrp.LLRPReaderThread` class
provides a simple API to expose interesting events to programs.

The flow is as follows:

1. Create an `llrp.LLRPReaderThread` with configuration options set as
   necessary.
2. Create and add callbacks for the events you care about, such as
   `RO_ACCESS_REPORT` which reports tag reads.
3. Start the reader thread.  By default, the reader thread will begin
   inventorying (looking for tags) immediately; see `sllurp/reset.py` for an
   example of how to avoid automatically inventorying.
4. `join` the reader thread from your application to wait for it to complete
   its inventory operation.  By default, the reader thread will exit when all
   inventory operations are complete.

sllurp uses the asynchronous networking library [Twisted][] to simplify its
communications with readers.  This introduces a few extra complexities related
to Twisted's assumption that it runs the main loop of the application.  If
sllurp is the only part of your application that relies on Twisted for network
communication, pass `standalone=True` to the `LLRPReaderThread` constructor to
tell sllurp that it has sole control over the Twisted `reactor` object.

Note that you can also skip the `LLRPReaderThread` and use the
`LLRPClientFactory` directly with your own Twisted reactor.  See the
implementation of the `LLRPReaderThread` for a guide.

[Twisted]: http://twistedmatrix.com/

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
