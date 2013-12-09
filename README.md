# sllurp

This repository began in August 2013 as a snapshot of the dormant
[LLRPyC project][]'s [code][] on SourceForge.  It has been violently updated to
work with Impinj Speedway readers (and probably still other readers), and to
provide a simple callback-based API to clients.

[LLRPyC project]: http://wiki.enneenne.com/index.php/LLRPyC
[code]: http://sourceforge.net/projects/llrpyc/.

## Quick Start

Make sure you have the prerequisite Python modules installed.  Use the `pip`
package manager to load the requirements:

    pip install -r requirements.txt

To connect to a reader and perform EPC Gen 2 inventory for 10 seconds:

1. Figure out your reader's IP address `ip.add.re.ss`
2. `bin/inventory ip.add.re.ss`

Run `bin/inventory -h` to see options.

## Reader API

Interactions with the reader are brokered by a `llrp.LLRPReaderThread` object;
see `simple_inventory.py` for an example.  This class provides a simple API to
expose interesting events to programs.

 * `addCallback(eventType, func)`: Every time the reader receives an LLRP
   message of type `eventType` (e.g., `RO_ACCESS_REPORT` reports tag reads),
   call the function `func` with the representative `LLRPMessage` object as its
   argument.
 * `start_inventory()`: Starts the reader performing inventory.
 * `stop_inventory()`: Cleanly stops the active inventory operation.

## Handy Commands

To see what inventory settings an Impinj reader is currently using (i.e., to
fetch the current ROSpec), ssh to the reader and

    show rfid llrp rospec 0

You can dump the reader's entire configuration, including the current ROSpec,
to a set of files by running `bin/get_reader_config.sh`.

## Contributing

Want to contribute?  Here are some areas that need improvement:

 * Reduce redundancy in the `encode_*` and `decode_*` functions in
   `llrp_proto.py`.
 * Support the AccessSpec primitive (basis for tag read and write).
 * Write tests for common encoding and decoding tasks.
