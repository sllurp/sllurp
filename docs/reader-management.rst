Reader management and tag deduplication
=======================================

Sllurp's core protocol is LLRP.  LLRP is standardized across compatible RFID
readers, while each vendor's web-management API is different.  Sllurp therefore
keeps LLRP control and HTTP/HTTPS management separate.

Tag report deduplication
------------------------

A reader can report the same EPC repeatedly across multiple ``RO_ACCESS_REPORT``
messages.  ``TagReportDeduplicator`` optionally suppresses repeated application
callbacks for a configurable time window without changing the reader's RF or
inventory behavior.

.. code:: python

    from sllurp.dedup import TagReportDeduplicator

    def on_unique_tags(reader, tags):
        for tag in tags:
            print(tag)

    dedup = TagReportDeduplicator(
        on_unique_tags,
        window_seconds=1.0,
        include_antenna=False,
    )
    reader.add_tag_report_callback(dedup)

By default the EPC is the identity.  Set ``include_antenna=True`` when the same
EPC seen on different antennas should be treated as separate observations.
Pass a custom ``key=`` callable for application-specific identity rules.

This is intentionally distinct from LLRP's reader-side tag accumulation and
``TagSeenCount``.  Hardware and firmware may aggregate sightings inside a
single report; this helper suppresses duplicate reports seen by the application
across time.

HTTP/HTTPS management
---------------------

``HTTPReaderManager`` provides a vendor-neutral transport for readers that
expose a management API over HTTP or HTTPS.  Because URL paths and JSON schemas
are vendor-specific, callers supply the documented endpoint and payload.

.. code:: python

    from sllurp.reader_management import HTTPReaderManager

    manager = HTTPReaderManager(
        "https://reader.example",
        username="admin",
        password="secret",
    )

    settings = manager.get_settings("/api/settings")
    manager.update_settings(
        "/api/settings",
        {"rfid": {"enabled": True}},
        method="PATCH",
    )

The transport supports:

* HTTP and HTTPS
* GET plus PATCH/PUT/POST settings updates
* HTTP Basic authentication
* Bearer-token authentication
* custom request headers
* certificate verification with an optional custom CA bundle
* optional TLS client certificates
* explicit disabling of certificate verification for development or legacy
  readers
* normalized management exceptions carrying the HTTP status and response body

Vendor compatibility
--------------------

There is no single standard HTTP settings endpoint shared by Impinj, Zebra,
Motorola, and other reader vendors.  The generic transport therefore avoids
hard-coding one vendor's endpoint as if it were universal.  Vendor-specific
profiles can be layered on top of ``HTTPReaderManager`` while keeping the
calling application unchanged.

LLRP-compatible inventory and the deduplication helper remain vendor-neutral.
A non-LLRP reader is outside Sllurp's core protocol scope and requires a
separate transport or vendor SDK.
