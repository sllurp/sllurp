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

Generic HTTP/HTTPS management
-----------------------------

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

The transport supports HTTP and HTTPS, Basic and Bearer authentication, custom
headers, verified TLS with custom CAs, optional client certificates, and
normalized errors carrying the HTTP status and response body.

Zebra fixed-reader management
-----------------------------

``sllurp.zebra_management`` adds concrete management adapters for Zebra fixed
readers.  It supports both Zebra management generations instead of pretending
they share one API.

=================  ========================  ===========================
Reader             RM XML over HTTP(S)       IoT Connector local REST
=================  ========================  ===========================
FX7400             yes                       no adapter
FX7500             yes                       yes, supported firmware
FX9500             yes                       no adapter
FX9600             yes                       yes, supported firmware
ATR7000            yes                       yes, supported firmware
FXR90 family       no RM adapter             yes
=================  ========================  ===========================

The RM adapter is based on Zebra's documented Reader Management extensions and
``/control`` XML interface.  The IoT adapter uses the documented ``/cloud/*``
local REST API.  FX7500, FX9600, and ATR7000 can use either adapter when their
firmware exposes IoT Connector; ``api="auto"`` intentionally chooses RM for
those models because it spans more firmware generations.  FXR90 automatically
selects IoT Connector.

FX9500
~~~~~~

FX9500 is handled explicitly rather than being treated as an FX9600.  Zebra's
product matrix documents a smaller RM command set for FX9500.  Sllurp blocks
known unsupported helpers before a request is sent.  In particular, FX9500 can
read network settings but Zebra marks ``setNetworkInterfaceSettings``,
``setDHCPConfig``, and ``setActiveRegion`` unsupported.  It does support common
operations such as reader information, status, LLRP configuration, reboot or
shutdown, profiles, time, name, debounce settings, and configuration save.

.. code:: python

    from sllurp.zebra_management import zebra_reader_manager

    manager = zebra_reader_manager(
        "FX9500",
        "https://reader.example",
        username="admin",
        password="secret",
    )
    manager.login()
    try:
        print(manager.get_info())
        print(manager.get_network())
        manager.set_llrp_config(
            port=5084,
            secure=False,
            validate_peer=False,
            client=False,
        )
        manager.save_config()
    finally:
        manager.logout()

Zebra RM API
~~~~~~~~~~~~

For FX7400/FX7500/FX9500/FX9600/ATR7000, ``ZebraRMManager`` provides login and
logout plus convenience methods for common management operations: reader and
health information, network configuration, DHCP, regions, LLRP service
configuration, reboot/shutdown, config save/discard state, profiles, time and
time zone, shell/FTP status, external antenna mode, firmware update, debounce,
and password changes.  ``command()`` remains available for other documented RM
commands without requiring Sllurp to duplicate the entire Zebra schema.

For setters that are model-specific, the adapter raises
``UnsupportedReaderOperation`` when the Zebra support matrix says the operation
is not available on that model.

Zebra IoT Connector REST
~~~~~~~~~~~~~~~~~~~~~~~~

The IoT adapter authenticates using Zebra's documented two-step local REST
flow: Basic authentication to ``/cloud/localRestLogin`` followed by the returned
JWT as a Bearer token.  A previously obtained token can also be supplied.

.. code:: python

    from sllurp.zebra_management import zebra_reader_manager

    manager = zebra_reader_manager(
        "FXR90",
        "https://fxr90.example",
        username="admin",
        password="secret",
    )

    print(manager.get_info())
    print(manager.get_status())
    manager.set_hostname("dock-door-reader")
    manager.set_gpo(2, True)
    manager.set_mode({
        "type": "INVENTORY",
        "antennas": [1, 2, 3, 4],
        "transmitPower": 30.0,
    })
    manager.start()

Convenience methods cover published local REST endpoints for version/status,
capabilities, network settings, hostname, region reads, supported regions,
configuration, operating mode, start/stop, reboot, GPI/GPO, time zone, and OS
update.  ``request()`` is the forward-compatible escape hatch for additional
endpoints present in a reader's own Swagger/OpenAPI version.

References
~~~~~~~~~~

Zebra publishes the protocol details used by these adapters:

* Reader Software Interface Control Guide:
  https://www.zebra.com/content/dam/support-dam/en/documentation/unrestricted/guide/software/interface-control-guide-en.pdf
* Zebra IoT Connector documentation:
  https://zebradevs.github.io/rfid-ziotc-docs/
* Zebra IoT Connector local REST OpenAPI:
  https://zebradevs.github.io/rfid-ziotc-docs/_static/api/redoc-static.html

Vendor compatibility
--------------------

There is no single standard HTTP settings endpoint shared by Impinj, Zebra,
Motorola, and other reader vendors.  The generic transport and vendor adapters
therefore keep the public calling style consistent while preserving the actual
protocol and capabilities of each reader family.

LLRP-compatible inventory and the deduplication helper remain vendor-neutral.
A non-LLRP reader is outside Sllurp's core protocol scope and requires a
separate transport or vendor SDK.
