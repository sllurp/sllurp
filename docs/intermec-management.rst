Honeywell / Intermec IF-series management
========================================

Honeywell/Intermec IF1, IF2, and IF61 readers expose Device Configuration Web
Services (DCWS) over HTTP or HTTPS.  DCWS is a SOAP service, not a REST API.
The reader itself publishes the authoritative ``DeviceConfiguration.wsdl``
document describing the operations available in that firmware build.

``IntermecDCWSManager`` therefore loads the reader's WSDL, discovers the SOAP
endpoint and action names, and only permits operations advertised by that WSDL.
This avoids hard-coding a command catalogue that can drift between firmware
releases.

Basic usage
-----------

.. code:: python

    from sllurp.reader_management import create_reader_manager

    manager = create_reader_manager(
        "IF2",
        "https://reader.example",
        username="admin",
        password="secret",
    )

    print(manager.list_operations())
    result = manager.call(
        "SomeOperationFromTheReaderWSDL",
        {"settingName": "value"},
    )
    print(result)

The exact operation and parameter names come from the reader's
``DeviceConfiguration.wsdl`` and the vendor's Device Configuration Web Service
command reference.  Sllurp does not invent generic setting names for this SOAP
interface.

HTTP and HTTPS
--------------

DCWS can be exposed through secure or insecure web services depending on reader
configuration.  The Sllurp adapter uses ``HTTPReaderManager`` underneath, so it
supports HTTP Basic authentication, TLS certificate verification, custom CA
bundles, optional client certificates, and an explicit no-verification mode for
controlled legacy deployments.

The WSDL may contain an absolute ``soap:address``.  Sllurp intentionally keeps
the configured reader host and uses only the path/query portion from that
address.  This prevents credentials from being redirected to another host by
WSDL content.

WSDL overrides
--------------

The default WSDL path is ``/DeviceConfiguration.wsdl``.  Firmware or deployments
that expose it elsewhere can override the path, and a SOAP endpoint can also be
supplied explicitly::

    manager = create_reader_manager(
        "IF61",
        "https://reader.example",
        api="dcws",
        username="admin",
        password="secret",
        wsdl_path="/custom/DeviceConfiguration.wsdl",
        endpoint_path="/custom/DeviceConfiguration",
    )

``load_wsdl=False`` can be used to construct the client without network I/O;
call ``refresh_wsdl()`` before invoking operations.

Supported models
----------------

The built-in DCWS adapter currently recognizes:

* IF1
* IF2
* IF61

These models are documented as exposing Device Configuration Web Services that
can programmatically configure network, RFID, and system settings.  The precise
set of callable operations still comes from the individual reader WSDL.

References
----------

* Honeywell IF2B product/support page, including the IF2 Network Reader User
  Guide: https://automation.honeywell.com/us/en/products/productivity-solutions/mobile-computers/rfid/readers/if2b-fixed-rfid-reader
* IF1 Fixed RFID Reader Series User Manual describes Device Configuration Web
  Services and ``DeviceConfiguration.wsdl``.
* IF61 Fixed Reader User Guide documents secure/insecure Device Configuration
  Web Services and the downloadable WSDL.
