Secure LLRP (LLRP over TLS)
===========================

LLRP can run over TLS. IANA assigns TCP port 5084 to normal LLRP and TCP port
5085 to encrypted LLRP. sllurp's TLS transport is reader-neutral: it can be used
with any reader/firmware that exposes LLRP over TLS.

Two APIs are available:

* :class:`sllurp.llrp.LLRPReaderClient` with ``tls_enabled=True`` in
  :class:`sllurp.llrp.LLRPReaderConfig`.
* :class:`sllurp.secure.LLRPTLSReaderClient`, a convenience client that defaults
  to encrypted-LLRP port 5085.

The command-line ``--tls`` option uses the same transport and, unless ``--port``
is explicitly supplied, uses port 5085. Plain LLRP keeps port 5084.

Verified server certificate
---------------------------

For a reader certificate signed by a trusted CA::

    from sllurp.llrp import LLRPReaderConfig
    from sllurp.secure import LLRPTLSReaderClient

    config = LLRPReaderConfig()
    reader = LLRPTLSReaderClient(
        "reader.example.com",
        config=config,
    )
    reader.connect()

For a private or self-signed reader CA, supply the CA certificate rather than
turning verification off::

    reader = LLRPTLSReaderClient(
        "reader.example.com",
        cafile="/path/to/reader-ca.pem",
    )

If the certificate name differs from the host used to reach the reader, set
``server_hostname`` to the DNS name present in the certificate.

Mutual TLS
----------

Readers that require a client certificate can use::

    reader = LLRPTLSReaderClient(
        "reader.example.com",
        cafile="/path/to/reader-ca.pem",
        certfile="/path/to/client-cert.pem",
        keyfile="/path/to/client-key.pem",
    )

A fully configured :class:`ssl.SSLContext` may instead be supplied using the
``ssl_context`` argument.

Command line
------------

For a reader configured for Secure LLRP::

    $ sllurp inventory --tls --tls-ca-file /path/to/reader-ca.pem reader.example

If the reader uses a non-default secure port, override it::

    $ sllurp inventory --tls --port 55085 reader.example

Reader compatibility
--------------------

TLS is a reader/firmware feature, not a different LLRP message set. The same
sllurp encoder/decoder and state machine run after the TLS session is
established.  See :mod:`sllurp.readers` and ``docs/readers.rst`` for the
machine-readable and human-readable compatibility lists.

===============================  ===========================  =======================
Reader family                    Secure LLRP status           Port
===============================  ===========================  =======================
Zebra/Motorola FX7400            **Yes**                      Configurable; 5085 standard
Zebra FX7500                     **Yes**                      5085 default secure port
Zebra/Motorola FX9500            **Yes**                      Configurable; 5085 standard
Zebra FX9600                     **Yes**                      5085 default secure port
Zebra ATR7000                    **Yes**                      5085 secure LLRP
Zebra FXR90 family               Firmware/config dependent   Use configured endpoint
Zebra MC3090Z/MC319Z             Not verified                Use configured endpoint
Zebra MC9090/MC9190-Z            Not verified                Use configured endpoint
Impinj Speedway R220/R420        **Yes**                      5085 secure LLRP
Impinj R700/R720                 **Yes**                      5085 LLRPS
Impinj xArray                    **Yes**                      5085 standard secure port
Impinj xSpan                     **Yes**                      5085 standard secure port
Impinj xPortal                   Firmware dependent          Use configured endpoint
Honeywell/Intermec IF2           **Yes**                      5085 secure server
Honeywell/Intermec IF61          **Yes**                      5085 LLRP/TLS
ThingMagic IZAR/Sargas           Not verified                Use configured endpoint
ThingMagic Mercury6/M6/Astra-EX  Not verified                Use configured endpoint
Alien ALR-9900+                  Not verified                Use configured endpoint
===============================  ===========================  =======================

Zebra FX7400, FX7500, FX9500, FX9600 and ATR7000
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Zebra's March 2025 *RFID Reader Software Interface Control Guide* explicitly
applies to FX7400, FX7500, FX9500, FX9600 and ATR7000.  The per-product Reader
Management table marks both ``ReaderDevice.getLLRPConfig`` and
``ReaderDevice.setLLRPConfig`` as supported on all five fixed-reader families.
Those commands expose ``portNum``, ``IsSecure`` and
``ValidatePeerInSecureMode``.  This is vendor documentation of Secure LLRP on
FX7400 and FX9500 as well as the newer FX7500/FX9600/ATR7000 models.

The guide also shows that certificate-management feature coverage differs by
model.  In particular, FX9500 does not expose every certificate-management RM
command that the other fixed readers do.  sllurp therefore supports the TLS
transport without assuming that every Zebra model manages certificates in the
same way.

For FX7500/FX9600/ATR7000 firmware that implements Zebra's current Secure LLRP
service, 5085 is the normal encrypted endpoint.  FX7400/FX9500 expose a
configurable LLRP port through Reader Management; use the reader's configured
port if it differs from 5085.

Zebra FXR90
~~~~~~~~~~~

The FXR90 exposes standard LLRP and sllurp's transport code is not model
specific.  Public FXR90 integration documentation reviewed for this matrix
clearly documents TLS/certificate support for network security, but does not
spell out the classic FX-series Secure LLRP service/5085 control as explicitly
as the older fixed-reader control guide.  Therefore the registry leaves
``secure_llrp`` unverified rather than inventing a model-specific claim.  If the
installed firmware exposes an LLRP/TLS listener, use ``--tls`` and its configured
port.

Impinj Speedway, R700/R720, xArray and xSpan
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Current Impinj Speedway datasheets list **TLS 1.2 for Secure LLRP**.  Current
RShell documentation exposes LLRP security modes including encryption and peer
validation.  R700-series firmware exposes LLRPS on port 5085, with TLS 1.2 and,
on appropriate firmware, TLS 1.3.  Impinj xArray and xSpan datasheets also list
TLS 1.2 for Secure LLRP.

Some older Impinj LLRP documentation describes older security behavior.  Treat
reader firmware as authoritative when a legacy document conflicts with a newer
reader datasheet/RShell command set.

Honeywell/Intermec IF2 and IF61
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The IF2 user guide explicitly exposes an unsecure LLRP server on 5084 and a
secure LLRP server on 5085.  Honeywell/Intermec's LLRP Programmer's Reference
states that the LLRP implementation supports TLS on IANA port 5085 and discusses
the IF61 TLS cipher configuration.  sllurp's generic TLS transport therefore
applies directly to both families.

Other standard-LLRP readers
~~~~~~~~~~~~~~~~~~~~~~~~~~~

ThingMagic documents standard LLRP on IZAR, Sargas, Mercury6/M6 and Astra-EX,
and Alien documents LLRP 1.1 on the ALR-9900+ family.  These are included in
the reader compatibility registry.  The vendor material reviewed for this
change did not establish their Secure LLRP behavior, so secure support remains
``None``/unverified rather than being falsely marked yes or no.

References
----------

* IANA service registry (``llrp`` 5084, ``encrypted-llrp`` 5085):
  https://www.iana.org/assignments/service-names-port-numbers/
* Zebra RFID Reader Software Interface Control Guide (March 2025):
  https://www.zebra.com/content/dam/support-dam/en/documentation/unrestricted/guide/software/interface-control-guide-en.pdf
* Impinj Speedway reader datasheet:
  https://support.impinj.com/hc/article_attachments/33623069818515
* Impinj RShell Reference Manual:
  https://support.impinj.com/hc/article_attachments/25550317747347
* Impinj R700 Series datasheet:
  https://support.impinj.com/hc/article_attachments/31243539924371
* Impinj xArray datasheet:
  https://support.impinj.com/hc/article_attachments/33623069807763
* Impinj xSpan datasheet:
  https://support.impinj.com/hc/article_attachments/33623069809939
* Honeywell/Intermec LLRP Programmer's Reference:
  https://prod-edam.honeywell.com/content/dam/honeywell-edam/sps/ppr/zh-cn/public/products/rfid/readers/if2b/documents/sps-ppr-937-017.pdf
* ThingMagic Reader LLRP Spec User Guide:
  https://www.jadaktech.com/wp-content/uploads/2022/08/ThingMagic-Reader-LLRP-Spec-User-Guide-03022020-1.pdf
* Alien ALR-9900+ LLRP announcement:
  https://www.alientechnology.com/media/press-releases/alien-technology-adds-low-level-reader-protocol-support-for-enterprise-readers/

Disabling verification
----------------------

``verify=False`` / ``--tls-no-verify`` is available for controlled lab/debugging
situations, but it does not authenticate the reader and is not suitable for
production networks.

Hardware validation
-------------------

The TLS transport is covered by unit tests using mocked sockets and SSL
contexts. Actual interoperability still depends on reader model, firmware,
certificate configuration, and supported TLS versions/cipher suites.
