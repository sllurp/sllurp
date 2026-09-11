Secure LLRP (LLRP over TLS)
===========================

LLRP can run over TLS. IANA assigns TCP port 5084 to normal LLRP and TCP port
5085 to encrypted LLRP. sllurp's TLS transport is reader-neutral: it can be used
with any reader/firmware that actually exposes LLRP over TLS.

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

For a Zebra FX7500/FX9600 configured with **Enable Secure Mode**::

    $ sllurp inventory --tls --tls-ca-file /path/to/reader-ca.pem reader.example

Zebra documents that enabling Secure LLRP switches the default LLRP port to
5085. If the reader is configured with a non-default secure port, override it::

    $ sllurp inventory --tls --port 55085 reader.example

Reader compatibility
--------------------

TLS is a reader/firmware feature, not a different LLRP message set. The same
sllurp LLRP encoder/decoder is used after the TLS session is established.

==============================  ==========================  =====================
Reader family                   Secure LLRP status          Default/documented port
==============================  ==========================  =====================
Zebra FX7500                    **Yes**                     5085 in Secure Mode
Zebra FX9600                    **Yes**                     5085 in Secure Mode
Zebra FXR90 family              sllurp TLS-capable;         Firmware/config dependent
                                verify firmware settings
Motorola/Zebra FX7400           Not documented             5084 plain LLRP
Zebra FX9500                    Not documented             5084 plain LLRP
Motorola/Zebra MC9190-Z         Not documented             Use documented LLRP setup
Impinj Speedway R220/R420       **No** encrypted LLRP      5084 TCP only
Impinj Speedway xPortal         **No** encrypted LLRP      5084 TCP only
Impinj Speedway R1000           Legacy; not verified       Use documented LLRP setup
==============================  ==========================  =====================

Zebra FX7500 and FX9600
~~~~~~~~~~~~~~~~~~~~~~~

Zebra's FX Series integration documentation explicitly describes a **Secure
LLRP Service**. Enabling Secure Mode changes the default LLRP port to 5085,
supports TLS 1.2-compliant ciphers, and optionally validates the peer using
certificates. The same documentation states that FX7500 and FX9600 can use a
custom reader certificate and can require a client certificate issued by the
same CA.

This means sllurp secure LLRP applies directly to both FX7500 and FX9600; it is
not an FXR90-only feature.

Zebra FXR90
~~~~~~~~~~~

sllurp's transport implementation is not model-specific and works with an
FXR90 endpoint configured to accept LLRP over TLS. Zebra's current FXR90
platform documentation advertises TLS/FIPS capabilities and certificate
management, but the public guide reviewed for this matrix does not document the
classic FX7500/FX9600 ``Enable Secure Mode -> port 5085`` control as explicitly.
Do not assume port 5085 on every FXR90 firmware build; use the reader's configured
LLRP endpoint/port.

Motorola/Zebra FX7400 and Zebra FX9500
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The reviewed FX7400 and FX9500 guides document normal LLRP on port 5084. They do
not document the FX7500/FX9600 Secure LLRP mode. sllurp therefore supports their
normal LLRP operation, but does not claim vendor-confirmed encrypted LLRP for
those models. If a particular firmware exposes LLRP/TLS, sllurp's generic TLS
transport can still be pointed at that endpoint explicitly.

Impinj Speedway and xPortal
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Impinj's Octane LLRP documentation states that TLS encrypted connection support
is not available for the Speedway fixed-reader family covered by that guide and
that only TCP connections are supported. Impinj also documents xPortal as using
the same configuration/operation as Speedway R120/R220/R420. Therefore sllurp
must continue to use ordinary LLRP/TCP for those readers; ``--tls`` cannot add a
hardware feature that the reader does not expose.

References
----------

* IANA service registry (``llrp`` 5084, ``encrypted-llrp`` 5085):
  https://www.iana.org/assignments/service-names-port-numbers/
* Zebra FX Series integration guide (FX7500/FX9600 Secure LLRP):
  https://www.zebra.com/content/dam/support-dam/en/documentation/unrestricted/guide/product/fx-series-integrator-guide-en.pdf
* Zebra FX7500 product specification:
  https://www.zebra.com/us/en/products/spec-sheets/rfid/rfid-readers/fx7500.html
* Zebra FX9500 user guide:
  https://www.zebra.cn/content/dam/support-dam/en/documentation/unrestricted/guide/product/fx9500-ug-en.pdf
* Impinj Octane LLRP guide:
  https://support.impinj.com/hc/article_attachments/4403727655059/Impinj_Octane_LLRP_7.6.pdf
* Impinj Speedway installation guide (xPortal uses Speedway configuration):
  https://support.impinj.com/hc/article_attachments/33622168584723

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