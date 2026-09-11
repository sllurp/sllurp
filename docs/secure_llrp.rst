Secure LLRP (LLRP over TLS)
===========================

LLRP can run over TLS. The IANA-assigned default TCP port for encrypted LLRP is
5085; normal unencrypted LLRP commonly uses TCP port 5084.

sllurp's existing :class:`sllurp.llrp.LLRPReaderClient` remains unchanged and
continues to use plain TCP. Use :class:`sllurp.secure.LLRPTLSReaderClient` when
the reader is configured for LLRP over TLS.

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

Disabling verification
----------------------

``verify=False`` is available for controlled lab/debugging situations, but it
does not authenticate the reader and is not suitable for production networks.

Reader compatibility
--------------------

TLS support is a reader/firmware capability. Configuring sllurp for TLS does not
make a reader expose a secure LLRP listener; the reader must be configured for
LLRP/TLS first.

Motorola/Zebra FX7400
---------------------

The FX7400 implements standard LLRP and its documented default LLRP server port
is 5084. sllurp already contains Motorola vendor ID 161 handling and a set of
Motorola ``Moto*`` custom LLRP parameters, so no separate transport or message
codec is required for ordinary FX7400 LLRP inventory/configuration.

The FX7400 documentation reviewed for this change advertises SSL/SSH security
generally, but its LLRP configuration documents the normal LLRP listener on
port 5084 and does not document a separate LLRP-over-TLS listener. Therefore,
do not assume that an FX7400 accepts secure LLRP on port 5085. Use normal LLRP
on 5084 unless the exact FX7400 firmware in use explicitly exposes LLRP/TLS.

Example::

    from sllurp.llrp import LLRPReaderClient, LLRPReaderConfig

    reader = LLRPReaderClient(
        "fx7400.example.com",
        5084,
        LLRPReaderConfig(),
    )
    reader.connect()

Hardware validation
-------------------

The TLS transport is covered by unit tests using mocked sockets and SSL
contexts. Actual interoperability still depends on the reader model, firmware,
certificate configuration, and supported TLS versions/cipher suites.
