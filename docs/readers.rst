Reader compatibility
====================

sllurp implements standard GS1/EPCglobal LLRP and is deliberately not tied to
one reader model.  Readers in this document fall into two groups:

* **Known sllurp families**: families historically listed by sllurp or covered
  by sllurp's existing vendor-extension code.
* **Standard-LLRP compatible families**: vendor documentation explicitly says
  the reader exposes standard LLRP and is therefore usable with sllurp's core
  protocol.  Vendor-specific features may require additional extensions.

The machine-readable version of this table is in :mod:`sllurp.readers`.

===============================  ===============================  ==============
Reader family                    LLRP                            Secure LLRP
===============================  ===============================  ==============
Zebra/Motorola FX7400            Yes + Motorola extensions       Yes
Zebra FX7500                     Yes + Zebra extensions          Yes
Zebra/Motorola FX9500            Yes + Motorola/Zebra extensions Yes
Zebra FX9600                     Yes + Zebra extensions          Yes
Zebra ATR7000                    Yes + Zebra extensions          Yes
Zebra FXR90 family               Yes                             Firmware/config dependent
Zebra/Motorola MC3090Z/MC319Z    Yes + Motorola extensions       Not verified
Zebra/Motorola MC9090/MC9190-Z   Yes + Motorola extensions       Not verified
Impinj Speedway R220/R420        Yes + Impinj extensions         Yes
Impinj R700/R720                 Yes + Impinj extensions         Yes
Impinj xPortal                   Yes + Impinj extensions         Firmware dependent
Impinj xArray                    Yes + Impinj extensions         Yes
Impinj xSpan                     Yes + Impinj extensions         Yes
Impinj Speedway R1000            Yes (legacy)                    Not verified
Honeywell/Intermec IF2           LLRP 1.0.1                      Yes
Honeywell/Intermec IF61          LLRP 1.0.1                      Yes
ThingMagic IZAR/Sargas           Standard LLRP                   Not verified
ThingMagic Mercury6/M6/Astra-EX  Standard LLRP                   Not verified
Alien ALR-9900+ family           LLRP 1.1                        Not verified
===============================  ===============================  ==============

Secure LLRP
-----------

Secure LLRP is transport security around the normal LLRP message stream.  For
vendor-confirmed secure readers, sllurp uses the same LLRP state machine over a
TLS socket.  Plain LLRP uses the IANA port 5084; encrypted LLRP normally uses
5085.  A reader may configure another secure port, in which case pass it
explicitly.

Example::

    $ sllurp inventory --tls reader.example

or with a private CA::

    $ sllurp inventory --tls --tls-ca-file reader-ca.pem reader.example

Zebra/Motorola fixed readers
----------------------------

Zebra's March 2025 *RFID Reader Software Interface Control Guide* applies to
FX7400, FX7500, FX9500, FX9600 and ATR7000.  Its per-product Reader Management
table marks ``getLLRPConfig`` and ``setLLRPConfig`` supported on all five fixed
reader families.  Those commands expose ``IsSecure`` and
``ValidatePeerInSecureMode`` along with the configurable LLRP port.  Therefore
FX7400 and FX9500 are secure-LLRP-capable too; they must not be treated as
plain-LLRP-only devices.

The same guide documents Motorola/Zebra LLRP custom extensions for the FX and
MC RFID families.  MC Series devices do not support the Reader Management API,
so this document does not claim secure LLRP for those handheld models without a
separate vendor source.

Impinj
------

Current Impinj Speedway documentation lists TLS 1.2 for Secure LLRP.  The
R700-series documentation exposes LLRPS on port 5085 and supports both TLS 1.2
and TLS 1.3 on appropriate firmware.  xArray and xSpan datasheets also list TLS
1.2 for Secure LLRP.  Older Impinj documents can describe different security
capabilities, so firmware matters.

Honeywell/Intermec
------------------

The IF2 user guide exposes an unsecure LLRP server on 5084 and a secure LLRP
server on 5085.  Honeywell's LLRP Programmer's Reference describes TLS on 5085
and specifically notes the IF61 cipher configuration.  Both therefore use the
same sllurp TLS transport.

ThingMagic
----------

JADAK's ThingMagic LLRP guide explicitly targets IZAR and Sargas and states that
generic LLRP clients should work when using standard LLRP commands.  Mercury6,
M6 and Astra-EX also expose standard LLRP.  This adds them to the compatibility
registry, but secure LLRP is left unverified rather than guessed.

Alien
-----

Alien documents LLRP 1.1 for the ALR-9900+ and ALR-9900+EMA family.  Core LLRP
can therefore be used by sllurp.  Secure LLRP remains unverified in the vendor
material reviewed for this change.

References
----------

* Zebra RFID Reader Software Interface Control Guide (March 2025):
  https://www.zebra.com/content/dam/support-dam/en/documentation/unrestricted/guide/software/interface-control-guide-en.pdf
* Impinj Speedway reader datasheet:
  https://support.impinj.com/hc/article_attachments/33623069818515
* Impinj xArray datasheet:
  https://support.impinj.com/hc/article_attachments/33623069807763
* Impinj xSpan datasheet:
  https://support.impinj.com/hc/article_attachments/33623069809939
* Honeywell/Intermec Low-Level Reader Protocol Programmer's Reference:
  https://prod-edam.honeywell.com/content/dam/honeywell-edam/sps/ppr/zh-cn/public/products/rfid/readers/if2b/documents/sps-ppr-937-017.pdf
* ThingMagic Reader LLRP Spec User Guide:
  https://www.jadaktech.com/wp-content/uploads/2022/08/ThingMagic-Reader-LLRP-Spec-User-Guide-03022020-1.pdf
* Alien ALR-9900+ LLRP announcement:
  https://www.alientechnology.com/media/press-releases/alien-technology-adds-low-level-reader-protocol-support-for-enterprise-readers/
