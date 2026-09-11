Impinj reader management
========================

Sllurp separates RFID inventory control from reader administration.  Inventory
continues to use LLRP.  Device-management over HTTP/HTTPS is implemented only
where Impinj publishes a stable machine API.

R700 and R720
-------------

``ImpinjRESTManager`` supports the Impinj R700-series reader-configuration REST
API under ``/api/v1``.  It uses HTTP Basic authentication and the same TLS
verification controls as ``HTTPReaderManager``.

.. code:: python

    from sllurp.impinj_management import ImpinjRESTManager

    manager = ImpinjRESTManager(
        "https://impinj-r700.example",
        model="R700",
        username="root",
        password="your-reader-password",
    )

    print(manager.get_status())
    manager.set_mqtt({
        "brokerHostname": "mqtt.example",
        "clientId": "dock-door",
        "eventTopic": "rfid/events",
        "tlsEnabled": True,
    })
    manager.set_power_source("poeplus")

The adapter provides convenience methods for endpoints that are explicitly
shown in Impinj documentation, including ``/status``, ``/mqtt``,
``/system/power``, TLS/CA certificate installation and service assignment, and
the diagnostic debug bundle.  Firmware versions can expose more resources, so
``get_settings()``, ``update_settings()``, ``get()``, ``put()``, ``patch()``,
``post()``, ``delete()``, and ``response()`` make every documented
``/api/v1`` resource reachable without waiting for a new sllurp release.

For example, a resource added by a firmware OpenAPI document can be updated as
follows::

    manager.update_settings(
        "some/documented/resource",
        {"enabled": True},
        method="PUT",
    )

Sllurp does not embed the factory-default password.  Supply the credentials
configured on the actual reader.  Certificate verification remains enabled by
default; use a private CA bundle when the reader uses an internal certificate.

Legacy Speedway platform
-------------------------

Speedway R1000/R220/R420, xPortal, xArray, and xSpan are not treated as R700
REST readers.  Current Impinj documentation describes RShell over SSH/serial as
the machine management interface for Speedway readers, while the browser page
is a management UI.  Sllurp therefore does not automate undocumented CGI URLs.
This avoids coupling deployments to private endpoints that can change with
firmware.

LLRP support for those readers is unaffected.  ``create_reader_manager()``
raises ``UnsupportedReaderOperation`` when asked for built-in HTTP/HTTPS
management on a legacy Impinj model.  Applications with a vendor-documented
endpoint for a particular firmware can still use ``HTTPReaderManager``
directly.

Unified factory
---------------

``create_reader_manager`` selects the documented adapter from a model name.  It
currently selects Zebra RM/IoT adapters and the Impinj R700-series REST adapter.

.. code:: python

    from sllurp.reader_management import create_reader_manager

    manager = create_reader_manager(
        "R720",
        "https://reader.example",
        username="root",
        password="secret",
    )
    print(manager.get_status())

Unknown/vendor-specific HTTP services can opt into the generic transport with
``vendor="generic"`` rather than being guessed from a product name.

References
----------

* Impinj R700 Series datasheet (Reader configuration REST API):
  https://support.impinj.com/hc/article_attachments/31243539924371
* Impinj R700 AWS IoT application note (``/api/v1/status``, ``/api/v1/mqtt``
  and certificate-management examples):
  https://support.impinj.com/hc/article_attachments/10268482888723
* Impinj Speedway installation and operations guide (RShell machine
  management):
  https://support.impinj.com/hc/article_attachments/4403721192979/Impinj_SpeedwayR_installation_and_operations_guide_7.6.pdf
