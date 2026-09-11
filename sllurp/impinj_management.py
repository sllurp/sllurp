"""Impinj R700-series reader-configuration REST management.

Impinj R700 and R720 readers expose an OpenAPI-compatible configuration REST
API under ``/api/v1``.  The API is separate from LLRP inventory control.  This
module wraps the authenticated HTTP/HTTPS transport while keeping arbitrary
vendor resources reachable for firmware versions that expose more endpoints.

Legacy Speedway-platform readers are deliberately not driven through private
web-UI CGI endpoints.  Impinj documents RShell as their machine management
interface; use LLRP for RFID control and RShell/SSH for device administration.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlparse

from .reader_management import HTTPReaderManager, ReaderHTTPResponse


IMPINJ_REST_MODELS = frozenset({"R700", "R720"})


def _model_name(model: str) -> str:
    value = "".join(character for character in model.upper() if character.isalnum())
    if value.startswith("IMPINJ"):
        value = value[len("IMPINJ") :]
    return value


def _multipart_file(
    field_name: str,
    filename: str,
    content: bytes,
    content_type: str,
) -> tuple[bytes, str]:
    boundary = f"sllurp-{uuid.uuid4().hex}"
    body = b"".join(
        (
            f"--{boundary}\r\n".encode("ascii"),
            (
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{filename}"\r\n'
            ).encode("utf-8"),
            f"Content-Type: {content_type}\r\n\r\n".encode("ascii"),
            content,
            b"\r\n",
            f"--{boundary}--\r\n".encode("ascii"),
        )
    )
    return body, boundary


class ImpinjRESTManager:
    """HTTP/HTTPS management client for Impinj R700/R720 readers.

    ``username`` and ``password`` are the reader's HTTP Basic credentials.  The
    factory does not embed Impinj's factory password; applications must supply
    their actual credentials.
    """

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        username: str,
        password: str,
        api_prefix: str = "/api/v1",
        timeout: float = 5.0,
        verify_tls: bool = True,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
    ) -> None:
        self.model = _model_name(model)
        if self.model not in IMPINJ_REST_MODELS:
            raise ValueError(f"{model!r} is not an Impinj R700-series REST model")
        prefix = "/" + api_prefix.strip("/")
        if prefix == "/":
            raise ValueError("api_prefix cannot be empty")
        self.api_prefix = prefix
        self.transport = HTTPReaderManager(
            base_url,
            username=username,
            password=password,
            timeout=timeout,
            verify_tls=verify_tls,
            ca_file=ca_file,
            cert_file=cert_file,
            key_file=key_file,
            headers={"Accept": "application/json"},
        )

    def _path(self, resource: str) -> str:
        parsed = urlparse(resource)
        if parsed.scheme or parsed.netloc:
            raise ValueError("Impinj REST resources must be paths on the reader host")
        path = "/" + resource.lstrip("/")
        if path == self.api_prefix or path.startswith(self.api_prefix + "/"):
            return path
        return self.api_prefix + path

    def response(
        self,
        method: str,
        resource: str,
        *,
        json_body: Any = None,
        data: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ReaderHTTPResponse:
        """Return the normalized raw HTTP response for one REST resource."""
        return self.transport.request(
            method,
            self._path(resource),
            json_body=json_body,
            data=data,
            headers=headers,
        )

    def request(
        self,
        method: str,
        resource: str,
        *,
        json_body: Any = None,
        data: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Request a resource and decode JSON when the response contains JSON."""
        response = self.response(
            method,
            resource,
            json_body=json_body,
            data=data,
            headers=headers,
        )
        if not response.body:
            return None
        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type.lower() or response.body.lstrip().startswith(
            (b"{", b"[")
        ):
            return response.json()
        return response.text

    def get(self, resource: str) -> Any:
        return self.request("GET", resource)

    def put(self, resource: str, settings: Mapping[str, Any]) -> Any:
        return self.request("PUT", resource, json_body=dict(settings))

    def patch(self, resource: str, settings: Mapping[str, Any]) -> Any:
        return self.request("PATCH", resource, json_body=dict(settings))

    def post(
        self,
        resource: str,
        body: Mapping[str, Any] | None = None,
    ) -> Any:
        return self.request(
            "POST",
            resource,
            json_body=dict(body) if body is not None else None,
        )

    def delete(self, resource: str) -> Any:
        return self.request("DELETE", resource)

    def get_settings(self, resource: str) -> Any:
        """Read any documented reader-configuration REST resource."""
        return self.get(resource)

    def update_settings(
        self,
        resource: str,
        settings: Mapping[str, Any],
        *,
        method: str = "PUT",
    ) -> Any:
        """Update any documented configuration resource using PUT/PATCH/POST."""
        method = method.upper()
        if method not in {"PUT", "PATCH", "POST"}:
            raise ValueError("settings update method must be PUT, PATCH, or POST")
        return self.request(method, resource, json_body=dict(settings))

    def get_status(self) -> Any:
        """Return the documented ``/api/v1/status`` reader status resource."""
        return self.get("status")

    def get_mqtt(self) -> Any:
        """Read the MQTT event-reporting configuration resource."""
        return self.get("mqtt")

    def set_mqtt(self, settings: Mapping[str, Any]) -> Any:
        """Replace MQTT event-reporting settings at ``/api/v1/mqtt``."""
        return self.put("mqtt", settings)

    def get_power(self) -> Any:
        return self.get("system/power")

    def set_power_source(self, power_source: str) -> Any:
        """Set the reader power source through ``/system/power``.

        Impinj documents ``poeplus`` for PoE+ configuration.  Other values are
        passed through so firmware-specific values remain usable.
        """
        if not power_source or not power_source.strip():
            raise ValueError("power_source cannot be empty")
        return self.put(
            "system/power", {"powerSource": power_source.strip().lower()}
        )

    def install_ca_certificate(
        self,
        certificate: bytes,
        *,
        filename: str = "ca.pem",
    ) -> Any:
        """Install a CA certificate and return the API response."""
        body, boundary = _multipart_file(
            "certFile", filename, certificate, "application/x-pem-file"
        )
        return self.request(
            "POST",
            "system/certificates/ca/certs",
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
            },
        )

    def install_tls_certificate(
        self,
        certificate: bytes,
        *,
        filename: str = "reader.p12",
    ) -> Any:
        """Install a PKCS#12 TLS certificate/key bundle."""
        body, boundary = _multipart_file(
            "certFile", filename, certificate, "application/x-pkcs12"
        )
        return self.request(
            "POST",
            "system/certificates/tls/certs",
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
            },
        )

    def set_tls_service_certificate(self, service: str, cert_id: int) -> Any:
        """Assign an installed TLS certificate to a reader service."""
        if not service or not service.strip():
            raise ValueError("service cannot be empty")
        service_path = quote(service.strip(), safe="-")
        return self.put(
            f"system/certificates/tls/services/{service_path}",
            {"certId": int(cert_id)},
        )

    def get_debug_bundle(self) -> bytes:
        """Download the documented reader diagnostic debug bundle."""
        response = self.response("GET", "system/diagnostics/debug-bundle/")
        return response.body
