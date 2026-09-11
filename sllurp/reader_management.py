"""HTTP/HTTPS management helpers for RFID readers.

LLRP controls RFID inventory behavior, but many readers expose additional
vendor-specific management APIs over HTTP or HTTPS.  The endpoint layout and
payload schema are not standardized, so this module deliberately provides a
small transport abstraction rather than pretending every reader uses the same
settings model.
"""

from __future__ import annotations

import base64
import json
import ssl
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPSHandler, Request, build_opener


class ReaderManagementError(RuntimeError):
    """Raised when a reader management request cannot be completed."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        body: bytes | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass(frozen=True)
class ReaderHTTPResponse:
    """Normalized response returned by :class:`HTTPReaderManager`."""

    status: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))


class HTTPReaderManager:
    """Generic HTTP/HTTPS management transport for RFID readers.

    The class is intentionally vendor-neutral.  Callers provide the reader's
    API path and payload documented by the reader vendor.

    Parameters:
        base_url: Reader base URL, including ``http://`` or ``https://``.
        username/password: Optional HTTP Basic credentials.
        bearer_token: Optional bearer token.  Mutually exclusive with
            username/password.
        headers: Default request headers.
        timeout: Socket timeout in seconds.
        verify_tls: Verify HTTPS certificates when true.
        ca_file: Optional CA bundle for private reader certificates.
        cert_file/key_file: Optional TLS client certificate and key.
    """

    def __init__(
        self,
        base_url: str,
        *,
        username: str | None = None,
        password: str | None = None,
        bearer_token: str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 5.0,
        verify_tls: bool = True,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute http:// or https:// URL")
        if bearer_token and (username is not None or password is not None):
            raise ValueError("bearer_token cannot be combined with username/password")
        if (username is None) != (password is None):
            raise ValueError("username and password must be supplied together")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if key_file and not cert_file:
            raise ValueError("key_file requires cert_file")

        self.base_url = base_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.bearer_token = bearer_token
        self.default_headers = dict(headers or {})
        self.timeout = float(timeout)
        self.verify_tls = bool(verify_tls)

        ssl_context = None
        if parsed.scheme == "https":
            if verify_tls:
                ssl_context = ssl.create_default_context(cafile=ca_file)
            else:
                ssl_context = ssl._create_unverified_context()
            if cert_file:
                ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        handlers = []
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)

    def _url(self, path: str) -> str:
        parsed = urlparse(path)
        if parsed.scheme:
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("path URL must use http:// or https://")
            return path
        return urljoin(self.base_url, path.lstrip("/"))

    def _headers(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        headers = dict(self.default_headers)
        if extra:
            headers.update(extra)

        if self.bearer_token:
            headers.setdefault("Authorization", f"Bearer {self.bearer_token}")
        elif self.username is not None:
            raw = f"{self.username}:{self.password}".encode("utf-8")
            token = base64.b64encode(raw).decode("ascii")
            headers.setdefault("Authorization", f"Basic {token}")
        return headers

    def request(
        self,
        method: str,
        path: str = "",
        *,
        json_body: Any = None,
        data: bytes | bytearray | memoryview | str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ReaderHTTPResponse:
        """Send one management request to the reader.

        ``json_body`` and ``data`` are mutually exclusive.  Non-2xx HTTP
        responses and transport failures raise :class:`ReaderManagementError`.
        """

        if json_body is not None and data is not None:
            raise ValueError("json_body and data are mutually exclusive")

        request_headers = self._headers(headers)
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
            request_headers.setdefault("Accept", "application/json")
        elif data is not None:
            body = data.encode("utf-8") if isinstance(data, str) else bytes(data)

        req = Request(
            self._url(path),
            data=body,
            headers=request_headers,
            method=method.upper(),
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as response:
                response_body = response.read()
                return ReaderHTTPResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=response_body,
                )
        except HTTPError as exc:
            error_body = exc.read()
            detail = error_body.decode("utf-8", errors="replace").strip()
            message = f"reader returned HTTP {exc.code} {exc.reason}"
            if detail:
                message = f"{message}: {detail}"
            raise ReaderManagementError(
                message,
                status=exc.code,
                body=error_body,
            ) from exc
        except (URLError, OSError, TimeoutError) as exc:
            raise ReaderManagementError(f"reader management request failed: {exc}") from exc

    def get_settings(self, path: str) -> Any:
        """GET and JSON-decode a vendor settings endpoint."""
        return self.request("GET", path).json()

    def update_settings(
        self,
        path: str,
        settings: Mapping[str, Any],
        *,
        method: str = "PATCH",
    ) -> Any:
        """Update a vendor settings endpoint and decode any JSON response.

        ``PATCH`` is the default, but readers that require ``PUT`` or ``POST``
        can select that method explicitly.
        """
        method = method.upper()
        if method not in {"PATCH", "PUT", "POST"}:
            raise ValueError("settings update method must be PATCH, PUT, or POST")
        response = self.request(method, path, json_body=dict(settings))
        if not response.body:
            return None
        return response.json()

    def replace_settings(self, path: str, settings: Mapping[str, Any]) -> Any:
        """Replace a settings resource using HTTP PUT."""
        return self.update_settings(path, settings, method="PUT")
