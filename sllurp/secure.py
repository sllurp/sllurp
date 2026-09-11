"""TLS transport for secure LLRP connections.

This module adds LLRP over TLS without changing the existing plain-TCP
``LLRPReaderClient`` API. Secure LLRP uses TCP port 5085 by default.
"""

import select
import ssl
from socket import (
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_KEEPALIVE,
    SO_RCVBUF,
    IPPROTO_TCP,
    TCP_NODELAY,
    socket,
    error as SocketError,
)

from .llrp import LLRPReaderClient, LLRP_SECURE_PORT, SOCKET_RECV_CHUNK
from .llrp_errors import ReaderConfigurationError
from .log import get_logger

logger = get_logger(__name__)


def create_ssl_context(
    *,
    cafile=None,
    capath=None,
    cadata=None,
    certfile=None,
    keyfile=None,
    password=None,
    verify=True,
    check_hostname=None,
):
    """Create an SSLContext suitable for LLRP over TLS.

    Certificate verification and hostname checking are enabled by default.
    For readers using a private/self-signed CA, pass ``cafile``/``capath``/
    ``cadata`` rather than disabling verification.

    ``certfile`` and ``keyfile`` can be supplied for mutual TLS.
    """
    if check_hostname is None:
        check_hostname = verify

    if check_hostname and not verify:
        raise ValueError("check_hostname=True requires verify=True")

    if verify:
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=cafile,
            capath=capath,
            cadata=cadata,
        )
        context.check_hostname = check_hostname
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if certfile:
        context.load_cert_chain(certfile, keyfile=keyfile, password=password)
    elif keyfile:
        raise ValueError("keyfile requires certfile")

    return context


class LLRPTLSReaderClient(LLRPReaderClient):
    """LLRP reader client using TLS for the transport layer.

    The default secure LLRP port is 5085. Existing LLRP framing and state
    handling are inherited from :class:`LLRPReaderClient`.

    Args:
        host: Reader hostname or IP address.
        port: TLS LLRP port. Defaults to 5085.
        config: Optional ``LLRPReaderConfig``.
        timeout: Socket timeout in seconds.
        ssl_context: Optional preconfigured ``ssl.SSLContext``. When supplied,
            certificate-related arguments must not also be supplied.
        server_hostname: TLS SNI / certificate hostname. Defaults to ``host``.
        cafile/capath/cadata: Trust material for the reader certificate.
        certfile/keyfile/password: Optional client certificate for mutual TLS.
        verify: Verify the reader certificate. Defaults to True.
        check_hostname: Check that the certificate matches ``server_hostname``.
            Defaults to the value of ``verify``.
    """

    def __init__(
        self,
        host,
        port=None,
        config=None,
        timeout=5.0,
        *,
        ssl_context=None,
        server_hostname=None,
        cafile=None,
        capath=None,
        cadata=None,
        certfile=None,
        keyfile=None,
        password=None,
        verify=True,
        check_hostname=None,
    ):
        tls_options_supplied = any(
            value is not None
            for value in (
                cafile,
                capath,
                cadata,
                certfile,
                keyfile,
                password,
                check_hostname,
            )
        ) or verify is not True

        if ssl_context is not None and tls_options_supplied:
            raise ValueError(
                "ssl_context cannot be combined with certificate/verification options"
            )

        if ssl_context is None:
            ssl_context = create_ssl_context(
                cafile=cafile,
                capath=capath,
                cadata=cadata,
                certfile=certfile,
                keyfile=keyfile,
                password=password,
                verify=verify,
                check_hostname=check_hostname,
            )

        self.ssl_context = ssl_context
        self.server_hostname = host if server_hostname is None else server_hostname

        super().__init__(
            host,
            LLRP_SECURE_PORT if port is None else port,
            config=config,
            timeout=timeout,
        )

    def _connect_socket(self):
        if self._socket:
            raise ReaderConfigurationError("Already connected")

        raw_socket = None
        try:
            raw_socket = socket(AF_INET, SOCK_STREAM)
            if self.config.socket_receive_buffer_bytes is not None:
                raw_socket.setsockopt(
                    SOL_SOCKET, SO_RCVBUF, self.config.socket_receive_buffer_bytes
                )
            raw_socket.settimeout(self._socktimeout)
            raw_socket.connect((self._host, self._port))
            raw_socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
            raw_socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)

            self._socket = self.ssl_context.wrap_socket(
                raw_socket,
                server_hostname=self.server_hostname,
            )
        except Exception:
            self._socket = None
            if raw_socket is not None:
                try:
                    raw_socket.close()
                except Exception:
                    pass
            raise

        self._disconnected_notified = False
        logger.info("connected securely to %s (:%s)", self._host, self._port)
        return True

    def main_loop(self):
        """Receive TLS data while also draining already-decrypted TLS bytes."""
        if not self._socket:
            self._socket_thread = None
            raise ReaderConfigurationError("Not connected")

        try:
            while True:
                lost_connection = False

                # SSLSocket.pending() reports decrypted bytes already buffered
                # in OpenSSL. select() cannot see those bytes, so drain them
                # before blocking on the underlying file descriptor.
                if self._socket.pending():
                    read_sockets = [self._socket]
                else:
                    read_sockets, _, _ = select.select([self._socket], [], [])

                for sock in read_sockets:
                    try:
                        data = sock.recv(SOCKET_RECV_CHUNK)
                        if data:
                            self.raw_data_received(data)
                        else:
                            logger.warning("\nDisconnected from server")
                            lost_connection = True
                    except ssl.SSLWantReadError:
                        continue
                    except (ssl.SSLError, SocketError):
                        logger.exception("\nDisconnected from secure LLRP server")
                        lost_connection = True
                    except ReaderConfigurationError:
                        self.hard_disconnect()
                        self._on_disconnected()
                        logger.error(
                            "\nDisconnected because of a reader configuration error"
                        )

                if self._stop_main_loop.is_set():
                    break

                if lost_connection:
                    if self.on_lost_connection():
                        break
                    self._stop_main_loop.clear()
        except Exception:
            logger.exception("Exception encountered in secure main loop, exiting...")
            try:
                self.hard_disconnect()
            except Exception:
                logger.exception("Error while cleaning up failed secure reader connection")
            self._on_disconnected()

        self._socket_thread = None


# Clear alias for callers that prefer the wording used by the LLRP standard.
SecureLLRPReaderClient = LLRPTLSReaderClient

__all__ = [
    "LLRP_SECURE_PORT",
    "LLRPTLSReaderClient",
    "SecureLLRPReaderClient",
    "create_ssl_context",
]
