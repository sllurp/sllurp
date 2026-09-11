import ssl
from socket import SOL_SOCKET, SO_RCVBUF
from unittest.mock import Mock, patch

import pytest

from sllurp.llrp import SOCKET_RECV_CHUNK
from sllurp.secure import (
    LLRP_SECURE_PORT,
    LLRPTLSReaderClient,
    SecureLLRPReaderClient,
    create_ssl_context,
)


def test_secure_llrp_default_port():
    reader = LLRPTLSReaderClient("reader.example.test")
    assert reader.get_peername() == ("reader.example.test", LLRP_SECURE_PORT)


def test_secure_alias():
    assert SecureLLRPReaderClient is LLRPTLSReaderClient


def test_default_context_verifies_peer_and_hostname():
    context = create_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_insecure_context_requires_explicit_opt_out():
    context = create_ssl_context(verify=False)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_hostname_check_requires_verification():
    with pytest.raises(ValueError, match="requires verify=True"):
        create_ssl_context(verify=False, check_hostname=True)


def test_key_requires_certificate():
    with pytest.raises(ValueError, match="keyfile requires certfile"):
        create_ssl_context(keyfile="reader-client.key")


def test_custom_context_cannot_be_mixed_with_context_options():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with pytest.raises(ValueError, match="ssl_context cannot be combined"):
        LLRPTLSReaderClient(
            "reader.example.test",
            ssl_context=context,
            verify=False,
        )


def test_connect_wraps_socket_with_tls_and_sets_receive_buffer():
    raw_socket = Mock()
    tls_socket = Mock()

    context = Mock()
    context.wrap_socket.return_value = tls_socket

    reader = LLRPTLSReaderClient(
        "reader.example.test",
        ssl_context=context,
        server_hostname="reader-cert.example.test",
    )

    with patch("sllurp.secure.socket", return_value=raw_socket):
        assert reader._connect_socket() is True

    raw_socket.settimeout.assert_called_once_with(5.0)
    raw_socket.connect.assert_called_once_with(
        ("reader.example.test", LLRP_SECURE_PORT)
    )
    raw_socket.setsockopt.assert_any_call(
        SOL_SOCKET, SO_RCVBUF, reader.config.socket_receive_buffer_bytes
    )
    context.wrap_socket.assert_called_once_with(
        raw_socket,
        server_hostname="reader-cert.example.test",
    )
    assert reader._socket is tls_socket


def test_secure_receive_chunk_matches_core_client():
    assert SOCKET_RECV_CHUNK >= 64 * 1024


def test_tls_handshake_failure_closes_raw_socket():
    raw_socket = Mock()
    context = Mock()
    context.wrap_socket.side_effect = ssl.SSLError("handshake failed")

    reader = LLRPTLSReaderClient(
        "reader.example.test",
        ssl_context=context,
    )

    with patch("sllurp.secure.socket", return_value=raw_socket):
        with pytest.raises(ssl.SSLError):
            reader._connect_socket()

    raw_socket.close.assert_called_once_with()
    assert reader._socket is None


def test_secure_main_loop_unexpected_failure_cleans_up(monkeypatch):
    reader = LLRPTLSReaderClient(
        "reader.example.test",
        ssl_context=Mock(),
    )
    tls_socket = Mock()
    tls_socket.pending.return_value = 0
    reader._socket = tls_socket
    called = []
    reader.add_disconnected_callback(called.append)

    def fail_select(*_args, **_kwargs):
        raise RuntimeError("select failed")

    monkeypatch.setattr("sllurp.secure.select.select", fail_select)
    reader.main_loop()

    assert reader._socket is None
    assert called == [reader]
