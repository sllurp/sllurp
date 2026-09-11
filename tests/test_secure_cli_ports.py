import pytest
from click.testing import CliRunner

import sllurp.cli as cli_module
from sllurp.llrp import LLRP_DEFAULT_PORT
from sllurp.secure import LLRP_SECURE_PORT


@pytest.mark.parametrize(
    ("command", "verb_attr"),
    [
        ("inventory", "_inventory"),
        ("log", "_log"),
        ("access", "_access"),
        ("reset", "_reset"),
    ],
)
def test_tls_cli_uses_encrypted_llrp_port_by_default(monkeypatch, command, verb_attr):
    captured = []
    monkeypatch.setattr(getattr(cli_module, verb_attr), "main", captured.append)

    result = CliRunner().invoke(cli_module.cli, [command, "--tls", "reader.example"])

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0].port == LLRP_SECURE_PORT == 5085


@pytest.mark.parametrize(
    ("command", "verb_attr"),
    [
        ("inventory", "_inventory"),
        ("log", "_log"),
        ("access", "_access"),
        ("reset", "_reset"),
    ],
)
def test_plain_cli_keeps_normal_llrp_port(monkeypatch, command, verb_attr):
    captured = []
    monkeypatch.setattr(getattr(cli_module, verb_attr), "main", captured.append)

    result = CliRunner().invoke(cli_module.cli, [command, "reader.example"])

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0].port == LLRP_DEFAULT_PORT == 5084


def test_explicit_secure_port_override_is_preserved(monkeypatch):
    captured = []
    monkeypatch.setattr(cli_module._inventory, "main", captured.append)

    result = CliRunner().invoke(
        cli_module.cli,
        ["inventory", "--tls", "--port", "55085", "reader.example"],
    )

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0].port == 55085
