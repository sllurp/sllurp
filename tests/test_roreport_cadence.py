import pytest
from click.testing import CliRunner

import sllurp.cli as cli_module
import sllurp.llrp_proto as llrp_proto
from sllurp.llrp import LLRPClient, LLRPReaderConfig
from sllurp.llrp_proto import LLRPError, LLRPROSpec, decode_param, encode_param


def _aispec_stop(rospec):
    return rospec["AISpec"][0]["AISpecStopTrigger"]


def _report_spec(rospec):
    return rospec["ROReportSpec"]


def test_default_rospec_keeps_existing_report_and_aispec_defaults():
    rospec = LLRPROSpec(None, 1)

    assert _aispec_stop(rospec) == {
        "AISpecStopTriggerType": "Null",
        "DurationTriggerValue": 0,
    }
    assert _report_spec(rospec)["ROReportTrigger"] == (
        "Upon_N_Tags_Or_End_Of_AISpec"
    )
    assert _report_spec(rospec)["N"] == 0


def test_absent_option_preserves_default_rospec_wire_bytes():
    default = encode_param("ROSpec", LLRPROSpec(None, 1))
    explicit_none = encode_param(
        "ROSpec", LLRPROSpec(None, 1, ro_report_every_n_tags=None)
    )

    assert explicit_none == default


def test_legacy_report_count_retains_aispec_stop_behavior():
    rospec = LLRPROSpec(None, 1, report_every_n_tags=1)
    trigger = _aispec_stop(rospec)

    assert trigger["AISpecStopTriggerType"] == "Tag observation"
    assert trigger["TagObservationTrigger"] == {
        "TriggerType": "UponNTags",
        "NumberOfTags": 1,
        "NumberOfAttempts": 0,
        "T": 0,
        "Timeout": 0,
    }
    assert _report_spec(rospec)["N"] == 0


def test_legacy_timeout_remains_an_aispec_stop_timeout():
    rospec = LLRPROSpec(
        None,
        1,
        report_every_n_tags=25,
        report_timeout_ms=1000,
    )

    assert _aispec_stop(rospec)["TagObservationTrigger"]["Timeout"] == 1000
    assert _report_spec(rospec)["N"] == 0


@pytest.mark.parametrize("count", [1, 100, 65535])
def test_ro_report_count_sets_cadence_without_ending_aispec(count):
    rospec = LLRPROSpec(None, 1, ro_report_every_n_tags=count)

    assert _aispec_stop(rospec) == {
        "AISpecStopTriggerType": "Null",
        "DurationTriggerValue": 0,
    }
    assert "TagObservationTrigger" not in _aispec_stop(rospec)
    assert _report_spec(rospec)["ROReportTrigger"] == (
        "Upon_N_Tags_Or_End_Of_AISpec"
    )
    assert _report_spec(rospec)["N"] == count


def test_report_cadence_and_legacy_aispec_stop_are_independent():
    rospec = LLRPROSpec(
        None,
        1,
        ro_report_every_n_tags=10,
        report_every_n_tags=1000,
        report_timeout_ms=5000,
    )

    assert _report_spec(rospec)["N"] == 10
    observation = _aispec_stop(rospec)["TagObservationTrigger"]
    assert observation["NumberOfTags"] == 1000
    assert observation["Timeout"] == 5000


@pytest.mark.parametrize(
    "value",
    [0, -1, 65536, True, False, "1", 1.0, object()],
)
def test_ro_report_count_validation_rejects_invalid_values(value):
    message = "ro_report_every_n_tags must be an integer from 1 through 65535"

    with pytest.raises(LLRPError, match=message):
        LLRPReaderConfig({"ro_report_every_n_tags": value})
    with pytest.raises(LLRPError, match=message):
        LLRPROSpec(None, 1, ro_report_every_n_tags=value)


def test_client_rospec_cache_and_force_new_preserve_report_cadence():
    config = LLRPReaderConfig({"ro_report_every_n_tags": 1})
    client = LLRPClient(config)

    first = client.getROSpec()
    assert client.getROSpec() is first
    regenerated = client.getROSpec(force_new=True)

    assert regenerated is not first
    assert _report_spec(regenerated)["N"] == 1


def test_generated_rospec_round_trips_with_report_cadence():
    rospec = LLRPROSpec(None, 1, ro_report_every_n_tags=10)
    encoded = encode_param("ROSpec", rospec)

    name, decoded, consumed = decode_param(encoded)

    assert name == "ROSpec"
    assert consumed == len(encoded)
    assert decoded["ROReportSpec"]["ROReportTrigger"] == (
        "Upon_N_Tags_Or_End_Of_AISpec"
    )
    assert decoded["ROReportSpec"]["N"] == 10
    assert decoded["AISpec"][0]["AISpecStopTrigger"] == {
        "AISpecStopTriggerType": 0,
        "DurationTriggerValue": 0,
    }


def test_configuration_logs_distinguish_report_cadence_from_aispec_stop(monkeypatch):
    messages = []
    monkeypatch.setattr(
        llrp_proto.logger,
        "info",
        lambda message, *args: messages.append(message % args),
    )

    LLRPROSpec(None, 1, ro_report_every_n_tags=10)
    LLRPROSpec(
        None,
        2,
        report_every_n_tags=1000,
        report_timeout_ms=5000,
    )

    assert (
        "RO_ACCESS_REPORT will be requested every 10 tag observations while "
        "AISpec remains active"
    ) in messages
    assert "AISpec will end after 1000 tag observations or 5000 ms" in messages


def test_cli_passes_valid_report_cadence_to_inventory(monkeypatch):
    captured = []
    monkeypatch.setattr(cli_module._inventory, "main", captured.append)

    result = CliRunner().invoke(
        cli_module.cli,
        ["inventory", "--ro-report-every-n-tags", "10", "reader"],
    )

    assert result.exit_code == 0
    assert captured[0].ro_report_every_n_tags == 10


def test_cli_passes_valid_report_cadence_to_access(monkeypatch):
    captured = []
    monkeypatch.setattr(cli_module._access, "main", captured.append)

    result = CliRunner().invoke(
        cli_module.cli,
        [
            "access",
            "--ro-report-every-n-tags",
            "10",
            "--read-words",
            "1",
            "reader",
        ],
    )

    assert result.exit_code == 0
    assert captured[0].ro_report_every_n_tags == 10


@pytest.mark.parametrize("value", ["0", "-1", "65536", "1.0", "not-a-number"])
def test_cli_rejects_invalid_report_cadence(value, monkeypatch):
    calls = []
    monkeypatch.setattr(cli_module._inventory, "main", calls.append)

    result = CliRunner().invoke(
        cli_module.cli,
        ["inventory", "--ro-report-every-n-tags", value, "reader"],
    )

    assert result.exit_code == 2
    assert not calls
    assert "Invalid value for '--ro-report-every-n-tags'" in result.output


@pytest.mark.parametrize("command", ["inventory", "access"])
def test_cli_help_distinguishes_report_cadence_from_legacy_stop(command):
    result = CliRunner().invoke(cli_module.cli, [command, "--help"])

    assert result.exit_code == 0
    assert "--ro-report-every-n-tags" in result.output
    assert "without ending the AISpec" in result.output
    assert "Legacy: end the AISpec" in result.output
