import io
import runpy
import sys
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import sllurp.cli as cli_module
import sllurp.decode as decode_module
import sllurp.lock as lock_module
import sllurp.verb.access as access_module
import sllurp.verb.inventory as inventory_module
import sllurp.verb.log as log_module
import sllurp.verb.reset as reset_module
from sllurp.llrp import C1G2Lock, C1G2Read, C1G2Write
from sllurp.llrp_decoder import msg_header_encode
from sllurp.llrp_proto import Message_struct


class FakeReader:
    instances = []
    disconnect_all_calls = 0

    def __init__(self, host, port=None, config=None, timeout=5.0):
        self.host = host
        self.port = port
        self.config = config
        self.timeout = timeout
        self.connected = False
        self.disconnected = False
        self.state_callbacks = []
        self.tag_callbacks = []
        self.disconnected_callbacks = []
        self.access_specs = []
        self.alive = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.disconnect_all_calls = 0

    @classmethod
    def disconnect_all_readers(cls, *args, **kwargs):
        cls.disconnect_all_calls += 1

    def add_disconnected_callback(self, callback):
        self.disconnected_callbacks.append(callback)

    def add_tag_report_callback(self, callback):
        self.tag_callbacks.append(callback)

    def add_state_callback(self, state, callback):
        self.state_callbacks.append((state, callback))

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.disconnected = True
        self.alive = False

    def is_alive(self):
        return self.alive

    def join(self, timeout=None):
        return None

    def get_peername(self):
        return self.host, self.port

    def start_access_spec(self, opspec, stop_after_count=0, **kwargs):
        self.access_specs.append((opspec, stop_after_count, kwargs))
        return "started"


def tls_args():
    return dict(
        tls_enabled=False,
        tls_verify=True,
        tls_ca_file=None,
        tls_client_cert=None,
        tls_client_key=None,
        tls_server_hostname=None,
    )


def inventory_args(**overrides):
    values = dict(
        host=["reader-a", "reader-b:6000"],
        port=5084,
        time=0,
        every_n=2,
        antennas="0",
        tx_power=0,
        tari=0,
        session=2,
        mode_identifier=None,
        population=4,
        reconnect=False,
        reconnect_retries=2,
        tag_filter_mask=[],
        keepalive_interval=60000,
        impinj_extended_configuration=False,
        impinj_search_mode=None,
        impinj_reports=False,
        frequencies="0",
        hoptable_id=1,
        **tls_args(),
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def access_args(**overrides):
    values = dict(
        host=["reader-a"],
        port=5084,
        time=0,
        every_n=1,
        antennas="1,2",
        tx_power=0,
        tari=0,
        session=2,
        mode_identifier=None,
        population=4,
        read_words=1,
        write_words=None,
        count=1,
        mb=3,
        word_ptr=0,
        access_password=0,
        frequencies="0",
        hoptable_id=1,
        **tls_args(),
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def log_args(outfile, **overrides):
    values = dict(
        host=["reader-a"],
        port=5084,
        outfile=outfile,
        antennas="0",
        tx_power=0,
        epc=None,
        reader_timestamp=False,
        frequencies="0",
        hoptable_id=1,
        **tls_args(),
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def reset_args(**overrides):
    values = dict(host=["reader-a"], port=5084, **tls_args())
    values.update(overrides)
    return SimpleNamespace(**values)


def test_inventory_main_builds_capability_driven_readers(monkeypatch):
    FakeReader.reset()
    monkeypatch.setattr(inventory_module, "LLRPReaderClient", FakeReader)

    inventory_module.main(inventory_args())

    assert [(reader.host, reader.port) for reader in FakeReader.instances] == [
        ("reader-a", 5084),
        ("reader-b", 6000),
    ]
    assert all(reader.connected for reader in FakeReader.instances)
    assert FakeReader.disconnect_all_calls == 1
    for reader in FakeReader.instances:
        assert reader.config.antennas == [0]
        assert reader.config.frequencies["Automatic"] is True
        assert reader.config.frequencies["ChannelList"] == [1]
        assert reader.tag_callbacks == [inventory_module.tag_report_cb]


def test_inventory_callbacks_cover_empty_and_tagged_reports(monkeypatch):
    inventory_module.numtags = 0
    inventory_module.start_time = 10.0
    monkeypatch.setattr(inventory_module, "monotonic", lambda: 12.0)

    inventory_module.tag_report_cb(None, [])
    inventory_module.tag_report_cb(None, [{"TagSeenCount": 3}])
    inventory_module.finish_cb(None)
    inventory_module.inventory_start_cb(None, None)

    assert inventory_module.numtags == 3
    assert inventory_module.start_time == 12.0


def test_log_main_writes_csv_header_without_hardware(monkeypatch):
    FakeReader.reset()
    monkeypatch.setattr(log_module, "LLRPReaderClient", FakeReader)
    output = io.StringIO()

    log_module.main(log_args(output))

    assert FakeReader.instances[0].connected is True
    assert FakeReader.instances[0].config.frequencies["Automatic"] is True
    assert output.getvalue().startswith("timestamp,reader,antenna,rssi,epc")


def test_csv_logger_filters_epc_and_supports_reader_timestamp():
    output = io.StringIO()
    logger = log_module.CsvLogger(output, epc="wanted", reader_timestamp=True)
    reader = FakeReader("reader-a", 5084)
    tags = [
        {
            "EPC": "ignored",
            "LastSeenTimestampUTC": 1_000_000,
            "AntennaID": 1,
            "PeakRSSI": -50,
            "TagSeenCount": 1,
        },
        {
            "EPC": "wanted",
            "LastSeenTimestampUTC": 2_000_000,
            "AntennaID": 2,
            "PeakRSSI": -40,
            "TagSeenCount": 3,
        },
    ]

    logger.tag_cb(reader, tags)
    logger.flush()

    assert logger.num_tags == 3
    assert len(logger.rows) == 1
    assert logger.rows[0][:4] == (2.0, "reader-a:5084", 2, -40)
    assert "wanted" in output.getvalue()
    assert "ignored" not in output.getvalue()


def test_access_main_builds_reader_and_frequency_config(monkeypatch):
    FakeReader.reset()
    monkeypatch.setattr(access_module, "LLRPReaderClient", FakeReader)

    access_module.main(access_args())

    reader = FakeReader.instances[0]
    assert reader.connected is True
    assert reader.config.antennas == [1, 2]
    assert reader.config.frequencies["Automatic"] is True
    assert reader.tag_callbacks == [access_module.tag_report_cb]


def test_access_callback_builds_read_and_write_ops(monkeypatch):
    reader = FakeReader("reader-a", 5084)

    access_module.args = access_args(read_words=2, write_words=None, count=7)
    assert access_module.access_cb(reader, None) == "started"
    assert isinstance(reader.access_specs[-1][0], C1G2Read)
    assert reader.access_specs[-1][1] == 7

    class FakeStdin:
        buffer = io.BytesIO(b"\x01\x02\x03\x04")

    monkeypatch.setattr(access_module.sys, "stdin", FakeStdin())
    access_module.args = access_args(read_words=None, write_words=2, count=2)
    assert access_module.access_cb(reader, None) == "started"
    assert isinstance(reader.access_specs[-1][0], C1G2Write)

    access_module.args = access_args(read_words=None, write_words=None)
    assert access_module.access_cb(reader, None) is None


def test_access_tag_callback_handles_read_result(monkeypatch):
    access_module.tagReport = 0

    class FakeStdout:
        buffer = io.BytesIO()

    fake_stdout = FakeStdout()
    monkeypatch.setattr(access_module.sys, "stdout", fake_stdout)
    access_module.tag_report_cb(None, [])
    access_module.tag_report_cb(
        None,
        [
            {
                "TagSeenCount": 2,
                "C1G2ReadOpSpecResult": {"ReadData": b"\xaa\xbb"},
            }
        ],
    )

    assert access_module.tagReport == 2
    assert fake_stdout.buffer.getvalue() == b"\xaa\xbb"


def test_reset_main_and_shutdown_callback(monkeypatch):
    FakeReader.reset()
    monkeypatch.setattr(reset_module, "LLRPReaderClient", FakeReader)

    reset_module.main(reset_args())

    reader = FakeReader.instances[0]
    assert reader.connected is True
    assert reader.timeout == 3
    assert reader.config.start_inventory is False
    reset_module.shutdown(reader, None)
    assert reader.disconnected is True


def test_lock_parse_args_and_main_without_hardware(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sllurp.lock",
            "reader-a",
            "--antennas",
            "1,2",
            "--privilege",
            "3",
            "--data-field",
            "4",
        ],
    )
    lock_module.parse_args()
    assert lock_module.args.host == ["reader-a"]
    assert lock_module.args.privilege == 3
    assert lock_module.args.data_field == 4

    FakeReader.reset()
    parsed = lock_module.args
    monkeypatch.setattr(lock_module, "parse_args", lambda: setattr(lock_module, "args", parsed))
    monkeypatch.setattr(lock_module, "init_logging", lambda: None)
    monkeypatch.setattr(lock_module, "LLRPReaderClient", FakeReader)

    lock_module.main()

    reader = FakeReader.instances[0]
    assert reader.connected is True
    assert reader.config.antennas == [1, 2]


def test_lock_callbacks_create_lock_operation_and_count_tags(monkeypatch):
    reader = FakeReader("reader-a", 5084)
    lock_module.args = SimpleNamespace(
        privilege=1,
        data_field=4,
        access_password=123,
        count=5,
    )

    assert lock_module.access_cb(reader, None) == "started"
    assert isinstance(reader.access_specs[-1][0], C1G2Lock)
    assert reader.access_specs[-1][1] == 5

    lock_module.tagReport = 0
    lock_module.tag_report_cb(None, [])
    lock_module.tag_report_cb(
        None,
        [{"TagSeenCount": 4, "C1G2LockOpSpecResult": {"Result": 0}}],
    )
    assert lock_module.tagReport == 4

    lock_module.startTime = 1.0
    monkeypatch.setattr(lock_module, "monotonic", lambda: 3.0)
    lock_module.finish_cb(None)
    assert lock_module.endTime == 3.0


def test_decode_script_decodes_header_only_message(monkeypatch, capsys):
    frame = msg_header_encode(Message_struct["KEEPALIVE"]["type"], 1, 0, 77)
    monkeypatch.setattr(sys, "argv", ["sllurp.decode", frame.hex()])

    runpy.run_module("sllurp.decode", run_name="__main__")

    output = capsys.readouterr().out
    assert "Decoded message" in output
    assert "KEEPALIVE" in output


def test_decode_parse_args_and_logging(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sllurp.decode", "00", "--debug"])
    decode_module.parse_args()
    decode_module.init_logging()

    assert decode_module.args.msg == "00"
    assert decode_module.args.debug is True


def test_python_m_entrypoint_runs_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sllurp", "version"])

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("sllurp.__main__", run_name="__main__")

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip()


@pytest.mark.parametrize(
    "command,target,extra",
    [
        ("access", "_access", ["--read-words", "1"]),
        ("reset", "_reset", []),
    ],
)
def test_cli_forwards_all_reader_commands(monkeypatch, command, target, extra):
    captured = []
    monkeypatch.setattr(getattr(cli_module, target), "main", captured.append)

    result = CliRunner().invoke(cli_module.cli, [command, *extra, "reader-a"])

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0].host == ("reader-a",)
