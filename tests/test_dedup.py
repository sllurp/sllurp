from sllurp.dedup import TagReportDeduplicator, default_tag_key


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_deduplicates_epc_within_window():
    clock = FakeClock()
    dedup = TagReportDeduplicator(window_seconds=1.0, clock=clock)
    tag = {"EPC-96": b"0123456789ab", "TagSeenCount": 1}

    assert dedup.filter([tag]) == [tag]
    assert dedup.filter([tag]) == []

    clock.advance(1.0)
    assert dedup.filter([tag]) == [tag]


def test_duplicate_sighting_does_not_refresh_window():
    clock = FakeClock()
    dedup = TagReportDeduplicator(window_seconds=1.0, clock=clock)
    tag = {"EPC-96": b"0123456789ab"}

    assert dedup.filter([tag]) == [tag]
    clock.advance(0.8)
    assert dedup.filter([tag]) == []
    clock.advance(0.2)
    assert dedup.filter([tag]) == [tag]


def test_can_scope_identity_by_antenna():
    dedup = TagReportDeduplicator(window_seconds=10, include_antenna=True)
    tag_a = {"EPC-96": b"same", "AntennaID": 1}
    tag_b = {"EPC-96": b"same", "AntennaID": 2}

    assert dedup.filter([tag_a, tag_b]) == [tag_a, tag_b]


def test_variable_length_epcdata_is_supported():
    tag = {"EPCData": {"EPC": b"variable-length"}}
    assert default_tag_key(tag) == ("EPCData", (("EPC", b"variable-length"),))


def test_callback_wrapper_only_emits_unique_reports():
    clock = FakeClock()
    calls = []

    def callback(reader, reports):
        calls.append((reader, reports))

    dedup = TagReportDeduplicator(callback, window_seconds=2.0, clock=clock)
    tag = {"EPC-96": b"0123456789ab"}

    dedup("reader", [tag])
    dedup("reader", [tag])

    assert calls == [("reader", [tag])]


def test_zero_window_disables_cross_report_suppression():
    dedup = TagReportDeduplicator(window_seconds=0)
    tag = {"EPC-96": b"0123456789ab"}

    assert dedup.filter([tag, tag]) == [tag, tag]


def test_large_population_default_capacity_and_eviction_are_bounded():
    clock = FakeClock()
    dedup = TagReportDeduplicator(window_seconds=600, max_entries=5, clock=clock)
    tags = [{"EPC-96": f"tag-{i}".encode()} for i in range(8)]

    assert dedup.filter(tags) == tags
    assert dedup.entry_count == 5
    assert dedup.evictions == 3
    assert TagReportDeduplicator().max_entries >= 500_000
