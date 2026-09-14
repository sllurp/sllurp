import pytest

from sllurp.llrp import C1G2Read, C1G2TargetTag, LLRPReaderClient


def test_start_access_spec_accepts_two_target_filters(monkeypatch):
    reader = LLRPReaderClient("reader")
    captured = {}
    monkeypatch.setattr(
        reader.llrp, "startAccess", lambda **kwargs: captured.update(kwargs)
    )
    targets = [C1G2TargetTag(MB=1), C1G2TargetTag(MB=2)]
    reader.start_access_spec(C1G2Read(), target_spec=targets)
    assert captured["targetSpec"] == targets


def test_start_access_spec_rejects_more_than_two_targets():
    reader = LLRPReaderClient("reader")
    with pytest.raises(ValueError, match="at most two"):
        reader.start_access_spec(
            C1G2Read(),
            target_spec=[C1G2TargetTag(), C1G2TargetTag(), C1G2TargetTag()],
        )
