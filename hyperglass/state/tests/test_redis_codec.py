"""Regression tests for the Redis cache JSON codec.

These pin the security guarantee that the cache layer never deserializes
arbitrary objects (the legacy `pickle.loads` was an RCE vector if Redis were
ever reachable). The codec accepts only JSON; non-JSON payloads raise
`StateDecodeError` rather than executing deserialized code.

These tests exercise the pure `_encode`/`_decode` helpers directly and do not
require a running Redis instance.
"""

# Standard Library
import pytest

# Project
from hyperglass.state.redis import _decode, _encode, StateDecodeError


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1, "b": [1, 2, "x"]},
        "hello",
        42,
        3.14,
        True,
        False,
        None,
        ["a", 1, True],
        {"nested": {"k": "v"}, "list": [1, {"inner": 2}]},
        "",
        [],
        {},
    ],
)
def test_roundtrip_json_native(value):
    """JSON-native values must survive an encode/decode round trip unchanged."""
    assert _decode(_encode(value)) == value
    assert isinstance(_encode(value), bytes)


def test_roundtrip_bytes():
    """Bytes are base64-wrapped since JSON has no bytes literal."""
    payload = b"\x00\x01\x02raw binary\xfe\xff"
    assert _decode(_encode(payload)) == payload


def test_decode_rejects_pickle_payload():
    """A legacy pickled value must raise StateDecodeError, not execute.

    The classic pickle exploit relies on `pickle.loads` running `__reduce__`.
    JSON decoding never invokes arbitrary code, so this is the core safety
    property of the migration.
    """
    import pickle

    legacy = pickle.dumps({"anything": "inside"})
    with pytest.raises(StateDecodeError):
        _decode(legacy)


@pytest.mark.parametrize("bad", [b"\x80\x05\x00\x00not json", b"\xff\xfe garbage", b""])
def test_decode_rejects_non_json(bad):
    """Any non-JSON bytes must raise StateDecodeError instead of crashing."""
    with pytest.raises(StateDecodeError):
        _decode(bad)
