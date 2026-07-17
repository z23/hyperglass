"""FRR BGP Route Parsing Tests."""

# flake8: noqa
# Standard Library
import json
from pathlib import Path

# Third Party
import pytest

# Project
from hyperglass.models.config.devices import Device
from hyperglass.models.data.bgp_route import BGPRouteTable
from hyperglass.exceptions.private import ParsingError

# Local
from ._fixtures import MockDevice
from .._builtin.bgp_route_frr import BGPRoutePluginFrr, parse_frr

DEPENDS_KWARGS = {
    "depends": [
        "hyperglass/models/tests/test_util.py::test_check_legacy_fields",
        "hyperglass/external/tests/test_rpki.py::test_rpki",
    ],
    "scope": "session",
}

SAMPLE = Path(__file__).parent.parent.parent.parent / ".samples" / "frr_bgp_route.json"


def _tester(sample: str):
    plugin = BGPRoutePluginFrr()

    device = MockDevice(
        name="Test Device",
        address="127.0.0.1",
        group="Test Network",
        credential={"username": "", "password": ""},
        platform="frr",
        structured_output=True,
        directives=["__hyperglass_frr_bgp_route_table__"],
        attrs={"source4": "192.0.2.1", "source6": "2001:db8::1"},
    )

    query = type("Query", (), {"device": device})

    result = plugin.process(output=(sample,), query=query)
    assert isinstance(result, BGPRouteTable), "Invalid parsed result"
    assert hasattr(result, "count"), "BGP Table missing count"
    assert result.count > 0, "BGP Table count is 0"


@pytest.mark.dependency(**DEPENDS_KWARGS)
def test_frr_route_sample():
    with SAMPLE.open("r") as file:
        sample = file.read()
    return _tester(sample)


def test_frr_validation_error_is_parsing_error():
    """A path that fails validation surfaces a clean ParsingError, not a TypeError.

    Regression for the same bug as #8 on Arista: `ParsingError(err.errors())`
    passed a list into `PrivateHyperglassError._safe_format`, raising TypeError
    and masking the real validation error as an opaque 500.
    """
    data = json.loads(SAMPLE.read_text())
    # Remove a required nested structure so FRRBGPTable validation fails.
    for path in data.get("paths", []):
        path.pop("nexthops", None)
        path.pop("peer", None)

    with pytest.raises(ParsingError):
        parse_frr((json.dumps(data),))
