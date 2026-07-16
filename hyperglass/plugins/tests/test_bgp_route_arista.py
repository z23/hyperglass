"""Arista BGP Route Parsing Tests."""

# flake8: noqa
# Standard Library
import json
from pathlib import Path

# Third Party
import pytest

# Project
from hyperglass.models.config.devices import Device
from hyperglass.exceptions.private import ParsingError
from hyperglass.models.data.bgp_route import BGPRouteTable
from hyperglass.models.parsing.arista_eos import AristaBGPTable

# Local
from ._fixtures import MockDevice
from .._builtin.bgp_route_arista import parse_arista, BGPRoutePluginArista

DEPENDS_KWARGS = {
    "depends": [
        "hyperglass/models/tests/test_util.py::test_check_legacy_fields",
        "hyperglass/external/tests/test_rpki.py::test_rpki",
    ],
    "scope": "session",
}

SAMPLE = Path(__file__).parent.parent.parent.parent / ".samples" / "arista_route.json"


def _tester(sample: str):
    plugin = BGPRoutePluginArista()

    device = MockDevice(
        name="Test Device",
        address="127.0.0.1",
        group="Test Network",
        credential={"username": "", "password": ""},
        platform="arista",
        structured_output=True,
        directives=["__hyperglass_arista_eos_bgp_route_table__"],
        attrs={"source4": "192.0.2.1", "source6": "2001:db8::1"},
    )

    query = type("Query", (), {"device": device})

    result = plugin.process(output=(sample,), query=query)
    assert isinstance(result, BGPRouteTable), "Invalid parsed result"
    assert hasattr(result, "count"), "BGP Table missing count"
    assert result.count > 0, "BGP Table count is 0"


@pytest.mark.dependency(**DEPENDS_KWARGS)
def test_arista_route_sample():
    with SAMPLE.open("r") as file:
        sample = file.read()
    return _tester(sample)


def _sample_without_route_detail() -> str:
    """Return the EOS sample with every routeDetail block removed.

    This mirrors BGP AS Path and BGP Community query output, which does not
    include the routeDetail block.
    """
    data = json.loads(SAMPLE.read_text())
    for vrf in data["vrfs"].values():
        for entry in vrf["bgpRouteEntries"].values():
            for path in entry.get("bgpRoutePaths", []):
                path.pop("routeDetail", None)
    return json.dumps(data)


def test_arista_route_detail_optional():
    """A path missing routeDetail must validate (routeDetail defaults to None).

    Mirrors BGP AS Path/Community query output, where the routeDetail block is
    legitimately absent. Under pydantic v2 an Optional field without a default
    is still a required key, so this pins the explicit ``= None`` default.
    """
    data = json.loads(_sample_without_route_detail())
    vrf = next(iter(data["vrfs"]))
    table = AristaBGPTable(**data["vrfs"][vrf])
    for entry in table.bgp_route_entries.values():
        for path in entry.bgp_route_paths:
            assert path.route_detail is None


def test_arista_validation_error_is_parsing_error():
    """A path that fails validation surfaces a clean ParsingError, not a TypeError.

    Regression for the bug where `ParsingError(err.errors())` passed a list
    into `PrivateHyperglassError._safe_format`, raising TypeError and masking
    the real validation error as an opaque 500.
    """
    data = json.loads(SAMPLE.read_text())
    vrf = next(iter(data["vrfs"]))
    # Remove a genuinely-required field to force a ValidationError.
    for entry in data["vrfs"][vrf]["bgpRouteEntries"].values():
        for path in entry.get("bgpRoutePaths", []):
            path.pop("nextHop", None)

    with pytest.raises(ParsingError):
        parse_arista((json.dumps(data),))
