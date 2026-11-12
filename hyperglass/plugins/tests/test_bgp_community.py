"""Test BGP Community validation."""

# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.plugins import init_builtin_plugins
from hyperglass.configuration import init_ui_params
from hyperglass.models.api.query import Query
from hyperglass.exceptions.public import InputInvalid
from hyperglass.defaults.directives import init_builtin_directives
from hyperglass.models.config.params import Params
from hyperglass.models.config.devices import Devices
from hyperglass.execution.drivers._construct import Construct

# Local
from .._builtin.bgp_community import ValidateBGPCommunity

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState


CHECKS = (
    ("32768", True),
    ("65000:1", True),
    ("65000:4294967296", False),
    ("4294967295:65000", False),
    ("192.0.2.1:65000", True),
    ("65000:192.0.2.1", False),
    ("target:65000:1", True),
    ("origin:65001:1", True),
    ("wrong:65000:1", False),
    ("65000:65001:65002", True),
    ("4294967295:4294967294:4294967293", True),
    ("65000:4294967295:1", True),
    ("65000:192.0.2.1:1", False),
    ("gibberish", False),
    ("192.0.2.1", False),
    ("65000:1 vrf all", False),
    (["65000:1"], True),
    (["65000:1", "65000:2"], True),
    (["65000:1 vrf all"], False),
    (["65000:1", "65000:1 vrf all"], False),
    (True, None),
    (type("FakeClass", (), {}), None),
)


@pytest.fixture
def params():
    return {}


@pytest.fixture
def state(*, params: t.Dict[str, t.Any]) -> t.Generator["HyperglassState", None, None]:
    """Test fixture to initialize Redis store."""
    _state = use_state()
    _params = Params(**params)

    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", _params)

    yield _state
    _state.clear()


def test_bgp_community(state):
    plugin = ValidateBGPCommunity()

    for value, expected in CHECKS:
        query = type("Query", (), {"query_target": value})
        result = plugin.validate(query)
        assert result == expected, f"Invalid value {value!r}"


def _device(name: str, address: str, platform: str) -> t.Dict[str, t.Any]:
    return {
        "name": name,
        "address": address,
        "platform": platform,
        "structured_output": False,
        "credential": {"username": "u", "password": "p"},
        "attrs": {"source4": "192.0.2.1", "source6": "2001:db8::1"},
    }


@pytest.fixture
def community_query_state(params):
    """Redis state with builtin directives, two devices, and builtin plugins."""
    _state = use_state()
    _params = Params(**params)
    directives = init_builtin_directives()
    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", _params)
        pipeline.set("directives", directives)
    devices = Devices(
        _device("lab-arista", "192.0.2.1", "arista_eos"),
        _device("lab-frr", "192.0.2.2", "frr"),
    )
    ui_params = init_ui_params(params=_params, devices=devices)
    with _state.cache.pipeline() as pipeline:
        pipeline.set("devices", devices)
        pipeline.set("ui_params", ui_params)
    init_builtin_plugins()
    yield _state
    _state.clear()


def _community_query(location: str, query_type: str, target: t.Union[str, t.List[str]]) -> Query:
    return Query(query_location=location, query_target=target, query_type=query_type)


def test_community_query_rejects_extra_words_for_string_and_list(community_query_state):
    """A community with extra CLI words is rejected as a string and as a one-element list."""
    expected = {
        "lab-arista": [
            "show ip bgp community 65000:1",
            "show ipv6 bgp community 65000:1",
        ],
        "lab-frr": [
            'vtysh -c "show bgp ipv4 unicast community 65000:1"',
            'vtysh -c "show bgp ipv6 unicast community 65000:1"',
        ],
    }
    cases = (
        ("lab-arista", "__hyperglass_arista_eos_bgp_community__"),
        ("lab-frr", "__hyperglass_frr_bgp_community__"),
    )
    for location, query_type in cases:
        for target in ("65000:1 vrf all", ["65000:1 vrf all"]):
            with pytest.raises(InputInvalid):
                _community_query(location, query_type, target)

        accepted = _community_query(location, query_type, "65000:1")
        accepted_list = _community_query(location, query_type, ["65000:1"])
        device = community_query_state.devices[location]
        assert Construct(device=device, query=accepted).queries() == expected[location]
        assert Construct(device=device, query=accepted_list).queries() == expected[location]
