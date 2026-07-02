# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.models.api import Query
from hyperglass.configuration import init_ui_params
from hyperglass.models.directive import Directives
from hyperglass.models.config.params import Params
from hyperglass.models.config.devices import Devices
from hyperglass.exceptions.public import InputInvalid

# Local
from .._construct import Construct

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState


@pytest.fixture
def params():
    return {}


@pytest.fixture
def devices():
    return [
        {
            "name": "test1",
            "address": "127.0.0.1",
            "credential": {"username": "", "password": ""},
            "platform": "juniper",
            "attrs": {"source4": "192.0.2.1", "source6": "2001:db8::1"},
            "directives": ["juniper_bgp_route"],
        }
    ]


@pytest.fixture
def directives():
    return [
        {
            "juniper_bgp_route": {
                "name": "BGP Route",
                "field": {"description": "test"},
            }
        }
    ]


@pytest.fixture
def state(
    *,
    params: t.Dict[str, t.Any],
    directives: t.Sequence[t.Dict[str, t.Any]],
    devices: t.Sequence[t.Dict[str, t.Any]],
) -> t.Generator["HyperglassState", None, None]:
    """Test fixture to initialize Redis store."""
    _state = use_state()
    _params = Params(**params)
    _directives = Directives.new(*directives)

    with _state.cache.pipeline() as pipeline:
        # Write params and directives to the cache first to avoid a race condition where ui_params
        # or devices try to access params or directives before they're available.
        pipeline.set("params", _params)
        pipeline.set("directives", _directives)

    _devices = Devices(*devices)
    ui_params = init_ui_params(params=_params, devices=_devices)

    with _state.cache.pipeline() as pipeline:
        pipeline.set("devices", _devices)
        pipeline.set("ui_params", ui_params)

    yield _state
    _state.clear()


def test_construct(state):
    query = Query(
        queryLocation="test1",
        queryTarget="192.0.2.0/24",
        queryType="juniper_bgp_route",
    )
    constructor = Construct(device=state.devices["test1"], query=query)
    assert constructor.target == "192.0.2.0/24"


@pytest.mark.parametrize("metachar", [";", "|", "\n", "`", '"', "<", ">", "\\"])
def test_construct_format_rejects_forbidden_post_formatter_target(state, metachar):
    """Layer-3 defense in depth must reject a metachar in `self.target`.

    Even if Layers 1/2 are bypassed (e.g. by a plugin transform that injects
    a metacharacter, or a `RuleWithoutValidation` directive),
    `Construct.format()` must still refuse to build the command string.
    Simulated by mutating `target` post-init to a forbidden value.
    """
    query = Query(
        queryLocation="test1",
        queryTarget="192.0.2.0/24",
        queryType="juniper_bgp_route",
    )
    constructor = Construct(device=state.devices["test1"], query=query)
    constructor.target = f"192.0.2.0/24{metachar}id"
    with pytest.raises(InputInvalid):
        constructor.format("show route {target}")
