"""Query targets must not be able to carry more than the directive asks for.

Covers gaps that the character deny-list alone does not close:

- the built-in BGP community and AS path directives interpolate the target
  into the device command without quoting on most platforms, so any accepted
  word after the value becomes a command keyword (`vrf all`, `detail`);
- a select field's options were only enforced by the UI;
- list targets were unbounded and were accepted by single-value directives;
- `?` (the help key on an interactive CLI) and non-ASCII control, format and
  separator characters were accepted wherever a rule did no validation.
"""

# Standard Library
import typing as t

# Third Party
import pytest
from pydantic import ValidationError

# Project
from hyperglass.state import use_state
from hyperglass.plugins import InputPluginManager, OutputPluginManager, init_builtin_plugins
from hyperglass.constants import MAX_QUERY_TARGETS, target_contains_forbidden_content
from hyperglass.models.api import Query
from hyperglass.state.hooks import _use_state
from hyperglass.configuration import init_ui_params
from hyperglass.exceptions.public import InputInvalid
from hyperglass.defaults.directives import init_builtin_directives
from hyperglass.models.config.params import Params
from hyperglass.models.config.devices import Devices
from hyperglass.execution.drivers._construct import Construct
from hyperglass.plugins._builtin.bgp_aspath import ValidateBGPASPath, validate_as_path
from hyperglass.plugins._builtin.bgp_community import ValidateBGPCommunity, check_decimal

# Local
from ..directive import Directives

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState

PLATFORMS = {
    "eos": "arista_eos",
    "ios": "cisco_ios",
    "nxos": "cisco_nxos",
    "xr": "cisco_xr",
    "huawei": "huawei",
    "junos": "juniper",
    "tik": "mikrotik_routeros",
    "sros": "nokia_sros",
    "frr": "frr",
    "bird": "bird",
    "obgpd": "openbgpd",
    "vyos": "vyos",
}

CUSTOM = {
    "pick": {
        "name": "Pick",
        "rules": [{"condition": None, "command": "show thing {target}"}],
        "field": {"description": "Pick", "options": [{"value": "a"}, {"value": "b c"}]},
    },
    "pick_many": {
        "name": "Pick Many",
        "multiple": True,
        "rules": [{"condition": None, "command": "show thing {target}"}],
        "field": {"description": "Pick", "options": [{"value": "a"}, {"value": "b"}]},
    },
    "free": {
        "name": "Free",
        "rules": [{"condition": None, "command": "show thing {target}"}],
        "field": {"description": "Text"},
    },
    "asns": {
        "name": "ASNs",
        "multiple": True,
        "rules": [{"condition": "[0-9]+", "command": "show as {target}"}],
        "field": {"description": "ASNs"},
    },
    "asn": {
        "name": "ASN",
        "rules": [{"condition": "[0-9]+", "command": "show as {target}"}],
        "field": {"description": "ASN"},
    },
}


@pytest.fixture
def state() -> t.Generator["HyperglassState", None, None]:
    """State with one device per platform, built-in directives and built-in plugins."""
    _use_state.cache_clear()
    _state = use_state()
    params = Params()
    directives = Directives(*init_builtin_directives(), *Directives.new(CUSTOM))

    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", params)
        pipeline.set("directives", directives)

    devices = Devices(
        *(
            {
                "name": name,
                "address": f"192.0.2.{index}",
                "platform": platform,
                "credential": {"username": "user", "password": "pass"},
                "attrs": {"source4": "198.51.100.1", "source6": "2001:db8::1"},
                "directives": [{"builtins": True}, *CUSTOM],
            }
            for index, (name, platform) in enumerate(PLATFORMS.items(), start=1)
        )
    )

    with _state.cache.pipeline() as pipeline:
        pipeline.set("devices", devices)
        pipeline.set("ui_params", init_ui_params(params=params, devices=devices))

    _use_state.cache_clear()
    init_builtin_plugins()
    yield _state
    for manager in (InputPluginManager, OutputPluginManager):
        manager().reset()
    _state.clear()
    _use_state.cache_clear()


def directive_id(state: "HyperglassState", location: str, marker: str) -> str:
    """Get the device's directive ID for a query kind (plain or table variant)."""
    ids = [directive.id for directive in state.devices[location].directives]
    if marker in ids:
        return marker
    matches = [i for i in ids if marker in i]
    assert matches, f"{location} has no directive matching {marker}"
    return matches[0]


def command(state: "HyperglassState", location: str, marker: str, target: t.Any) -> str:
    """Validate a query the way the API does and return the first device command."""
    query = Query(
        queryLocation=location,
        queryType=directive_id(state, location, marker),
        queryTarget=target,
    )
    return Construct(device=state.devices[location], query=query).queries()[0]


# --- built-in plugin selection ------------------------------------------------


def test_builtin_validators_select_every_variant_and_nothing_else():
    """A built-in input plugin with no selector is never run by the plugin manager."""
    builtin_ids = {directive.id for directive in init_builtin_directives()}
    community = set(ValidateBGPCommunity().directives)
    aspath = set(ValidateBGPASPath().directives)

    assert community == {i for i in builtin_ids if "_bgp_community" in i}
    assert aspath == {i for i in builtin_ids if "_bgp_aspath" in i}
    assert community and aspath
    assert not community & aspath
    # Plain, table, VRF and VRF table variants are all covered.
    for suffix in ("__", "_table__", "_vrf__", "_vrf_table__"):
        assert f"__hyperglass_arista_eos_bgp_community{suffix}" in community
        assert f"__hyperglass_arista_eos_bgp_aspath{suffix}" in aspath


@pytest.mark.parametrize("location", list(PLATFORMS))
def test_builtin_validators_are_registered_for_each_platform(state, location):
    for marker, plugin in (
        ("_bgp_community", "ValidateBGPCommunity"),
        ("_bgp_aspath", "ValidateBGPASPath"),
    ):
        query = Query(
            queryLocation=location,
            queryType=directive_id(state, location, marker),
            queryTarget="65000:100" if "community" in marker else "^65000$",
        )
        gathered = [p.name for p in InputPluginManager()._gather_plugins(query)]
        assert plugin in gathered


# --- BGP community --------------------------------------------------------------


@pytest.mark.parametrize("location", list(PLATFORMS))
@pytest.mark.parametrize(
    "target",
    [
        "65000:1 vrf all",
        "65000:1 detail",
        "not-a-community",
        "no-export",
        "65000:1 65000:2",
        "65000: 1",
        "+65000:1",
        "6_5000:1",
    ],
)
def test_community_directive_rejects_anything_but_a_community(state, location, target):
    with pytest.raises(InputInvalid):
        command(state, location, "_bgp_community", target)


@pytest.mark.parametrize("location", list(PLATFORMS))
@pytest.mark.parametrize("target", ["65000:100", "65000:1:2", "target:65000:1", "4200000000"])
def test_community_directive_accepts_communities(state, location, target):
    assert target in command(state, location, "_bgp_community", target)


@pytest.mark.parametrize("value", ["1", "65535", "0"])
def test_check_decimal_accepts_plain_digits(value):
    assert check_decimal(value, 0xFFFF) is True


@pytest.mark.parametrize("value", ["-1", "+1", " 1", "1 ", "1_0", "١", "65536", "", "1.0", None, 1])
def test_check_decimal_rejects_everything_else(value):
    assert check_decimal(value, 0xFFFF) is False


# --- BGP AS path ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "^65000$",
        "_65000_",
        "^65000 65001$",
        ".* 65000 .*",
        "^(65000_)+$",
        "_6500[0-9]$",
        "^$",
        "65000",
    ],
)
def test_as_path_expressions_are_accepted(value):
    assert validate_as_path(value) is True


@pytest.mark.parametrize(
    "value",
    ["65000 vrf all", "65000 detail", "^65000$ vrf MGMT", "internal", "65000,65001", "65000=1", ""],
)
def test_as_path_rejects_words_and_other_syntax(value):
    assert validate_as_path(value) is False


@pytest.mark.parametrize("location", list(PLATFORMS))
@pytest.mark.parametrize("target", ["65000 vrf all detail", "^65000$ vrf MGMT", "65000 json"])
def test_aspath_directive_rejects_trailing_keywords(state, location, target):
    with pytest.raises(InputInvalid):
        command(state, location, "_bgp_aspath", target)


@pytest.mark.parametrize("location", list(PLATFORMS))
@pytest.mark.parametrize("target", ["^65000$", "_65000_", "^65000 65001$"])
def test_aspath_directive_accepts_expressions(state, location, target):
    assert target in command(state, location, "_bgp_aspath", target)


# --- select fields ----------------------------------------------------------------


def test_select_field_only_accepts_its_options(state):
    assert command(state, "eos", "pick", "a") == "show thing a"
    assert command(state, "eos", "pick", "b c") == "show thing b c"
    for target in ("zzz", "a extra words", "A", "b"):
        with pytest.raises(InputInvalid):
            command(state, "eos", "pick", target)


def test_select_field_checks_every_value_of_a_multiple_target(state):
    assert command(state, "eos", "pick_many", ["a", "b"]) == "show thing a b"
    with pytest.raises(InputInvalid):
        command(state, "eos", "pick_many", ["a", "vrf all"])


def test_text_field_is_not_restricted_to_options(state):
    assert command(state, "eos", "free", "anything goes") == "show thing anything goes"


# --- list targets -----------------------------------------------------------------


def test_list_target_length_is_bounded(state):
    values = [str(65000 + i) for i in range(MAX_QUERY_TARGETS)]
    assert command(state, "eos", "asns", values) == "show as " + " ".join(values)
    with pytest.raises(ValidationError):
        command(state, "eos", "asns", [*values, "65999"])


def test_single_value_directive_rejects_a_list_of_several(state):
    assert command(state, "eos", "asn", ["65000"]) == "show as 65000"
    with pytest.raises(InputInvalid):
        command(state, "eos", "asn", ["65000", "65001"])


# --- characters ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "character",
    [
        "\u0085",  # NEL (C1 control)
        " ",  # line separator
        " ",  # paragraph separator
        " ",  # no-break space
        "　",  # ideographic space
        "​",  # zero-width space
        "‮",  # right-to-left override
        "﻿",  # byte order mark
    ],
)
def test_non_ascii_control_format_and_separator_characters_are_forbidden(state, character):
    assert target_contains_forbidden_content(f"a{character}b") is True
    with pytest.raises(InputInvalid):
        command(state, "eos", "free", f"a{character}b")


@pytest.mark.parametrize("value", ["plain ascii", "65000:100", "^65000$", "café", "例"])
def test_printable_text_is_still_allowed(value):
    assert target_contains_forbidden_content(value) is False


def test_help_key_is_rejected_on_interactive_clis_only(state):
    for location in ("eos", "ios", "xr", "junos", "huawei", "tik", "sros"):
        with pytest.raises(InputInvalid):
            command(state, location, "free", "x ?")
    # A shell-backed platform receives the target as one quoted word.
    assert command(state, "frr", "free", "x ?") == "show thing 'x ?'"
