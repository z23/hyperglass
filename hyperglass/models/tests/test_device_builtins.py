"""Tests for Directives.device_builtins attr-aware filtering."""

# Project
from hyperglass.defaults.directives.arista_eos import (
    AristaPing,
    AristaBGPRoute,
    AristaPingVRF,
    AristaTraceroute,
    AristaBGPASPath,
    AristaBGPRouteVRF,
    AristaBGPCommunity,
    AristaBGPASPathVRF,
    AristaTracerouteVRF,
    AristaBGPCommunityVRF,
)

# Local
from ..directive import Directives

ARISTA_BUILTINS = Directives(
    AristaBGPRoute,
    AristaBGPASPath,
    AristaBGPCommunity,
    AristaPing,
    AristaTraceroute,
    AristaBGPRouteVRF,
    AristaBGPASPathVRF,
    AristaBGPCommunityVRF,
    AristaPingVRF,
    AristaTracerouteVRF,
)

NON_VRF_IDS = {
    "__hyperglass_arista_eos_bgp_route__",
    "__hyperglass_arista_eos_bgp_aspath__",
    "__hyperglass_arista_eos_bgp_community__",
    "__hyperglass_arista_eos_ping__",
    "__hyperglass_arista_eos_traceroute__",
}

VRF_IDS = {
    "__hyperglass_arista_eos_bgp_route_vrf__",
    "__hyperglass_arista_eos_bgp_aspath_vrf__",
    "__hyperglass_arista_eos_bgp_community_vrf__",
    "__hyperglass_arista_eos_ping_vrf__",
    "__hyperglass_arista_eos_traceroute_vrf__",
}


def test_device_builtins_without_vrf_attr_excludes_vrf_directives():
    """An Arista device without `attrs.vrf` should not get the VRF variants."""
    result = ARISTA_BUILTINS.device_builtins(
        platform="arista_eos",
        table_output=False,
        attrs={"source4": "192.0.2.1", "source6": "2001:db8::1"},
    )
    ids = {d.id for d in result}
    assert ids == NON_VRF_IDS


def test_device_builtins_with_vrf_attr_includes_vrf_directives():
    """An Arista device with `attrs.vrf` should get both plain and VRF variants."""
    result = ARISTA_BUILTINS.device_builtins(
        platform="arista_eos",
        table_output=False,
        attrs={"source4": "192.0.2.1", "source6": "2001:db8::1", "vrf": "public"},
    )
    ids = {d.id for d in result}
    assert ids == NON_VRF_IDS | VRF_IDS


def test_device_builtins_vrf_directive_renders_vrf_in_command():
    """The VRF built-in's command template should substitute `{vrf}`."""
    cmd = AristaBGPRouteVRF.rules[0].commands[0]
    assert cmd.format(vrf="public", target="192.0.2.0/24") == (
        "show ip bgp vrf public 192.0.2.0/24"
    )


def test_device_builtins_filters_by_platform():
    """Non-matching platform yields an empty result regardless of attrs."""
    result = ARISTA_BUILTINS.device_builtins(
        platform="juniper",
        table_output=False,
        attrs={"source4": "192.0.2.1", "source6": "2001:db8::1", "vrf": "public"},
    )
    assert list(result) == []
