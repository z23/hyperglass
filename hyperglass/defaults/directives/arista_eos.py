"""Default Arista Directives."""

# Project
from hyperglass.models.directive import (
    Text,
    RuleWithIPv4,
    RuleWithIPv6,
    RuleWithPattern,
    BuiltinDirective,
)

__all__ = (
    "AristaBGPRoute",
    "AristaBGPASPath",
    "AristaBGPCommunity",
    "AristaPing",
    "AristaTraceroute",
    "AristaBGPRouteTable",
    "AristaBGPASPathTable",
    "AristaBGPCommunityTable",
    "AristaBGPRouteVRF",
    "AristaBGPASPathVRF",
    "AristaBGPCommunityVRF",
    "AristaPingVRF",
    "AristaTracerouteVRF",
    "AristaBGPRouteVRFTable",
    "AristaBGPASPathVRFTable",
    "AristaBGPCommunityVRFTable",
)

NAME = "Arista EOS"
PLATFORMS = ["arista_eos"]

AristaBGPRoute = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_route__",
    name="BGP Route",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="show ip bgp {target}",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="show ipv6 bgp {target}",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    table_output="__hyperglass_arista_eos_bgp_route_table__",
    platforms=PLATFORMS,
)

AristaBGPASPath = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_aspath__",
    name="BGP AS Path",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp regexp {target}",
                "show ipv6 bgp regexp {target}",
            ],
        )
    ],
    field=Text(description="AS Path Regular Expression"),
    table_output="__hyperglass_arista_eos_bgp_aspath_table__",
    platforms=PLATFORMS,
)

AristaBGPCommunity = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_community__",
    name="BGP Community",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp community {target}",
                "show ipv6 bgp community {target}",
            ],
        )
    ],
    field=Text(description="BGP Community String"),
    table_output="__hyperglass_arista_eos_bgp_community_table__",
    platforms=PLATFORMS,
)


AristaPing = BuiltinDirective(
    id="__hyperglass_arista_eos_ping__",
    name="Ping",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="ping ip {target} source {source4}",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="ping ipv6 {target} source {source6}",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    platforms=PLATFORMS,
)

AristaTraceroute = BuiltinDirective(
    id="__hyperglass_arista_eos_traceroute__",
    name="Traceroute",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="traceroute ip {target} source {source4}",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="traceroute ipv6 {target} source {source6}",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    platforms=PLATFORMS,
)

# Table Output Directives

AristaBGPRouteTable = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_route_table__",
    name="BGP Route",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="show ip bgp {target} | json",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="show ipv6 bgp {target} | json",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    platforms=PLATFORMS,
)

AristaBGPASPathTable = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_aspath_table__",
    name="BGP AS Path",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp regexp {target} | json",
                "show ipv6 bgp regexp {target} | json",
            ],
        )
    ],
    field=Text(description="AS Path Regular Expression"),
    platforms=PLATFORMS,
)

AristaBGPCommunityTable = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_community_table__",
    name="BGP Community",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp community {target} | json",
                "show ipv6 bgp community {target} | json",
            ],
        )
    ],
    field=Text(description="BGP Community String"),
    platforms=PLATFORMS,
)

# VRF-aware variants. These load only on devices that define `attrs.vrf`
# (see Directives.device_builtins).

AristaBGPRouteVRF = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_route_vrf__",
    name="BGP Route (VRF)",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="show ip bgp vrf {vrf} {target}",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="show ipv6 bgp vrf {vrf} {target}",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    table_output="__hyperglass_arista_eos_bgp_route_vrf_table__",
    platforms=PLATFORMS,
)

AristaBGPASPathVRF = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_aspath_vrf__",
    name="BGP AS Path (VRF)",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp vrf {vrf} regexp {target}",
                "show ipv6 bgp vrf {vrf} regexp {target}",
            ],
        )
    ],
    field=Text(description="AS Path Regular Expression"),
    table_output="__hyperglass_arista_eos_bgp_aspath_vrf_table__",
    platforms=PLATFORMS,
)

AristaBGPCommunityVRF = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_community_vrf__",
    name="BGP Community (VRF)",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp vrf {vrf} community {target}",
                "show ipv6 bgp vrf {vrf} community {target}",
            ],
        )
    ],
    field=Text(description="BGP Community String"),
    table_output="__hyperglass_arista_eos_bgp_community_vrf_table__",
    platforms=PLATFORMS,
)

AristaPingVRF = BuiltinDirective(
    id="__hyperglass_arista_eos_ping_vrf__",
    name="Ping (VRF)",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="ping vrf {vrf} ip {target} source {source4}",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="ping vrf {vrf} ipv6 {target} source {source6}",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    platforms=PLATFORMS,
)

AristaTracerouteVRF = BuiltinDirective(
    id="__hyperglass_arista_eos_traceroute_vrf__",
    name="Traceroute (VRF)",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="traceroute vrf {vrf} ip {target} source {source4}",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="traceroute vrf {vrf} ipv6 {target} source {source6}",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    platforms=PLATFORMS,
)

AristaBGPRouteVRFTable = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_route_vrf_table__",
    name="BGP Route (VRF)",
    rules=[
        RuleWithIPv4(
            condition="0.0.0.0/0",
            action="permit",
            command="show ip bgp vrf {vrf} {target} | json",
        ),
        RuleWithIPv6(
            condition="::/0",
            action="permit",
            command="show ipv6 bgp vrf {vrf} {target} | json",
        ),
    ],
    field=Text(description="IP Address, Prefix, or Hostname"),
    platforms=PLATFORMS,
)

AristaBGPASPathVRFTable = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_aspath_vrf_table__",
    name="BGP AS Path (VRF)",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp vrf {vrf} regexp {target} | json",
                "show ipv6 bgp vrf {vrf} regexp {target} | json",
            ],
        )
    ],
    field=Text(description="AS Path Regular Expression"),
    platforms=PLATFORMS,
)

AristaBGPCommunityVRFTable = BuiltinDirective(
    id="__hyperglass_arista_eos_bgp_community_vrf_table__",
    name="BGP Community (VRF)",
    rules=[
        RuleWithPattern(
            condition="*",
            action="permit",
            commands=[
                "show ip bgp vrf {vrf} community {target} | json",
                "show ipv6 bgp vrf {vrf} community {target} | json",
            ],
        )
    ],
    field=Text(description="BGP Community String"),
    platforms=PLATFORMS,
)
