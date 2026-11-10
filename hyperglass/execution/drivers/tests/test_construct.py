# Standard Library
import shlex
import typing as t
from types import SimpleNamespace

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.constants import quote_shell_command
from hyperglass.models.api import Query
from hyperglass.configuration import init_ui_params
from hyperglass.models.directive import Directives
from hyperglass.exceptions.public import InputInvalid
from hyperglass.exceptions.private import ConfigError
from hyperglass.models.config.params import Params
from hyperglass.models.config.devices import Devices

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


_ATTRS = {"source4": "192.0.2.1", "source6": "2001:db8::1"}


def _format(state, platform: str, command: str, target: str) -> str:
    """Build one command with `platform` after a valid query has been constructed."""
    query = Query(
        queryLocation="test1",
        queryTarget="192.0.2.0/24",
        queryType="juniper_bgp_route",
    )
    constructor = Construct(device=state.devices["test1"], query=query)
    constructor.device = SimpleNamespace(platform=platform, name=platform, attrs=_ATTRS)
    constructor.target = target
    return constructor.format(command)


@pytest.mark.parametrize(
    ("platform", "command", "target", "expected"),
    [
        (
            "frr",
            'vtysh -c "show bgp ipv4 unicast regexp {target}"',
            "^65000$",
            "vtysh -c 'show bgp ipv4 unicast regexp ^65000$'",
        ),
        (
            "frr",
            'vtysh -c "show bgp ipv4 unicast regexp {target}"',
            "65000$HOME",
            "vtysh -c 'show bgp ipv4 unicast regexp 65000$HOME'",
        ),
        (
            "frr",
            'vtysh -c "show bgp ipv4 unicast {target}"',
            "192.0.2.0/24",
            "vtysh -c 'show bgp ipv4 unicast 192.0.2.0/24'",
        ),
        (
            "frr",
            "ping -4 -c 5 -I {source4} {target}",
            "192.0.2.1",
            "ping -4 -c 5 -I 192.0.2.1 192.0.2.1",
        ),
        (
            "bird",
            'birdc "show route all where bgp_path ~ {target}"',
            "[= * 65000 * =]",
            "birdc 'show route all where bgp_path ~ [= * 65000 * =]'",
        ),
        (
            "bird",
            'birdc "show route all where {target} ~ bgp_community"',
            "(65000,100)",
            "birdc 'show route all where (65000,100) ~ bgp_community'",
        ),
        (
            "bird",
            "ping -6 -c 5 -I {source6} {target}",
            "2001:db8::1",
            "ping -6 -c 5 -I 2001:db8::1 2001:db8::1",
        ),
        (
            "openbgpd",
            "bgpctl show rib inet as {target}",
            "65000 .* 65001",
            "bgpctl show rib inet as '65000 .* 65001'",
        ),
        (
            "openbgpd",
            "bgpctl show rib inet {target}",
            "192.0.2.0/24",
            "bgpctl show rib inet 192.0.2.0/24",
        ),
        (
            "tnsr",
            'dataplane shell sudo vtysh -c "show bgp ipv4 unicast regexp {target}"',
            "^65000$",
            "dataplane shell sudo vtysh -c 'show bgp ipv4 unicast regexp ^65000$'",
        ),
        (
            "arista_eos",
            "show ip bgp {target}",
            "192.0.2.0/24",
            "show ip bgp 192.0.2.0/24",
        ),
        (
            "arista_eos",
            "show ip bgp regexp {target}",
            "^65000$",
            "show ip bgp regexp ^65000$",
        ),
        (
            "arista_eos",
            "show ip bgp community {target}",
            "65000:100",
            "show ip bgp community 65000:100",
        ),
        (
            "arista_eos",
            "show ip bgp {target} | json",
            "192.0.2.0/24",
            "show ip bgp 192.0.2.0/24 | json",
        ),
        (
            "arista_eos",
            "ping ipv6 {target} source {source6}",
            "2001:db8::1",
            "ping ipv6 2001:db8::1 source 2001:db8::1",
        ),
        (
            "arista_eos",
            "ping ipv6 {target} source {source6}",
            "2001:0db8:0000::0001",
            "ping ipv6 2001:db8::1 source 2001:db8::1",
        ),
        (
            "arista_eos",
            "show ip bgp regexp {target}",
            "65000$HOME",
            "show ip bgp regexp 65000$HOME",
        ),
        (
            "cisco_ios",
            'show bgp ipv4 unicast quote-regexp "{target}"',
            "^65000$",
            'show bgp ipv4 unicast quote-regexp "^65000$"',
        ),
        (
            "cisco_ios",
            "show bgp ipv4 unicast community {target}",
            "65000:100",
            "show bgp ipv4 unicast community 65000:100",
        ),
        (
            "cisco_ios",
            "ping {target} repeat 5 source {source4}",
            "192.0.2.1",
            "ping 192.0.2.1 repeat 5 source 192.0.2.1",
        ),
        (
            "juniper",
            'show route protocol bgp table inet.0 aspath-regex "{target}"',
            "65000 .* 65001",
            'show route protocol bgp table inet.0 aspath-regex "65000 .* 65001"',
        ),
        (
            "huawei",
            "display bgp routing-table {target} | no-more",
            "192.0.2.0 24",
            "display bgp routing-table 192.0.2.0 24 | no-more",
        ),
    ],
)
def test_valid_targets_render_for_shell_and_cli_platforms(
    state, platform, command, target, expected
):
    """Valid prefixes, addresses, AS paths, and communities keep working.

    Shell platforms quote the target word. EOS, IOS, Juniper, and Huawei keep
    the existing CLI text, including pipes and Huawei's spaced prefix.
    """
    rendered = _format(state, platform, command, target)
    assert rendered == expected
    if platform in {"frr", "bird", "openbgpd", "tnsr"}:
        assert shlex.split(rendered) == shlex.split(
            quote_shell_command(command, target=target, **_ATTRS)
        )


@pytest.mark.parametrize(
    ("platform", "command", "target"),
    [
        (
            "frr",
            'vtysh -c "show bgp ipv4 unicast regexp {target}"',
            '_65000"; $(id); echo "',
        ),
        (
            "bird",
            "ping -6 -c 5 -I {source6} {target}",
            "fe80::1%;id",
        ),
        (
            "cisco_ios",
            "show bgp ipv4 unicast community {target}",
            "1.1.1.1\nclear ip bgp *",
        ),
        (
            "arista_eos",
            "ping ipv6 {target} source {source6}",
            "2001:db8::1%x foo",
        ),
        (
            "bird",
            "ping -6 -c 5 -I {source6} {target}",
            "2001:db8::1%x foo",
        ),
        (
            "openbgpd",
            "bgpctl show rib inet6 {target}",
            "2001:db8::1%x foo",
        ),
    ],
)
def test_construct_rejects_command_injection_payloads(state, platform, command, target):
    """#383 payloads and a zoned IPv6 address never become a device command."""
    with pytest.raises(InputInvalid):
        _format(state, platform, command, target)


def test_query_gate_rejects_payloads_before_construct(state):
    """The query model rejects the shell and newline payloads before formatting."""
    payloads = [
        '_65000"; $(id); echo "',
        "fe80::1%;id",
        "1.1.1.1\nclear ip bgp *",
    ]
    for target in payloads:
        with pytest.raises(InputInvalid):
            Query(
                queryLocation="test1",
                queryTarget=target,
                queryType="juniper_bgp_route",
            )


def test_permissive_directive_still_rejects_zoned_ipv6_at_format(state):
    """A rule without validation cannot carry a zoned address into the command."""
    query = Query(
        queryLocation="test1",
        queryTarget="2001:db8::1%x foo",
        queryType="juniper_bgp_route",
    )
    constructor = Construct(device=state.devices["test1"], query=query)
    constructor.device = SimpleNamespace(platform="arista_eos", name="eos", attrs=_ATTRS)
    with pytest.raises(InputInvalid):
        constructor.format("ping ipv6 {target} source {source6}")


def test_shell_quoting_holds_when_character_denylist_is_bypassed(state, monkeypatch):
    """Quoting still keeps a breakout payload in one argument if the denylist misses it."""
    monkeypatch.setattr(
        "hyperglass.execution.drivers._construct.target_contains_forbidden_content",
        lambda _value: False,
    )
    payload = '_65000"; $(id); echo "'
    rendered = _format(
        state,
        "frr",
        'vtysh -c "show bgp ipv4 unicast regexp {target}"',
        payload,
    )
    assert shlex.split(rendered) == [
        "vtysh",
        "-c",
        f"show bgp ipv4 unicast regexp {payload}",
    ]


def test_zone_id_is_rejected_even_when_character_denylist_is_bypassed(state, monkeypatch):
    """The IPv6 zone check does not depend on `;` being in the character denylist."""
    monkeypatch.setattr(
        "hyperglass.execution.drivers._construct.target_contains_forbidden_content",
        lambda _value: False,
    )
    with pytest.raises(InputInvalid):
        _format(
            state,
            "bird",
            "ping -6 -c 5 -I {source6} {target}",
            "fe80::1%;id",
        )
    with pytest.raises(InputInvalid):
        _format(
            state,
            "arista_eos",
            "ping ipv6 {target} source {source6}",
            "2001:db8::1%x foo",
        )


def test_linux_escape_remains_when_shell_quoting_is_not_used(state, monkeypatch):
    """The `$(…)` backslash escape still applies to a double-quoted Linux command."""
    monkeypatch.setattr("hyperglass.execution.drivers._construct.SHELL_PLATFORMS", ())
    rendered = _format(
        state,
        "frr",
        'vtysh -c "show bgp ipv4 unicast regexp {target}"',
        "^65000$",
    )
    assert rendered == 'vtysh -c "show bgp ipv4 unicast regexp ^65000\\$"'


def test_broken_shell_template_is_rejected(state):
    """An unparsable shell template is not filled with str.format."""
    with pytest.raises(ConfigError):
        _format(state, "frr", 'vtysh -c "unterminated {target}', "192.0.2.1")
