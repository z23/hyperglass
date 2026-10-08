"""IP rules must honour allow_reserved / allow_unspecified / allow_loopback."""

# ruff: noqa: S104

# Third Party
import pytest

# Project
from hyperglass.exceptions.private import InputValidationError
from hyperglass.defaults.directives import init_builtin_directives

# Local
from ..directive import RuleWithIPv4, RuleWithIPv6


def _text(excinfo) -> str:
    """InputValidationError keeps its formatted text in `keywords`, not `str()`."""
    return " ".join(str(k) for k in excinfo.value.keywords)


V4_STRICT = RuleWithIPv4(condition="0.0.0.0/0", command="ping {target}")
V6_STRICT = RuleWithIPv6(condition="::/0", command="ping {target}")
V4_OPEN = RuleWithIPv4(
    condition="0.0.0.0/0",
    command="show ip bgp {target}",
    allow_reserved=True,
    allow_unspecified=True,
    allow_loopback=True,
)
V6_OPEN = RuleWithIPv6(
    condition="::/0",
    command="show ipv6 bgp {target}",
    allow_reserved=True,
    allow_unspecified=True,
    allow_loopback=True,
)


@pytest.mark.parametrize(
    ("rule", "target", "reason"),
    [
        (V4_STRICT, "10.0.0.1", "reserved"),
        (V4_STRICT, "10.0.0.0/8", "reserved"),
        (V4_STRICT, "172.16.5.4", "reserved"),
        (V4_STRICT, "192.168.1.1", "reserved"),
        (V4_STRICT, "100.64.0.1", "reserved"),  # CGNAT: not private, not global
        (V4_STRICT, "169.254.1.1", "reserved"),
        (V4_STRICT, "224.0.0.1", "reserved"),  # multicast: is_global is True in Python
        (V4_STRICT, "255.255.255.255", "reserved"),
        (V4_STRICT, "240.0.0.1", "reserved"),
        (V4_STRICT, "192.0.2.1", "reserved"),
        (V4_STRICT, "127.0.0.1", "loopback"),
        (V4_STRICT, "0.0.0.0", "unspecified"),
        (V4_STRICT, "0.0.0.0/0", "unspecified"),
        (V6_STRICT, "fc00::1", "reserved"),
        (V6_STRICT, "fe80::1", "reserved"),
        (V6_STRICT, "ff02::1", "reserved"),
        (V6_STRICT, "2001:db8::1", "reserved"),
        (V6_STRICT, "::1", "loopback"),
        (V6_STRICT, "::", "unspecified"),
        (V6_STRICT, "::/0", "unspecified"),
    ],
)
def test_strict_rule_rejects_non_global_targets(rule, target, reason):
    with pytest.raises(InputValidationError) as excinfo:
        rule.validate_target(target, multiple=False)
    assert reason in _text(excinfo)
    assert rule._passed is False


@pytest.mark.parametrize(
    ("rule", "target"),
    [
        (V4_STRICT, "1.1.1.1"),
        (V4_STRICT, "8.8.8.0/24"),
        (V4_STRICT, "121.200.42.16"),
        (V6_STRICT, "2001:4860:4860::8888"),
        (V6_STRICT, "2404:6800::/32"),
    ],
)
def test_strict_rule_accepts_global_targets(rule, target):
    assert rule.validate_target(target, multiple=False) is True


def test_prefix_spanning_reserved_space_is_rejected():
    """128.0.0.0/1 starts global but ends in 255.255.255.255."""
    with pytest.raises(InputValidationError):
        V4_STRICT.validate_target("128.0.0.0/1", multiple=False)


@pytest.mark.parametrize(
    ("rule", "target"),
    [
        (V4_OPEN, "10.0.0.0/8"),
        (V4_OPEN, "100.64.0.0/10"),
        (V4_OPEN, "224.0.0.1"),
        (V4_OPEN, "127.0.0.1"),
        (V4_OPEN, "0.0.0.0/0"),
        (V4_OPEN, "0.0.0.0"),
        (V6_OPEN, "fc00::/7"),
        (V6_OPEN, "::1"),
        (V6_OPEN, "::/0"),
    ],
)
def test_open_rule_accepts_everything(rule, target):
    assert rule.validate_target(target, multiple=False) is True


def test_flags_are_independent():
    loopback_only = RuleWithIPv4(condition="0.0.0.0/0", command="x {target}", allow_loopback=True)
    assert loopback_only.validate_target("127.0.0.1", multiple=False) is True
    with pytest.raises(InputValidationError):
        loopback_only.validate_target("10.0.0.1", multiple=False)
    with pytest.raises(InputValidationError):
        loopback_only.validate_target("0.0.0.0", multiple=False)


@pytest.mark.parametrize("rule", [V4_STRICT, V4_OPEN])
def test_scope_id_is_always_rejected(rule):
    rule6 = V6_STRICT if rule is V4_STRICT else V6_OPEN
    with pytest.raises(InputValidationError) as excinfo:
        rule6.validate_target("fe80::1%eth0", multiple=False)
    assert "scope" in _text(excinfo)


def test_non_member_is_not_rejected_by_flags():
    """A rule only polices targets inside its own condition."""
    rule = RuleWithIPv4(condition="192.0.2.0/24", command="x {target}")
    # 10.0.0.1 is reserved but not a member of 192.0.2.0/24: fall through to
    # the next rule rather than raising.
    assert rule.validate_target("10.0.0.1", multiple=False) is False


def test_deny_rule_message_takes_precedence():
    rule = RuleWithIPv4(condition="10.0.0.0/8", action="deny", command="x {target}")
    with pytest.raises(InputValidationError) as excinfo:
        rule.validate_target("10.1.2.3", multiple=False)
    assert "denied network" in _text(excinfo)


def test_builtin_bgp_route_is_open_and_ping_traceroute_are_strict():
    """Every vendor's builtins: route lookups permissive, probes strict."""
    seen_route = seen_probe = 0
    for directive in init_builtin_directives():
        ip_rules = [r for r in directive.rules if r._type in ("ipv4", "ipv6")]
        if "bgp_route" in directive.id:
            for rule in ip_rules:
                assert (rule.allow_reserved, rule.allow_unspecified, rule.allow_loopback) == (
                    True,
                    True,
                    True,
                ), directive.id
                seen_route += 1
        elif "ping" in directive.id or "traceroute" in directive.id:
            for rule in ip_rules:
                assert (rule.allow_reserved, rule.allow_unspecified, rule.allow_loopback) == (
                    False,
                    False,
                    False,
                ), directive.id
                seen_probe += 1
    assert seen_route >= 30
    assert seen_probe >= 30
