"""Regression tests for input-validation hardening.

These tests pin the security guarantees of the input pipeline:

1. CLI/shell metacharacters and control characters are rejected before any
   target reaches `command.format(target=...)`.
2. The wildcard `condition: "*"` accepts only characters that legitimately
   appear in BGP AS-path regex syntax or community values.
3. `RuleWithPattern` uses `fullmatch` semantics, so a custom regex without
   end-of-string anchoring still cannot allow trailing payload.
4. `Directive.multiple_separator` is restricted to a small allow-list.
"""

# Standard Library
import pytest

# Third Party
from pydantic import TypeAdapter, ValidationError

# Project
from hyperglass.exceptions.private import InputValidationError
from hyperglass.models.api.query import Query, _check_query_target

# Local
from ..directive import Directive, RuleWithPattern, RuleWithIPv4


@pytest.mark.parametrize(
    "target",
    [
        "1.1.1.1; reboot",
        "1.1.1.1 | section bgp",
        "1.1.1.1 && uname",
        "1.1.1.1\nshow running-config",
        "1.1.1.1\rshow running-config",
        "foo`id`",
        'foo" | section line "bar',
        "foo\\bar",
        "1.1.1.1 > /tmp/x",
        "1.1.1.1 < /tmp/x",
        # Shell command/parameter substitution on linux_ssh (issue #4).
        "$(reboot)",
        "65000$(id)",
        "${PATH}",
        "65000${IFS}id",
    ],
)
def test_wildcard_pattern_rejects_metachars(target):
    """`condition: "*"` must not let CLI metacharacters through."""
    rule = RuleWithPattern(condition="*", action="permit", commands=["show {target}"])
    assert rule.validate_target(target, multiple=False) is False


@pytest.mark.parametrize(
    "target",
    [
        "65000",
        "65000_65001",
        "_65000_",
        "^65000$",
        "65000 .* 65001",
        "(65000)(65001)",
        "65000:100",
        "no-export",
    ],
)
def test_wildcard_pattern_accepts_legitimate_targets(target):
    """`condition: "*"` must continue to accept normal AS-path / community values."""
    rule = RuleWithPattern(condition="*", action="permit", commands=["show {target}"])
    assert rule.validate_target(target, multiple=False) is True


def test_pattern_rule_uses_fullmatch():
    """A non-anchored custom regex must not allow trailing payload (fullmatch, not match)."""
    rule = RuleWithPattern(
        condition=r"[0-9]+",
        action="permit",
        commands=["show ip bgp regexp {target}"],
    )
    # `match` would accept this because it anchors only at the start; `fullmatch` rejects.
    assert rule.validate_target("12345abc", multiple=False) is False
    assert rule.validate_target("12345", multiple=False) is True


def test_multiple_separator_allowlist_rejects_pipe():
    """`multiple_separator: "|"` would be a CLI-injection vector if accepted."""
    with pytest.raises(ValueError):
        Directive(
            id="x",
            name="x",
            field=None,
            multiple=True,
            multiple_separator="|",
            rules=[{"condition": "*", "action": "permit", "command": "show {target}"}],
        )


def test_multiple_separator_allowlist_rejects_semicolon():
    with pytest.raises(ValueError):
        Directive(
            id="x",
            name="x",
            field=None,
            multiple=True,
            multiple_separator=";",
            rules=[{"condition": "*", "action": "permit", "command": "show {target}"}],
        )


def test_multiple_separator_allowlist_accepts_space_and_comma():
    for sep in (" ", ","):
        d = Directive(
            id="x",
            name="x",
            field=None,
            multiple=True,
            multiple_separator=sep,
            rules=[{"condition": "*", "action": "permit", "command": "show {target}"}],
        )
        assert d.multiple_separator == sep


def test_pattern_rule_rejects_embedded_newline_with_strict_regex():
    """An IP-shaped regex must not match a target with an embedded newline."""
    rule = RuleWithPattern(
        condition=r"\d+\.\d+\.\d+\.\d+",
        action="permit",
        commands=["ping {target}"],
    )
    assert rule.validate_target("1.1.1.1\nshow run", multiple=False) is False


# Layer 1 (type-level) tests: `_check_query_target` is the first gate the
# request hits, before any directive rule runs. These tests pin the guarantee
# directly so the type-level check can't silently regress even if the
# directive-rule layer (Layer 2) is permissive.


@pytest.mark.parametrize(
    "target",
    [
        "1.1.1.1;reboot",
        "1.1.1.1|cmd",
        "1.1.1.1&cmd",
        "1.1.1.1\nshow run",
        "1.1.1.1\rshow run",
        "1.1.1.1\tshow run",
        "1.1.1.1\x00",
        "foo`id`",
        'foo"bar',
        "foo<bar",
        "foo>bar",
        "foo\\bar",
        # Shell command/parameter substitution (issue #4 / linux_ssh RCE).
        "$(reboot)",
        "65000$(id)",
        "${PATH}",
        "65000${IFS}id",
    ],
)
def test_check_query_target_rejects_forbidden_chars(target):
    """The type-level forbidden-character check must reject every metachar."""
    with pytest.raises(InputValidationError):
        _check_query_target(target)


@pytest.mark.parametrize(
    "target",
    ["192.0.2.0/24", "65000:100", "_65000_", "^65000$", "(65000)(65001)", "65000 .* 65001"],
)
def test_check_query_target_accepts_normal_targets(target):
    """Normal looking-glass targets must pass the type-level check."""
    assert _check_query_target(target) == target


def test_query_validates_each_list_target_elementwise():
    """List targets must be checked element-wise at the type-level.

    Even when a directive's regex permits anything (`condition: "*"`), the
    type-level forbidden-character check must still reject a list whose any
    element contains a metacharacter.
    """
    # Simulate the loop in `Query.validate_query_target`: each element runs
    # through `_check_query_target` before the directive rule sees it.
    targets = ["1.1.1.1", "2.2.2.2;reboot"]
    with pytest.raises(InputValidationError):
        for item in targets:
            _check_query_target(item)


def test_check_query_target_rejects_even_when_rule_would_permit():
    """Layer-1 rejects metacharacters; Layer-2 also hard-blocks them.

    A rule with `condition='.*'` would match anything by regex alone, but both
    layers hard-block forbidden content so a custom permissive condition cannot
    re-open the injection path.
    """
    permissive_rule = RuleWithPattern(
        condition=r".*", action="permit", commands=["show {target}"]
    )
    target = "1.1.1.1;reboot"
    # Layer-2 now hard-blocks forbidden content even for custom regexes:
    assert permissive_rule.validate_target(target, multiple=False) is False
    # Layer-1 still rejects first in the request pipeline:
    with pytest.raises(InputValidationError):
        _check_query_target(target)


def test_shell_escape_linux_target_neutralizes_substitution():
    """Escaped targets keep AS-path anchors but neutralize `$(…)` for bash.

    After bash double-quote parsing, `\$` becomes a literal `$`, so vtysh still
    sees `^65000$` while `$(reboot)` cannot execute.
    """
    # Project
    from hyperglass.constants import shell_escape_linux_target

    assert shell_escape_linux_target("^65000$") == "^65000\\$"
    assert shell_escape_linux_target("$(reboot)") == "\\$(reboot)"
    assert shell_escape_linux_target('a"b') == 'a\\"b'
    assert shell_escape_linux_target("a\\b") == "a\\\\b"


# Empty-list query target: must be rejected, never a 500. Historically an empty
# list reached `target[0]` in `RuleWithIP` (uncaught IndexError -> HTTP 500) and
# was silently accepted by `RuleWithPattern` (empty generator -> `_passed=True`).


def test_query_target_field_rejects_empty_list():
    """`query_target=[]` must fail model validation (a 400), not reach a rule.

    Pins the `min_length=1` constraint on the real `Query.query_target` field
    so an empty list is rejected at the type boundary.
    """
    adapter = TypeAdapter(Query.model_fields["query_target"].annotation)
    with pytest.raises(ValidationError):
        adapter.validate_python([])
    # A single-value list and a bare string must still be accepted.
    assert adapter.validate_python(["1.1.1.1"]) == ["1.1.1.1"]
    assert adapter.validate_python("1.1.1.1") == "1.1.1.1"


def test_ip_rule_rejects_empty_list():
    """An empty list must raise InputValidationError, not IndexError."""
    rule = RuleWithIPv4(
        condition="0.0.0.0/0", ge=0, le=32, commands=["show ip bgp {target}"]
    )
    with pytest.raises(InputValidationError):
        rule.validate_target([], multiple=False)
    # A single-value list is still accepted.
    assert rule.validate_target(["1.1.1.1"], multiple=False) is True


def test_pattern_rule_rejects_empty_list():
    """An empty list must be rejected, not silently validated as passing."""
    rule = RuleWithPattern(condition="*", action="permit", commands=["show {target}"])
    with pytest.raises(InputValidationError):
        rule.validate_target([], multiple=False)
    assert rule._passed is not True
    # A populated list is still validated element-wise.
    assert rule.validate_target(["65000", "65001"], multiple=True) is True


def test_directive_resets_passed_state_across_targets():
    """A reused Directive must not carry `_passed` state between targets.

    Regression for the latent bug where validating an IPv6 target and then an
    IPv4 target against one Directive instance left both rules `_passed=True`,
    so `Construct.queries()` would build both the v4 and v6 command for the v4
    target.
    """
    directive = Directive(
        id="test",
        name="Test",
        field=None,
        rules=[
            {"condition": "0.0.0.0/0", "ge": 0, "le": 32, "command": "show ip bgp {target}"},
            {"condition": "::/0", "ge": 0, "le": 128, "command": "show ipv6 bgp {target}"},
        ],
    )

    directive.validate_target("2001:4860:4860::8888")
    directive.validate_target("1.1.1.1")
    passed = [rule._type for rule in directive.rules if rule._passed is True]
    assert passed == ["ipv4"], f"expected only the IPv4 rule to pass, got {passed}"

    # And the reverse order: a v6 target after a v4 target.
    directive.validate_target("2001:4860:4860::8888")
    passed = [rule._type for rule in directive.rules if rule._passed is True]
    assert passed == ["ipv6"], f"expected only the IPv6 rule to pass, got {passed}"
