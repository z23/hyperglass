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

# Project
from hyperglass.exceptions.private import InputValidationError

# Local
from ..directive import Directive, RuleWithPattern


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
