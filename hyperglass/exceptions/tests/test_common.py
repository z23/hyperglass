"""Tests for exception message formatting."""

# Local
from .._common import HyperglassError

SAFE_FORMAT = HyperglassError._safe_format


def test_safe_format_formats_matching_keys():
    result = SAFE_FORMAT("Error connecting to {device}: {error}", device="r1", error="down")
    assert result == "Error connecting to r1: down"


def test_safe_format_keeps_unmatched_placeholders():
    """A template key with no matching keyword must not raise a KeyError."""
    result = SAFE_FORMAT("Error connecting to {device_name}: {error}", error="down")
    assert result == "Error connecting to {device_name}: down"


def test_safe_format_returns_malformed_template_unchanged():
    """Raw output containing braces must never raise inside error handling."""
    template = "raw output {inet.0: 5 destinations"
    assert SAFE_FORMAT(template, error="x") == template


def test_safe_format_tolerates_attribute_access_placeholders():
    """Templates using attribute/index access must not raise."""
    template = "Error: {error.args}"
    assert SAFE_FORMAT(template, error="x") == template
    template = "Error: {error[0]}"
    assert SAFE_FORMAT(template, error="x") == "Error: x"


def test_safe_format_stringifies_values():
    assert SAFE_FORMAT("{count} failures", count=3) == "3 failures"
