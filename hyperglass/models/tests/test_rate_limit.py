"""Tests for the rate-limit configuration model.

The model-level guarantees (defaults, bounds, constraints, and that the config
does not leak to the UI/API) are unit tests that need no Redis. The middleware
factory (`create_rate_limit_middleware`) is integration-tested via the app
boot path, since importing `hyperglass.api` eagerly reads config from Redis.
"""

# Third Party
import pytest
from pydantic import ValidationError

# Project
from hyperglass.models.config.rate_limit import RateLimit


def test_defaults_are_secure():
    """Rate limiting is on by default with a strict 10/minute cap."""
    rl = RateLimit()
    assert rl.enable is True
    assert rl.limit == 10
    assert rl.unit == "minute"
    assert rl.exclude == []


def test_limit_must_be_positive():
    """A non-positive limit is rejected at validation time."""
    with pytest.raises(ValidationError):
        RateLimit(limit=0)
    with pytest.raises(ValidationError):
        RateLimit(limit=-5)


def test_unit_is_constrained():
    """Only the four supported sliding-window units are accepted."""
    with pytest.raises(ValidationError):
        RateLimit(unit="week")
    for unit in ("second", "minute", "hour", "day"):
        assert RateLimit(unit=unit).unit == unit


def test_custom_config_round_trips():
    """A fully-specified config preserves every field."""
    rl = RateLimit(enable=False, limit=60, unit="hour", exclude=["/api/docs"])
    assert rl.enable is False
    assert rl.limit == 60
    assert rl.unit == "hour"
    assert rl.exclude == ["/api/docs"]


def test_rate_limit_not_in_params_frontend_export():
    """Rate-limit config is server-side only and must not leak to the UI/API."""
    from hyperglass.models.config.params import Params

    exported = Params().frontend()
    assert "rate_limit" not in exported
