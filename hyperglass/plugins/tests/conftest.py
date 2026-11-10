"""Shared fixtures for plugin tests."""

# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.state.hooks import _use_state
from hyperglass.models.directive import Directives
from hyperglass.models.config.params import Params


@pytest.fixture(autouse=True)
def plugin_state() -> t.Generator[None, None, None]:
    """Provide the state plugin tests need, independent of test order.

    Constructing a device (MockDevice) reads directives from global state, and
    structured-output processing reads params. Previously these were satisfied
    only by whichever state an earlier test module happened to leave in the
    process-wide `use_state` cache.
    """
    _use_state.cache_clear()
    _state = use_state()
    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", Params())
        pipeline.set("directives", Directives.new())
    yield
    _state.clear()
    _use_state.cache_clear()
