"""Tests for the in-process plugin registry.

Pins the guarantee that plugins are held per-process in the manager's class
registry rather than in Redis (which would require serializing non-serializable
plugin objects). These tests do not require a running Redis instance.
"""

# Standard Library
import typing as t

# Third Party
import pytest

# Local
from .._input import InputPlugin
from .._manager import InputPluginManager


class AlphaPlugin(InputPlugin):
    """Stub input plugin used only for registry testing."""

    def validate(self, query: t.Any) -> t.Optional[bool]:
        """No-op validation."""
        return None


class BetaPlugin(InputPlugin):
    """Second stub input plugin used only for registry testing."""

    def validate(self, query: t.Any) -> t.Optional[bool]:
        """No-op validation."""
        return None


def _names(manager: InputPluginManager) -> t.List[str]:
    return [type(p).__name__ for p in manager.plugins()]


@pytest.fixture(autouse=True)
def _reset_registry():
    """Ensure each test starts from an empty input registry."""
    InputPluginManager._REGISTRY["input"] = []
    yield
    InputPluginManager._REGISTRY["input"] = []


def test_register_and_list():
    manager = InputPluginManager()
    manager.register(AlphaPlugin)
    manager.register(BetaPlugin)
    assert set(_names(manager)) == {"AlphaPlugin", "BetaPlugin"}


def test_register_is_idempotent():
    """Re-registering the same plugin class does not create duplicates."""
    manager = InputPluginManager()
    manager.register(AlphaPlugin)
    manager.register(AlphaPlugin)
    assert len(manager.plugins()) == 1


def test_unregister():
    manager = InputPluginManager()
    manager.register(AlphaPlugin)
    manager.register(BetaPlugin)
    manager.unregister(AlphaPlugin)
    assert _names(manager) == ["BetaPlugin"]


def test_reset_clears_all():
    manager = InputPluginManager()
    manager.register(AlphaPlugin)
    manager.register(BetaPlugin)
    manager.reset()
    assert manager.plugins() == []


def test_registry_does_not_touch_state():
    """The registry must not route through the Redis-backed state store.

    `_state` was removed from PluginManager entirely; confirm the attribute
    is absent so no code path can accidentally re-introduce a Redis round trip.
    """
    manager = InputPluginManager()
    assert not hasattr(manager, "_state")
