"""Primary state container."""

# Standard Library
import typing as t

# Local
from .manager import StateManager

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.ui import UIParameters
    from hyperglass.models.directive import Directive, Directives
    from hyperglass.models.config.params import Params
    from hyperglass.models.config.devices import Devices

    # Local
    from .manager import RedisManager


class HyperglassState(StateManager):
    """Primary hyperglass state container."""

    def add_directive(self, *directives: t.Union["Directive", t.Dict[str, t.Any]]) -> None:
        """Add a directive."""
        current = self.directives
        current.add(*directives, unique_by="id")
        self.redis.set("directives", current)

    def clear(self) -> None:
        """Delete all cache keys."""
        self.redis.instance.flushdb(asynchronous=True)

    @property
    def cache(self) -> "RedisManager":
        """Get the redis manager instance."""
        return self.redis

    @property
    def params(self) -> "Params":
        """Get hyperglass configuration parameters (`hyperglass.yaml`)."""
        from hyperglass.models.config.params import Params

        raw = self.redis.get("params", raise_if_none=True)
        return raw if isinstance(raw, Params) else Params.model_validate(raw)

    @property
    def devices(self) -> "Devices":
        """Get hyperglass devices (`devices.yaml`)."""
        from hyperglass.models.config.devices import Devices

        raw = self.redis.get("devices", raise_if_none=True)
        if isinstance(raw, Devices):
            return raw
        # MultiModel stores its items as a list; reconstruct from the root list.
        items = raw.root if hasattr(raw, "root") else raw
        return Devices(*items)

    @property
    def ui_params(self) -> "UIParameters":
        """UI parameters, built from params."""
        from hyperglass.models.ui import UIParameters

        raw = self.redis.get("ui_params", raise_if_none=True)
        return raw if isinstance(raw, UIParameters) else UIParameters.model_validate(raw)

    @property
    def directives(self) -> "Directives":
        """All directives."""
        from hyperglass.models.directive import Directives

        raw = self.redis.get("directives", raise_if_none=True)
        if isinstance(raw, Directives):
            return raw
        items = raw.root if hasattr(raw, "root") else raw
        return Directives(*items)
