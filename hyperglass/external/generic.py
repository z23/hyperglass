"""Session handler for Generic HTTP API endpoint."""

# Standard Library
import typing as t

# Project
from hyperglass.log import log
from hyperglass.models.webhook import Webhook

# Local
from ._base import BaseExternal

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.config.logging import Http


class GenericHook(BaseExternal, name="Generic"):
    """Slack session handler."""

    def __init__(self: "GenericHook", config: "Http") -> None:
        """Initialize external base class with http connection details."""

        base_url = f"{config.host.scheme}://{config.host.host}"
        if config.host.port is not None:
            # Without this a webhook on a non-default port is sent to 80/443.
            base_url += f":{config.host.port!s}"
        super().__init__(base_url=base_url, config=config)

    async def send(self: "GenericHook", query: t.Dict[str, t.Any]):
        """Send an incoming webhook to http endpoint."""

        payload = Webhook(**query)
        log.bind(host=self.config.host.host, payload=payload).debug("Sending request")

        return await self._apost(
            endpoint=self.config.host.path,
            headers=self.config.headers,
            params=self.config.params,
            data=payload.export_dict(),
        )
