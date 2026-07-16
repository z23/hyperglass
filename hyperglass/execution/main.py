"""Execute validated & constructed query on device.

Accepts input from front end application, validates the input and
returns errors if input is invalid. Passes validated parameters to
construct.py, which is used to build & run the Netmiko connections or
http client API calls, returns the output back to the front end.
"""

# Standard Library
from typing import TYPE_CHECKING, Dict, Union

# Third Party
import anyio

# Project
from hyperglass.log import log
from hyperglass.state import use_state
from hyperglass.util.typing import is_series
from hyperglass.exceptions.public import DeviceTimeout, ResponseEmpty

if TYPE_CHECKING:
    from hyperglass.models.api import Query
    from .drivers import Connection
    from hyperglass.models.data import OutputDataModel

# Local
from .drivers import HttpClient, NetmikoConnection


def map_driver(driver_name: str) -> "Connection":
    """Get the correct driver class based on the driver name."""

    if driver_name == "hyperglass_http_client":
        return HttpClient

    return NetmikoConnection


async def execute(query: "Query") -> Union["OutputDataModel", str]:
    """Initiate query validation and execution."""
    params = use_state("params")
    output = params.messages.general
    _log = log.bind(query=query.summary(), device=query.device.id)
    _log.debug("")

    mapped_driver = map_driver(query.device.driver)
    driver: "Connection" = mapped_driver(query.device, query)

    # Bound the whole device interaction with an async-native timeout. The
    # blocking Netmiko driver runs in a worker thread (see NetmikoConnection),
    # so a per-request timeout is safe here. This replaces a process-global
    # signal.alarm() timer, which was unsound under a concurrent async server:
    # only one alarm can be pending per process, so overlapping requests would
    # overwrite each other's timers and the handler could fire inside an
    # unrelated coroutine.
    try:
        with anyio.fail_after(params.request_timeout - 1):
            if query.device.proxy:
                proxy = driver.setup_proxy()
                with proxy() as tunnel:
                    response = await driver.collect(tunnel.local_bind_host, tunnel.local_bind_port)
            else:
                response = await driver.collect()
    except TimeoutError as timeout_error:
        raise DeviceTimeout(
            error=TimeoutError("Connection timed out"), device=query.device
        ) from timeout_error

    output = await driver.response(response)

    if is_series(output):
        if len(output) == 0:
            raise ResponseEmpty(query=query)
        output = "\n\n".join(output)

    elif isinstance(output, str):
        # If the output is a string (not structured) and is empty,
        # produce an error.
        if output == "" or output == "\n":
            raise ResponseEmpty(query=query)

    elif isinstance(output, Dict):
        # If the output an empty dict, responses have data, produce an
        # error.
        if not output:
            raise ResponseEmpty(query=query)

    return output
