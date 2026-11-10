"""User-facing/Public exceptions."""

# Standard Library
from typing import TYPE_CHECKING, Any, Dict, Union, Optional

# Project
from hyperglass.log import log

# Local
from ._common import PublicHyperglassError

if TYPE_CHECKING:
    # Project
    from hyperglass.models.api.query import Query
    from hyperglass.models.config.devices import Device


def _device_error_kwargs(device: "Device") -> Dict[str, Any]:
    """Build user-safe device error keywords.

    Proxy details must never be exposed in a public error: the full `Proxy`
    model's string representation includes the credential username and key
    path, and even the proxy's address/port would disclose infrastructure to
    anonymous users. Proxy-hop failures are attributed in the error text
    ("Error via SSH proxy: ...") and detailed in server-side logs.
    `device_name` is included because it is the key used by the default (and
    documented) `connection_error` message template.
    """
    return {"device": device.name, "device_name": device.name}


# Exception class names, matched against the error's MRO so this module does
# not import the SSH and HTTP client libraries. Checked in order.
_PUBLIC_ERROR_DETAILS = (
    (("NetmikoAuthenticationException", "AuthenticationException"), "Authentication failed"),
    (("ReadTimeout", "ReadException"), "Timed out waiting for the device to respond"),
    (("NetmikoTimeoutException",), "Connection to the device failed or timed out"),
    (("TimeoutException", "TimeoutError"), "Connection timed out"),
)


def _public_error_detail(error: Union[BaseException, str]) -> str:
    """Describe a device failure without repeating the library's own error text.

    Public errors are returned to anonymous API clients, and the underlying
    libraries describe failures in terms of the thing that failed: Netmiko
    appends `Device settings: <device_type> <address>:<port>` to connection and
    authentication errors and puts the device prompt (its hostname) in read
    timeouts, and httpx includes the full request URL. None of that is the
    client's business, so only a fixed description is exposed.

    A string is passed through unchanged: the caller has already chosen wording
    that is safe to publish (for example the SSH proxy descriptions).
    """
    if isinstance(error, str):
        return error

    names = {cls.__name__ for cls in type(error).__mro__}

    for candidates, detail in _PUBLIC_ERROR_DETAILS:
        if names.intersection(candidates):
            return detail

    if "HTTPStatusError" in names:
        status_code = getattr(getattr(error, "response", None), "status_code", None)
        if isinstance(status_code, int):
            return f"Device returned HTTP status {status_code}"

    return "Connection failed"


def _device_error(error: Union[BaseException, str], device: "Device") -> str:
    """Log the full device error server-side and return its public description."""
    if not isinstance(error, str):
        log.bind(
            device=getattr(device, "name", None),
            error_type=type(error).__name__,
            detail=str(error),
        ).error("Device error")
    return _public_error_detail(error)


class ScrapeError(
    PublicHyperglassError,
    template="connection_error",
    level="danger",
):
    """Raised when an SSH driver error occurs."""

    def __init__(self, *, error: Union[BaseException, str], device: "Device"):
        """Initialize parent error."""
        super().__init__(error=_device_error(error, device), **_device_error_kwargs(device))


class AuthError(PublicHyperglassError, template="authentication_error", level="danger"):
    """Raised when authentication to a device fails."""

    def __init__(self, *, error: Union[BaseException, str], device: "Device"):
        """Initialize parent error."""
        super().__init__(error=_device_error(error, device), **_device_error_kwargs(device))


class RestError(PublicHyperglassError, template="connection_error", level="danger"):
    """Raised upon a rest API client error."""

    def __init__(self, *, error: Union[BaseException, str], device: "Device"):
        """Initialize parent error."""
        super().__init__(error=_device_error(error, device), **_device_error_kwargs(device))


class DeviceTimeout(PublicHyperglassError, template="request_timeout", level="danger"):
    """Raised when the connection to a device times out."""

    def __init__(self, *, error: Union[BaseException, str], device: "Device"):
        """Initialize parent error."""
        super().__init__(error=_device_error(error, device), **_device_error_kwargs(device))


class DeviceBusy(PublicHyperglassError, template="device_busy", level="warning"):
    """Raised when a device already has its maximum number of queries in flight."""

    def __init__(self, *, device: "Device", limit: int):
        """Initialize parent error."""
        super().__init__(device=device.name, limit=limit)

    @property
    def status_code(self) -> int:
        """Service Unavailable: the client should retry shortly."""
        return 503


class InvalidQuery(PublicHyperglassError, template="request_timeout"):
    """Raised when input validation fails."""

    def __init__(
        self, *, error: Optional[str] = None, query: "Query", **kwargs: Dict[str, Any]
    ) -> None:
        """Initialize parent error."""

        kwargs = {
            "query_type": query.query_type,
            "target": query.query_target,
            "error": str(error),
            **kwargs,
        }

        super().__init__(**kwargs)


class NotFound(PublicHyperglassError, template="not_found"):
    """Raised when an object is not found."""

    def __init__(self, type: str, name: str, **kwargs: Dict[str, str]) -> None:
        """Initialize parent error."""
        super().__init__(type=type, name=name, **kwargs)


class QueryLocationNotFound(NotFound):
    """Raised when a query location is not found."""

    def __init__(self, location: Any, **kwargs: Dict[str, Any]) -> None:
        """Initialize a NotFound error for a query location."""
        # Project
        from hyperglass.state import use_state

        (text := use_state("params").web.text)

        super().__init__(type=text.query_location, name=str(location), **kwargs)


class QueryTypeNotFound(NotFound):
    """Raised when a query type is not found."""

    def __init__(self, query_type: Any, **kwargs: Dict[str, Any]) -> None:
        """Initialize a NotFound error for a query type."""
        # Project
        from hyperglass.state import use_state

        (text := use_state("params").web.text)
        super().__init__(type=text.query_type, name=str(query_type), **kwargs)


class InputInvalid(PublicHyperglassError, template="invalid_input"):
    """Raised when input validation fails."""

    def __init__(
        self, *, error: Optional[Any] = None, target: str, **kwargs: Dict[str, Any]
    ) -> None:
        """Initialize parent error."""

        kwargs = {"target": target, "error": str(error), **kwargs}

        super().__init__(**kwargs)


class InputNotAllowed(PublicHyperglassError, template="target_not_allowed"):
    """Raised when input validation fails due to a configured check."""

    def __init__(
        self, *, error: Optional[str] = None, query: "Query", **kwargs: Dict[str, Any]
    ) -> None:
        """Initialize parent error."""

        kwargs = {
            "query_type": query.query_type,
            "target": query.query_target,
            "error": str(error),
            **kwargs,
        }

        super().__init__(**kwargs)


class ResponseEmpty(PublicHyperglassError, template="no_output"):
    """Raised when hyperglass can connect to the device but the response is empty."""

    def __init__(
        self, *, error: Optional[str] = None, query: "Query", **kwargs: Dict[str, Any]
    ) -> None:
        """Initialize parent error."""

        kwargs = {
            "query_type": query.query_type,
            "target": query.query_target,
            "error": str(error),
            **kwargs,
        }

        super().__init__(**kwargs)
