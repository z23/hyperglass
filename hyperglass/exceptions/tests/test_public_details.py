"""Errors returned to API clients must not describe the infrastructure behind them."""

# Standard Library
import sys
import typing as t
import importlib
from types import ModuleType, SimpleNamespace
from pathlib import Path

# Third Party
import httpx
import pytest
from netmiko.exceptions import (  # type: ignore
    ReadTimeout,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)

# Project
from hyperglass.state import use_state
from hyperglass.state.hooks import _use_state
from hyperglass.exceptions.private import ConfigError, ParsingError
from hyperglass.models.config.params import Params

# Local
from ..public import (
    AuthError,
    RestError,
    ScrapeError,
    InputInvalid,
    DeviceTimeout,
    _public_error_detail,
)

DEVICE = SimpleNamespace(name="Core Router", proxy=None)

# What the libraries actually put in their exceptions.
NETMIKO_CONNECT = NetmikoTimeoutException(
    "TCP connection to device failed.\n\nCommon causes of this problem are:\n"
    "1. Incorrect hostname or IP address.\n2. Wrong TCP port.\n"
    "3. Intermediate firewall blocking access.\n\n"
    "Device settings: arista_eos 10.20.30.40:22\n\n"
)
NETMIKO_AUTH = NetmikoAuthenticationException(
    "Authentication to device failed.\n\nCommon causes of this problem are:\n"
    "1. Invalid username and password\n2. Incorrect SSH-key file\n"
    "3. Connecting to the wrong device\n\n"
    "Device settings: arista_eos 10.20.30.40:22\n\nAuthentication failed."
)
NETMIKO_READ = ReadTimeout(
    "\nPattern not detected: 'core1\\\\.per\\\\.example\\\\.net\\\\#' in output.\n\n"
    "Things you might try to fix this:\n1. Explicitly set your pattern"
)
HTTP_REQUEST = httpx.Request("GET", "https://10.20.30.50:8443/internal/lg?token=secret")
HTTP_STATUS = httpx.HTTPStatusError(
    "Server error '500 Internal Server Error' for url "
    "'https://10.20.30.50:8443/internal/lg?token=secret'",
    request=HTTP_REQUEST,
    response=httpx.Response(500, request=HTTP_REQUEST),
)
HTTP_TIMEOUT = httpx.ConnectTimeout("timed out connecting to 10.20.30.50", request=HTTP_REQUEST)
OS_ERROR = OSError(113, "No route to host", "/etc/hyperglass/keys/core1.key")

PRIVATE_DETAILS = (
    "10.20.30.40",
    "10.20.30.50",
    ":22",
    "8443",
    "arista_eos",
    "core1",
    "example",
    "token",
    "secret",
    "/etc/hyperglass",
    "Common causes",
    "Device settings",
)


@pytest.fixture
def state() -> t.Generator[None, None, None]:
    """Public errors read their message templates from state."""
    _use_state.cache_clear()
    _state = use_state()
    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", Params())
    _use_state.cache_clear()
    yield
    _state.clear()
    _use_state.cache_clear()


def _published(exc: Exception) -> str:
    """Everything the API error handler sends to the client for an error."""
    return " ".join([exc.message, *(str(k) for k in exc.keywords)])


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (NETMIKO_CONNECT, "Connection to the device failed or timed out"),
        (NETMIKO_AUTH, "Authentication failed"),
        (NETMIKO_READ, "Timed out waiting for the device to respond"),
        (HTTP_TIMEOUT, "Connection timed out"),
        (HTTP_STATUS, "Device returned HTTP status 500"),
        (TimeoutError("Connection timed out"), "Connection timed out"),
        (OS_ERROR, "Connection failed"),
        (RuntimeError("anything at 10.20.30.40"), "Connection failed"),
        (
            "Error via SSH proxy: Authentication failed",
            "Error via SSH proxy: Authentication failed",
        ),
    ],
)
def test_public_error_detail_is_a_fixed_description(error, expected):
    assert _public_error_detail(error) == expected


@pytest.mark.parametrize("exception", [ScrapeError, AuthError, RestError, DeviceTimeout])
@pytest.mark.parametrize(
    "error", [NETMIKO_CONNECT, NETMIKO_AUTH, NETMIKO_READ, HTTP_STATUS, HTTP_TIMEOUT, OS_ERROR]
)
def test_device_errors_do_not_publish_library_error_text(state, exception, error):
    published = _published(exception(error=error, device=DEVICE))
    for detail in PRIVATE_DETAILS:
        assert detail not in published
    # The device's display name is public: it is what the client selected.
    assert "Core Router" in published or exception in (AuthError, DeviceTimeout)


def test_detail_is_rendered_once(state):
    """`connection_error` places `{error}` itself; it must not also be appended."""
    exc = ScrapeError(error=NETMIKO_CONNECT, device=DEVICE)
    assert exc.message == (
        "Error connecting to Core Router: Connection to the device failed or timed out"
    )
    # A template without `{error}` still gets the detail appended.
    timeout = DeviceTimeout(error=NETMIKO_READ, device=DEVICE)
    assert timeout.message == "Request timed out. (Timed out waiting for the device to respond)"


def test_full_detail_is_logged_server_side(state, monkeypatch):
    records: t.List[t.Tuple[t.Dict[str, t.Any], str]] = []

    class Recorder:
        def __init__(self, bound=None):
            self.bound = bound or {}

        def bind(self, **kwargs):
            return Recorder({**self.bound, **kwargs})

        def error(self, message, *_, **__):
            records.append((self.bound, message))

        critical = info = warning = debug = error

    monkeypatch.setattr("hyperglass.exceptions.public.log", Recorder())
    ScrapeError(error=NETMIKO_CONNECT, device=DEVICE)
    bound, message = records[0]
    assert message == "Device error"
    assert bound["device"] == "Core Router"
    assert bound["error_type"] == "NetmikoTimeoutException"
    assert "10.20.30.40:22" in bound["detail"]


# --- API error handler -----------------------------------------------------------


@pytest.fixture
def error_handlers(monkeypatch):
    """Import `hyperglass.api.error_handlers` without running the app bootstrap."""
    package_name = "_hyperglass_error_handler_test_api"
    package = ModuleType(package_name)
    package.__path__ = [str(Path(__file__).resolve().parents[2] / "api")]
    monkeypatch.setitem(sys.modules, package_name, package)
    try:
        yield importlib.import_module(f"{package_name}.error_handlers")
    finally:
        for name in list(sys.modules):
            if name.startswith(f"{package_name}."):
                del sys.modules[name]


REQUEST = SimpleNamespace(method="POST", url=SimpleNamespace(path="/api/query"))


@pytest.mark.parametrize(
    "exc_factory",
    [
        lambda: ConfigError(
            "Command '{c}' has attribute '{k}', which is missing from device '{d}'",
            c="BGP Route",
            k="vrf",
            d="core1.per.example.net",
        ),
        lambda: ParsingError("Error from device: {error}", error="syntax error at 10.20.30.40"),
    ],
)
def test_internal_errors_are_not_published(state, error_handlers, exc_factory):
    response = error_handlers.app_handler(REQUEST, exc_factory())
    assert response.status_code == 500
    assert response.content == {
        "output": Params().messages.general,
        "level": "danger",
        "keywords": [],
    }


def test_public_errors_are_still_published(state, error_handlers):
    exc = InputInvalid(error="Target contains disallowed character(s)", target="1.1.1.1;x")
    response = error_handlers.app_handler(REQUEST, exc)
    assert response.status_code == 400
    assert response.content["output"] == exc.message
    assert response.content["level"] == "warning"
    assert "1.1.1.1;x" in response.content["keywords"]
