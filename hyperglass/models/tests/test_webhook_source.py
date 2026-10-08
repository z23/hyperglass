"""The webhook source address must not be chosen by the client."""

# Standard Library
import sys
import importlib
from types import ModuleType, SimpleNamespace
from pathlib import Path
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

# Third Party
import pytest


@pytest.fixture
def api_tasks(monkeypatch):
    """Import `hyperglass.api.tasks` without running the package's app bootstrap."""
    package_name = "_hyperglass_webhook_test_api"
    package = ModuleType(package_name)
    package.__path__ = [str(Path(__file__).resolve().parents[2] / "api")]
    monkeypatch.setitem(sys.modules, package_name, package)
    try:
        yield importlib.import_module(f"{package_name}.tasks")
    finally:
        for name in list(sys.modules):
            if name.startswith(f"{package_name}."):
                del sys.modules[name]


def _request(client_host, headers):
    return SimpleNamespace(
        client=SimpleNamespace(host=client_host, port=12345) if client_host else None,
        headers=headers,
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"x-real-ip": "198.51.100.9"},
        {"x-forwarded-for": "198.51.100.9"},
        {"x-real-ip": "198.51.100.9", "x-forwarded-for": "198.51.100.9, 203.0.113.1"},
    ],
)
def test_client_host_ignores_forwarding_headers(api_tasks, headers):
    """Spoofed X-Real-IP / X-Forwarded-For must not override the ASGI client."""
    assert api_tasks.client_host(_request("192.0.2.10", headers)) == "192.0.2.10"


def test_client_host_without_client(api_tasks):
    assert api_tasks.client_host(_request(None, {})) == "Unknown"


@pytest.mark.asyncio
async def test_send_webhook_reports_asgi_client_as_source(api_tasks, monkeypatch):
    """End to end: the webhook `source` and bgp.tools lookup use the ASGI client."""
    sent = {}

    class FakeHook:
        def __init__(self, _config):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def send(self, *, query):
            sent.update(query)

    network_info = AsyncMock(return_value={"192.0.2.10": {"asn": "64496"}})
    monkeypatch.setattr(api_tasks, "Webhook", FakeHook)
    monkeypatch.setattr(api_tasks.bgptools, "network_info", network_info)

    params = SimpleNamespace(logging=SimpleNamespace(http=SimpleNamespace(provider="generic")))
    data = MagicMock()
    data.dict.return_value = {
        "query_location": "r1",
        "query_type": "bgp_route",
        "query_target": "1.1.1.1",
    }
    request = _request(
        "192.0.2.10",
        {"x-real-ip": "198.51.100.9", "x-forwarded-for": "198.51.100.9", "user-agent": "t"},
    )

    await api_tasks.send_webhook(params, data, request, datetime.now(UTC))

    network_info.assert_awaited_once_with("192.0.2.10")
    assert sent["source"] == "192.0.2.10"
    assert sent["network"] == {"asn": "64496"}
    # Headers are still reported for information.
    assert sent["headers"]["x-real-ip"] == "198.51.100.9"
