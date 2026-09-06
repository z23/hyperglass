"""Output cached before plugin enforcement must not survive the security upgrade."""

# Standard Library
import sys
import importlib
from types import ModuleType, SimpleNamespace
from pathlib import Path
from datetime import UTC, datetime
from unittest.mock import Mock, AsyncMock

# Third Party
import pytest
from litestar.exceptions import TooManyRequestsException

# Project
from hyperglass.plugins._output import OutputPlugin
from hyperglass.plugins._manager import OutputPluginManager


@pytest.fixture
def api_routes(monkeypatch):
    """Import actual routes without executing the application's Redis/UI bootstrap."""
    package_name = "_hyperglass_cache_test_api"
    package = ModuleType(package_name)
    package.__path__ = [str(Path(__file__).resolve().parents[2] / "api")]
    monkeypatch.setitem(sys.modules, package_name, package)
    try:
        yield importlib.import_module(f"{package_name}.routes")
    finally:
        for name in list(sys.modules):
            if name.startswith(f"{package_name}."):
                del sys.modules[name]


class Redact(OutputPlugin):
    """Custom redactor with the documented default platform selection."""

    def process(self, *, output, query):
        """Remove sensitive placeholder data."""
        return tuple(line.replace("secret", "[redacted]") for line in output)


@pytest.mark.asyncio
async def test_legacy_unredacted_cache_is_not_returned_or_renewed(api_routes, monkeypatch):
    old_key = "hyperglass.query.test-digest"
    now = datetime.now(UTC)
    entries = {old_key: {"output": "secret", "timestamp": now}}
    cache = SimpleNamespace(
        get_map=lambda key, item: entries.get(key, {}).get(item),
        set_map_item=lambda key, item, value: entries.setdefault(key, {}).update({item: value}),
        expire=Mock(),
    )
    state = SimpleNamespace(
        redis=cache, params=SimpleNamespace(cache=SimpleNamespace(timeout=60), fake_output=False)
    )
    data = SimpleNamespace(
        digest=lambda: "test-digest",
        summary=lambda: "test query",
        random=lambda: "nonce",
        timestamp=now,
        directive=SimpleNamespace(id="route"),
        device=SimpleNamespace(platform="arista_eos"),
    )
    manager = object.__new__(OutputPluginManager)
    monkeypatch.setattr(manager, "plugins", lambda: [Redact(directives=["route"])])

    async def execute(query):
        return "\n".join(manager.execute(output=("secret",), query=query))

    executor = AsyncMock(side_effect=execute)
    monkeypatch.setattr(api_routes, "execute", executor)
    first = await api_routes.query.fn(_state=state, request=None, data=data)
    assert first.content["output"] == "[redacted]"
    assert first.content["cached"] is False
    assert first.content["id"] != old_key
    assert entries[first.content["id"]]["output"] == "[redacted]"
    assert all(call.args[0] != old_key for call in cache.expire.call_args_list)

    second = await api_routes.query.fn(_state=state, request=None, data=data)
    assert second.content["output"] == "[redacted]"
    assert second.content["cached"] is True
    executor.assert_awaited_once_with(data)


def test_http_error_handler_preserves_rate_limit_headers(api_routes):
    handlers = importlib.import_module(f"{api_routes.__package__}.error_handlers")
    request = SimpleNamespace(method="POST", url=SimpleNamespace(path="/api/query"))
    response = handlers.http_handler(
        request,
        TooManyRequestsException(
            headers={"RateLimit-Limit": "10", "RateLimit-Remaining": "0", "RateLimit-Reset": "60"}
        ),
    )
    assert response.status_code == 429
    assert response.headers["RateLimit-Remaining"] == "0"
    assert response.headers["RateLimit-Reset"] == "60"
