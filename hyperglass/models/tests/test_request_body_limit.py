"""Oversized request bodies must be rejected before they are buffered."""

# Standard Library
import sys
import importlib
from types import ModuleType
from pathlib import Path

# Third Party
import pytest
from litestar import Litestar, post
from litestar.testing import TestClient
from litestar.middleware import DefineMiddleware


@pytest.fixture
def api_middleware(monkeypatch):
    """Import `hyperglass.api.middleware` without running the package's app bootstrap."""
    package_name = "_hyperglass_body_limit_test_api"
    package = ModuleType(package_name)
    package.__path__ = [str(Path(__file__).resolve().parents[2] / "api")]
    monkeypatch.setitem(sys.modules, package_name, package)
    try:
        yield importlib.import_module(f"{package_name}.middleware")
    finally:
        for name in list(sys.modules):
            if name.startswith(f"{package_name}."):
                del sys.modules[name]


@pytest.fixture
def client(api_middleware):
    @post("/echo")
    async def echo(data: dict) -> dict:
        return {"size": len(str(data))}

    app = Litestar(
        route_handlers=[echo],
        middleware=[DefineMiddleware(api_middleware.MaxRequestBodySizeMiddleware, max_bytes=64)],
    )
    with TestClient(app) as test_client:
        yield test_client


def test_default_limit_is_small_but_fits_a_query(api_middleware):
    assert 4 * 1024 <= api_middleware.MAX_REQUEST_BODY_BYTES <= 64 * 1024


def test_small_body_passes(client):
    response = client.post("/echo", json={"queryTarget": "1.1.1.1"})
    assert response.status_code == 201
    assert response.json()["size"] > 0


def test_declared_oversize_body_is_rejected_before_the_handler(client):
    response = client.post("/echo", content=b'{"x": "' + b"a" * 200 + b'"}')
    assert response.status_code == 413
    body = response.json()
    assert body["level"] == "danger"
    assert "exceeds 64 bytes" in body["output"]


@pytest.mark.asyncio
async def test_streamed_oversize_body_is_cut_off(api_middleware):
    """A body with no Content-Length is counted as it arrives and rejected."""
    from litestar.exceptions import HTTPException

    chunks = [b"a" * 40, b"b" * 40, b"c" * 40]
    seen = []

    async def receive():
        body = chunks.pop(0) if chunks else b""
        return {"type": "http.request", "body": body, "more_body": bool(chunks)}

    async def app(scope, receive, send):
        # Mimic a handler draining the body.
        while True:
            message = await receive()
            seen.append(len(message["body"]))
            if not message.get("more_body"):
                break

    middleware = api_middleware.MaxRequestBodySizeMiddleware(app, max_bytes=64)
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    with pytest.raises(HTTPException) as excinfo:
        await middleware(scope, receive, lambda message: None)
    assert excinfo.value.status_code == 413
    # First chunk (40 bytes) was accepted, the second pushed the total over 64.
    assert seen == [40]


@pytest.mark.asyncio
async def test_non_http_scopes_pass_through(api_middleware):
    called = []

    async def app(scope, receive, send):
        called.append(scope["type"])

    middleware = api_middleware.MaxRequestBodySizeMiddleware(app, max_bytes=1)
    await middleware({"type": "lifespan"}, None, None)
    assert called == ["lifespan"]
