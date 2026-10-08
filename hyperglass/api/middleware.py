"""hyperglass API middleware."""

# Standard Library
import json
import typing as t

# Third Party
from litestar.exceptions import HTTPException
from litestar.config.cors import CORSConfig
from litestar.status_codes import HTTP_413_REQUEST_ENTITY_TOO_LARGE
from litestar.config.compression import CompressionConfig

if t.TYPE_CHECKING:
    # Third Party
    from litestar.types import Send, Scope, ASGIApp, Message, Receive

    # Project
    from hyperglass.state import HyperglassState

__all__ = (
    "create_cors_config",
    "COMPRESSION_CONFIG",
    "MAX_REQUEST_BODY_BYTES",
    "MaxRequestBodySizeMiddleware",
)

COMPRESSION_CONFIG = CompressionConfig(backend="brotli", brotli_gzip_fallback=True)

REQUEST_LOG_MESSAGE = "REQ"
RESPONSE_LOG_MESSAGE = "RES"
REQUEST_LOG_FIELDS = ("method", "path", "path_params", "query")
RESPONSE_LOG_FIELDS = ("status_code",)


def create_cors_config(state: "HyperglassState") -> CORSConfig:
    """Create CORS configuration from parameters."""
    origins = state.params.cors_origins.copy()
    if state.settings.dev_mode:
        origins = [*origins, state.settings.dev_url, "http://localhost:3000"]

    return CORSConfig(
        allow_origins=origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )


# Litestar < 2.13 reads request bodies into memory with no size limit
# (PYSEC-2024-178). Query payloads are well under 1 KiB, so anything beyond a
# few KiB is never legitimate. Enforced in-app so it does not depend on the
# reverse proxy being configured correctly.
MAX_REQUEST_BODY_BYTES = 16 * 1024


class MaxRequestBodySizeMiddleware:
    """Reject HTTP request bodies larger than ``max_bytes`` with 413.

    Two checks, because a client can omit or lie about ``Content-Length``:

    1. If ``Content-Length`` is present and exceeds the limit, respond 413
       immediately without passing the request to the application.
    2. Otherwise wrap ``receive`` and count body bytes as they arrive. If the
       running total exceeds the limit, raise ``HTTPException(413)`` from the
       read; Litestar's exception handling turns that into the normal JSON
       error response.
    """

    def __init__(self, app: "ASGIApp", max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        """Initialize middleware."""
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: "Scope", receive: "Receive", send: "Send") -> None:
        """Enforce the body size limit for HTTP requests."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _send_too_large(send, self.max_bytes)
            return

        received = 0

        async def limited_receive() -> "Message":
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(
                        status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=_too_large_detail(self.max_bytes),
                    )
            return message

        await self.app(scope, limited_receive, send)


def _content_length(scope: "Scope") -> t.Optional[int]:
    for name, value in scope.get("headers", ()):
        if name.lower() == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _too_large_detail(max_bytes: int) -> str:
    return f"Request body exceeds {max_bytes} bytes."


async def _send_too_large(send: "Send", max_bytes: int) -> None:
    body = json.dumps(
        {"output": _too_large_detail(max_bytes), "level": "danger", "keywords": []}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})
