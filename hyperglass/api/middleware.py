"""hyperglass API middleware."""

# Standard Library
import typing as t

# Third Party
from litestar.config.cors import CORSConfig
from litestar.config.compression import CompressionConfig
from litestar.middleware import DefineMiddleware
from litestar.middleware.rate_limit import RateLimitConfig

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState

__all__ = (
    "create_cors_config",
    "create_rate_limit_middleware",
    "COMPRESSION_CONFIG",
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
        # Restrict to the headers the UI actually sends rather than a wildcard,
        # so enabling CORS for a specific origin grants the minimum necessary.
        allow_headers=["Content-Type", "Accept"],
    )


def create_rate_limit_middleware(state: "HyperglassState") -> t.List[DefineMiddleware]:
    """Build rate-limit middleware from configured parameters.

    Returns an empty list when rate limiting is disabled or the limit is
    non-positive, so the middleware is simply not attached. Client identity
    follows Litestar's default resolution: `X-Forwarded-For` -> `X-Real-IP` ->
    the peer address, which is correct behind the recommended reverse proxy.
    """
    config = state.params.rate_limit
    if not config.enable or config.limit < 1:
        return []

    rate_limit = RateLimitConfig(
        rate_limit=(config.unit, config.limit),
        exclude=config.exclude or None,
        set_rate_limit_headers=True,
    )
    return [rate_limit.middleware]
