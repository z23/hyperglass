"""Configuration for API rate limiting."""

# Standard Library
import typing as t

# Third Party
from pydantic import Field

# Local
from ..main import HyperglassModel

# Sliding-window units supported by Litestar's RateLimitConfig.
RateLimitUnit = t.Literal["second", "minute", "hour", "day"]


class RateLimit(HyperglassModel):
    """Validation model for `params.rate_limit`.

    Caps how many queries a single client (identified by `X-Forwarded-For`,
    falling back to `X-Real-IP`, then the peer address) may submit within a
    sliding time window. Each query opens an SSH session to a production router,
    so limiting protects the router control plane from being exhausted by a
    single actor. This is server-side-only configuration and is intentionally
    not exported to the UI or `/api/info`.
    """

    enable: bool = Field(
        True,
        title="Enable",
        description="Enable or disable per-client query rate limiting.",
    )
    limit: int = Field(
        10,
        ge=1,
        title="Limit",
        description="Maximum number of queries a client may submit within the configured unit window.",
    )
    unit: RateLimitUnit = Field(
        "minute",
        title="Unit",
        description="Sliding-window duration over which `limit` is enforced.",
    )
    exclude: t.List[str] = Field(
        [],
        title="Exclude",
        description="URL path patterns exempt from rate limiting.",
    )
