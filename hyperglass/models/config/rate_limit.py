"""Validation model for API rate-limit config."""

# Standard Library
import typing as t

# Third Party
from pydantic import Field

# Local
from ..main import HyperglassModel

if t.TYPE_CHECKING:
    # Third Party
    from litestar.middleware.rate_limit import RateLimitConfig

RateLimitPeriod = t.Literal["second", "minute", "hour", "day"]

# Rate limiting is scoped to the unauthenticated query endpoint. This pattern
# matches every path EXCEPT `/api/query`; Litestar excludes matching paths from
# rate limiting, so only `/api/query` is throttled (the UI, static assets, and
# read-only info endpoints are never limited).
RATE_LIMIT_EXCLUDE = [r"^(?!/api/query$).*"]


class RateLimit(HyperglassModel):
    """Per-client rate limiting for the query API.

    The looking glass query endpoint is unauthenticated and each request opens a
    live connection to a network device, so it is rate limited by default to
    protect the backend and the devices from request floods.
    """

    enable: bool = Field(
        True,
        title="Enable Rate Limiting",
        description="Enable per-client rate limiting on the /api/query endpoint.",
    )
    period: RateLimitPeriod = Field(
        "minute",
        title="Rate Limit Period",
        description="Time window over which the request limit is applied.",
    )
    limit: int = Field(
        60,
        gt=0,
        title="Rate Limit",
        description="Maximum number of query requests allowed per client, per period.",
    )

    def to_litestar_config(self) -> t.Optional["RateLimitConfig"]:
        """Build a Litestar rate-limit config, or `None` when disabled.

        When disabled, no rate-limit middleware should be registered.
        """
        if not self.enable:
            return None

        # Third Party
        from litestar.middleware.rate_limit import RateLimitConfig

        return RateLimitConfig(
            rate_limit=(self.period, self.limit),
            exclude=RATE_LIMIT_EXCLUDE,
        )
