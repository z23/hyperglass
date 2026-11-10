"""Validate a BGP AS path regular expression."""

# Standard Library
import re
import typing as t

# Third Party
from pydantic import Field, PrivateAttr

# Project
from hyperglass.state.hooks import use_state

# Local
from .._input import InputPlugin
from ._selectors import builtin_directive_ids

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.api.query import Query

    # Local
    from .._input import InputPluginValidationReturn

# Everything an AS path expression needs: AS numbers, anchors, wildcards,
# quantifiers, groups, character classes and separators. Letters are excluded
# on purpose. Most platforms interpolate the target into the command without
# quoting, so a word such as `vrf`, `detail` or `all` after the expression is
# parsed by the device as a further command keyword, not as part of the
# expression.
AS_PATH_PATTERN = re.compile(r"[0-9_^$.*+()\[\] -]+")


def validate_as_path(value: str) -> bool:
    """Verify a value contains only AS path expression characters."""
    return AS_PATH_PATTERN.fullmatch(value) is not None


class ValidateBGPASPath(InputPlugin):
    """Validate a BGP AS path expression on the built-in AS path directives."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    directives: t.Sequence[str] = Field(
        default_factory=lambda: builtin_directive_ids("_bgp_aspath")
    )

    def validate(self, query: "Query") -> "InputPluginValidationReturn":
        """Ensure an input query target is an AS path expression and nothing more."""
        targets = query.query_target
        if isinstance(targets, str):
            targets = [targets]

        if all(isinstance(target, str) and validate_as_path(target) for target in targets):
            return True

        self.failure_reason = use_state("params").messages.invalid_input
        return False
