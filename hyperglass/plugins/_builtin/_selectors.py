"""Select the built-in directives a built-in plugin applies to."""

# Standard Library
import typing as t
from functools import lru_cache


@lru_cache(maxsize=None)
def builtin_directive_ids(marker: str) -> t.Tuple[str, ...]:
    """Get the IDs of every built-in directive whose ID contains `marker`.

    Built-in directive IDs follow `__hyperglass_<platform>_<query>[_vrf][_table]__`,
    so a marker such as `_bgp_community` selects that query on every platform
    and in every variant, including ones added later. Resolved lazily (when a
    plugin instance is created at startup) because the directive definitions
    import the models that in turn import the plugin package.
    """
    # Project
    from hyperglass.defaults.directives import init_builtin_directives

    return tuple(
        sorted(directive.id for directive in init_builtin_directives() if marker in directive.id)
    )
