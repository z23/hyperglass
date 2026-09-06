"""Policy enforcement at the shared plugin-manager boundary."""

# Standard Library
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import Mock

# Third Party
import pytest

# Project
from hyperglass.plugins._input import InputPlugin
from hyperglass.plugins._output import OutputPlugin
from hyperglass.plugins._manager import InputPluginManager, OutputPluginManager
from hyperglass.exceptions.private import InputValidationError
from hyperglass.models.data.bgp_route import BGPRouteTable
from hyperglass.plugins._builtin.bgp_route_arista import BGPRoutePluginArista


@pytest.fixture
def query():
    return SimpleNamespace(
        query_target="8.8.8.8",
        directive=SimpleNamespace(id="route", plugins=[]),
        device=SimpleNamespace(platform="arista_eos"),
    )


def manager_with_plugins(manager_class, monkeypatch, plugins):
    """Use real selection and execution with an isolated plugin registry."""
    manager = object.__new__(manager_class)
    monkeypatch.setattr(manager, "plugins", lambda **kwargs: plugins)
    return manager


@pytest.mark.parametrize("results", [(True, False), (False, True), (None, True, False)])
def test_any_deny_rejects_regardless_of_earlier_success(monkeypatch, query, results):
    plugins = [
        Mock(name=f"policy-{n}", directives=["route"], ref=None, common=False)
        for n in range(len(results))
    ]
    for plugin, result in zip(plugins, results):
        plugin.validate.return_value = result
    manager = manager_with_plugins(InputPluginManager, monkeypatch, plugins)
    with pytest.raises(InputValidationError):
        manager.validate(query)
    plugins[results.index(False)].validate.assert_called_once_with(query)


@pytest.mark.parametrize(
    "results, expected",
    [([], None), ([None], None), ([True, None], True), ([None, True], True), ([True, True], True)],
)
def test_valid_and_neutral_input_plugins_are_preserved(monkeypatch, query, results, expected):
    plugins = [Mock(directives=["route"], ref=None, common=False) for _ in results]
    for plugin, result in zip(plugins, results):
        plugin.validate.return_value = result
    manager = manager_with_plugins(InputPluginManager, monkeypatch, plugins)
    assert manager.validate(query) is expected
    for plugin in plugins:
        plugin.validate.assert_called_once_with(query)


def test_default_input_plugin_remains_neutral(monkeypatch, query):
    manager = manager_with_plugins(
        InputPluginManager, monkeypatch, [InputPlugin(directives=["route"])]
    )
    assert manager.validate(query) is None


def test_plugin_matching_multiple_selectors_is_only_validated_once(monkeypatch, query):
    plugin = Mock(directives=["route"], ref="policy", common=True)
    plugin.validate.return_value = True
    query.directive.plugins = ["policy"]
    manager = manager_with_plugins(InputPluginManager, monkeypatch, [plugin])
    assert manager.validate(query) is True
    plugin.validate.assert_called_once_with(query)


class Redact(OutputPlugin):
    """Platform-independent custom plugin, as documented."""

    def process(self, *, output, query):
        """Redact a placeholder from raw output."""
        return tuple(line.replace("secret", "[redacted]") for line in output)


@pytest.mark.parametrize(
    "platforms, expected",
    [([], "[redacted]"), (["arista_eos"], "[redacted]"), (["juniper"], "secret")],
)
def test_directive_output_plugins_respect_optional_platform_filter(
    monkeypatch, query, platforms, expected
):
    plugin = Redact(directives=["route"], platforms=platforms)
    manager = manager_with_plugins(OutputPluginManager, monkeypatch, [plugin])
    assert manager.execute(output=("secret",), query=query) == (expected,)


def test_unrelated_directive_is_not_processed(monkeypatch, query):
    plugin = Redact(directives=["different-route"])
    manager = manager_with_plugins(OutputPluginManager, monkeypatch, [plugin])
    assert manager.execute(output=("secret",), query=query) == ("secret",)


def test_common_output_plugin_still_runs(monkeypatch, query):
    manager = manager_with_plugins(OutputPluginManager, monkeypatch, [Redact(common=True)])
    assert manager.execute(output=("secret",), query=query) == ("[redacted]",)


@pytest.mark.parametrize("platforms", [[], ["arista_eos"]])
def test_dual_selector_output_plugin_runs_once_after_directive_plugins(
    monkeypatch, query, platforms
):
    common = Mock(common=True, directives=["route"], platforms=platforms)
    common.process.side_effect = lambda *, output, query: (output[0] + "!",)
    manager = manager_with_plugins(
        OutputPluginManager, monkeypatch, [common, Redact(directives=["route"])]
    )
    assert manager.execute(output=("secret",), query=query) == ("[redacted]!",)
    common.process.assert_called_once_with(output=("[redacted]",), query=query)


@pytest.mark.parametrize("directive_id", BGPRoutePluginArista().directives)
def test_arista_structured_parser_still_runs_for_plain_and_vrf_directives(
    monkeypatch, query, directive_id
):
    """Exercise the actual manager and parser without external RPKI requests."""
    params = SimpleNamespace(
        structured=SimpleNamespace(
            communities=SimpleNamespace(mode="deny", items=[]), rpki=SimpleNamespace(mode="router")
        )
    )
    monkeypatch.setattr("hyperglass.models.data.bgp_route.use_state", lambda key: params)
    query.directive.id = directive_id
    query.device.structured_output = True
    query.device.has_directives = lambda *args: True
    manager = manager_with_plugins(OutputPluginManager, monkeypatch, [BGPRoutePluginArista()])
    sample = Path(__file__).resolve().parents[3] / ".samples" / "arista_route.json"
    result = manager.execute(output=(sample.read_text(),), query=query)
    assert isinstance(result, BGPRouteTable)
    assert result.count > 0
    assert result.routes
