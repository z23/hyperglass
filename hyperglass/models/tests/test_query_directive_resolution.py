"""Query must resolve its directive by exact id, not by substring match."""

# Standard Library
from types import SimpleNamespace

# Third Party
import pytest

# Project
from hyperglass.models.api import query as query_module

# Local
from ..directive import Directive, Directives


def _directive(directive_id: str, command: str) -> Directive:
    return Directive(
        id=directive_id,
        name=directive_id,
        field=None,
        rules=[{"condition": "0.0.0.0/0", "ge": 0, "le": 32, "command": command}],
    )


class _FakeDevices:
    def __init__(self, device):
        self._device = device

    def valid_id_or_name(self, value):
        return value == self._device.id

    def __iter__(self):
        return iter([self._device])

    def __getitem__(self, key):
        return self._device


class _FakeState:
    def __init__(self, devices):
        self.devices = devices

    def plugins(self, _type):
        return []


@pytest.fixture
def state(monkeypatch):
    # `bgp_route` is deliberately a prefix of `bgp_route_table` and is listed
    # *after* it so a substring match would pick the wrong directive.
    table = _directive("bgp_route_table", "show ip bgp {target} | json")
    plain = _directive("bgp_route", "show ip bgp {target}")
    directives = Directives(table, plain)
    device = SimpleNamespace(
        id="r1",
        name="r1",
        platform="arista_eos",
        directives=directives,
        has_directives=lambda *ids: any(d.id in ids for d in directives),
    )
    fake = _FakeState(_FakeDevices(device))

    def use_state(attr=None):
        if attr == "devices":
            return fake.devices
        return fake

    monkeypatch.setattr(query_module, "use_state", use_state)
    monkeypatch.setattr("hyperglass.plugins._manager.use_state", use_state)
    return device


def test_matching_is_a_substring_match():
    """Document the behaviour `Query` must not rely on."""
    directives = Directives(_directive("foo_table", "a {target}"), _directive("foo", "b {target}"))
    assert [d.id for d in directives.matching("foo")] == ["foo_table", "foo"]
    assert [d.id for d in directives.filter("foo")] == ["foo"]


def test_query_resolves_directive_by_exact_id(state):
    """`query_type=bgp_route` must select `bgp_route`, not `bgp_route_table`."""
    query = query_module.Query(
        query_location="r1", query_type="bgp_route", query_target="1.1.1.1"
    )
    assert query.directive.id == "bgp_route"
    assert query.directive.rules[0].commands == ["show ip bgp {target}"]


def test_query_resolves_table_directive_by_exact_id(state):
    """And the longer id still resolves to itself."""
    query = query_module.Query(
        query_location="r1", query_type="bgp_route_table", query_target="1.1.1.1"
    )
    assert query.directive.id == "bgp_route_table"
