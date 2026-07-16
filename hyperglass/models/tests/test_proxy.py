"""Tests for SSH proxy configuration validation."""

# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.state.hooks import _use_state
from hyperglass.models.directive import Directives
from hyperglass.exceptions.private import ConfigError

# Local
from ..config.proxy import Proxy
from ..config.devices import Device

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState

PROXY_CONFIG = {
    "address": "203.0.113.1",
    "credential": {"username": "proxyuser", "password": "proxypass"},
}


@pytest.fixture
def state() -> t.Generator["HyperglassState", None, None]:
    """Initialize directives state, required to build Device models."""
    # `use_state` caches the first value read for each state attribute for the
    # life of the process; clear it so this fixture's state is visible. It is
    # deliberately not cleared on teardown: several later test modules
    # implicitly rely on a warm state cache.
    _use_state.cache_clear()
    _state = use_state()
    with _state.cache.pipeline() as pipeline:
        pipeline.set("directives", Directives.new())
    yield _state
    _state.clear()


def make_device(**overrides: t.Any) -> Device:
    config = {
        "name": "test1",
        "address": "192.0.2.1",
        "credential": {"username": "user", "password": "pass"},
        "platform": "juniper",
        **overrides,
    }
    return Device(**config)


def test_proxy_platform_defaults_to_linux_ssh():
    proxy = Proxy(**PROXY_CONFIG)
    assert proxy.platform == "linux_ssh"


def test_proxy_legacy_nos_field_maps_to_platform():
    proxy = Proxy(**PROXY_CONFIG, nos="linux_ssh")
    assert proxy.platform == "linux_ssh"


def test_proxy_rejects_unsupported_platform():
    with pytest.raises(ConfigError):
        Proxy(**PROXY_CONFIG, platform="cisco_ios")


def test_proxy_accepts_known_hosts_file(tmp_path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    proxy = Proxy(**PROXY_CONFIG, known_hosts_file=str(known_hosts))
    assert proxy.known_hosts_file is not None


def test_proxy_rejects_missing_known_hosts_file(tmp_path):
    with pytest.raises(ValueError):
        Proxy(**PROXY_CONFIG, known_hosts_file=str(tmp_path / "does_not_exist"))


def test_device_with_proxy(state):
    device = make_device(proxy=PROXY_CONFIG)
    assert device.proxy is not None
    assert device.driver == "netmiko"


def test_device_proxy_with_http_driver_rejected(state):
    with pytest.raises(ConfigError):
        make_device(platform="http", http={}, proxy=PROXY_CONFIG)


def test_device_proxy_with_ssh_config_file_rejected(state):
    with pytest.raises(ConfigError):
        make_device(proxy=PROXY_CONFIG, driver_config={"ssh_config_file": "/etc/ssh/ssh_config"})


def test_device_without_proxy_allows_ssh_config_file(state):
    device = make_device(driver_config={"ssh_config_file": "/etc/ssh/ssh_config"})
    assert device.proxy is None
