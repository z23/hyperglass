"""Devices that skip SSH host key verification must be flagged at startup."""

# Standard Library
from types import SimpleNamespace

# Project
from hyperglass.models.config.devices import ssh_host_key_warning


def _device(driver="netmiko", **driver_config):
    return SimpleNamespace(name="r1", driver=driver, driver_config=driver_config)


def test_default_driver_config_is_flagged():
    warning = ssh_host_key_warning(_device())
    assert warning is not None
    assert "does not verify SSH host keys" in warning
    assert "r1" in warning


def test_strict_without_keys_is_flagged_distinctly():
    warning = ssh_host_key_warning(_device(ssh_strict=True))
    assert warning is not None
    assert "loads no host keys" in warning


def test_strict_with_alt_keys_is_fine():
    assert (
        ssh_host_key_warning(
            _device(ssh_strict=True, alt_host_keys=True, alt_key_file="/etc/hyperglass/known_hosts")
        )
        is None
    )


def test_strict_with_system_keys_is_fine():
    assert ssh_host_key_warning(_device(ssh_strict=True, system_host_keys=True)) is None


def test_non_ssh_drivers_are_ignored():
    assert ssh_host_key_warning(_device(driver="hyperglass_http_client")) is None


def test_missing_driver_config_attribute_is_tolerated():
    device = SimpleNamespace(name="r1", driver="netmiko", driver_config=None)
    assert ssh_host_key_warning(device) is not None
