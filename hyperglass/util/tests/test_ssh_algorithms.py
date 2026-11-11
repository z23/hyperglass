"""The SSH algorithm probe must classify what a server offers without logging in."""

# Standard Library
import socket
import struct
import typing as t
import threading

# Third Party
import pytest

# Local
from ..ssh_algorithms import SSHProbeError, SSHAlgorithms, probe, parse_kexinit

MODERN_KEX = ("curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256")
LEGACY_KEX = ("diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1")
MODERN_KEYS = ("rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519")
LEGACY_KEYS = ("ssh-rsa", "ssh-dss")


def kexinit_payload(kex: t.Sequence[str], host_key: t.Sequence[str]) -> bytes:
    """Build an SSH_MSG_KEXINIT payload offering the given algorithms."""

    def name_list(names: t.Sequence[str]) -> bytes:
        data = ",".join(names).encode()
        return struct.pack(">I", len(data)) + data

    lists = [kex, host_key, *([("aes128-ctr",)] * 2), *([("hmac-sha2-256",)] * 2)]
    lists += [("none",)] * 2 + [()] * 2
    body = bytes([20]) + bytes(16) + b"".join(name_list(names) for names in lists)
    return body + b"\x00" + struct.pack(">I", 0)


def packet(payload: bytes) -> bytes:
    """Wrap a payload in an unencrypted SSH binary packet."""
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    return struct.pack(">IB", len(payload) + padding + 1, padding) + payload + bytes(padding)


@pytest.fixture
def server() -> t.Generator[t.Callable[[bytes], int], None, None]:
    """Start one-shot TCP servers that send fixed bytes to the first client."""
    sockets = []

    def start(response: bytes) -> int:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        sockets.append(listener)

        def serve() -> None:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                connection.sendall(response)
                connection.settimeout(2)
                try:
                    connection.recv(256)
                except OSError:
                    pass

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    yield start
    for listener in sockets:
        listener.close()


def test_modern_server_is_ok(server):
    port = server(b"SSH-2.0-TestServer_1.0\r\n" + packet(kexinit_payload(MODERN_KEX, MODERN_KEYS)))
    result = probe("127.0.0.1", port, timeout=3)
    assert result.server_version == "SSH-2.0-TestServer_1.0"
    assert result.kex == MODERN_KEX
    assert result.host_key == MODERN_KEYS
    assert result.legacy_only is False
    assert result.verdict == "ok"


def test_mixed_server_is_ok(server):
    """A server that also offers SHA-1 algorithms is fine as long as it has others."""
    port = server(
        b"SSH-2.0-Mixed\r\n"
        + packet(kexinit_payload(LEGACY_KEX + MODERN_KEX, LEGACY_KEYS + MODERN_KEYS))
    )
    result = probe("127.0.0.1", port, timeout=3)
    assert result.legacy_only is False
    assert result.modern_kex == MODERN_KEX
    assert result.modern_host_key == MODERN_KEYS


@pytest.mark.parametrize(
    ("kex", "keys", "expected"),
    [
        (LEGACY_KEX, LEGACY_KEYS, "legacy only (key exchange and host key need SHA-1)"),
        (LEGACY_KEX, MODERN_KEYS, "legacy only (key exchange need SHA-1)"),
        (MODERN_KEX, LEGACY_KEYS, "legacy only (host key need SHA-1)"),
    ],
)
def test_legacy_only_server_is_flagged(server, kex, keys, expected):
    port = server(b"SSH-2.0-Cisco-1.25\r\n" + packet(kexinit_payload(kex, keys)))
    result = probe("127.0.0.1", port, timeout=3)
    assert result.reachable is True
    assert result.legacy_only is True
    assert result.verdict == expected


def test_banner_lines_before_the_version_are_skipped(server):
    preamble = b"Authorised users only\r\nAll activity is logged\r\n"
    port = server(
        preamble + b"SSH-2.0-Banner\r\n" + packet(kexinit_payload(MODERN_KEX, MODERN_KEYS))
    )
    result = probe("127.0.0.1", port, timeout=3)
    assert result.server_version == "SSH-2.0-Banner"
    assert result.verdict == "ok"


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 400 Bad Request\r\n\r\n",
        b"SSH-2.0-Short\r\n",
        b"SSH-2.0-Garbage\r\n" + struct.pack(">I", 2_000_000),
        b"SSH-2.0-NotKex\r\n" + packet(bytes([2]) + bytes(40)),
    ],
)
def test_servers_that_do_not_speak_ssh_are_reported_not_crashed(server, response):
    result = probe("127.0.0.1", server(response), timeout=2)
    assert result.reachable is False
    assert result.legacy_only is False
    assert result.verdict.startswith("not checked: ")


def test_refused_connection_is_reported():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    result = probe("127.0.0.1", port, timeout=2)
    assert result.reachable is False
    assert "refused" in result.verdict.lower()


def test_parse_kexinit_rejects_truncated_lists():
    payload = kexinit_payload(MODERN_KEX, MODERN_KEYS)
    with pytest.raises(SSHProbeError):
        parse_kexinit(payload[:24])
    with pytest.raises(SSHProbeError):
        parse_kexinit(b"")


def test_unreachable_result_is_never_legacy():
    assert SSHAlgorithms(host="r1", port=22, error="timed out").legacy_only is False
