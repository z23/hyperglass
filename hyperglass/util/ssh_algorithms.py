"""Report which SSH algorithms a device offers.

paramiko 5 removed SHA-1 from the SSH client: the `ssh-rsa` host key
algorithm and every `*-sha1` key exchange are gone, with no option to turn
them back on. A device that offers nothing else cannot be reached with it.
This module reads what a device offers, without authenticating, so that can
be checked before the SSH library is upgraded.

Only the first, unencrypted step of the protocol is used: both sides
exchange a version line, then the server sends its `SSH_MSG_KEXINIT`
listing the algorithms it supports (RFC 4253, sections 4.2 and 7.1).
"""

# Standard Library
import socket
import struct
import typing as t
from dataclasses import field, dataclass

SSH_MSG_KEXINIT = 20

# Largest packet the probe will read. A KEXINIT is a few kilobytes; RFC 4253
# requires implementations to handle 35000 bytes.
MAX_PACKET_BYTES = 35000

CLIENT_VERSION = b"SSH-2.0-hyperglass_algorithm_probe\r\n"

# Host key algorithms and key exchanges implemented by paramiko 5.1.0, taken
# from its `Transport._key_info` and `Transport._kex_info` tables (certificate
# and GSS-API variants left out).
MODERN_HOST_KEY_ALGORITHMS = frozenset(
    {
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    }
)

MODERN_KEX_ALGORITHMS = frozenset(
    {
        "mlkem768x25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
    }
)


class SSHProbeError(Exception):
    """Raised when a device does not answer like an SSH server."""


@dataclass
class SSHAlgorithms:
    """The algorithms an SSH server offers."""

    host: str
    port: int
    server_version: str = ""
    kex: t.Tuple[str, ...] = ()
    host_key: t.Tuple[str, ...] = ()
    error: t.Optional[str] = None
    modern_kex: t.Tuple[str, ...] = field(init=False, default=())
    modern_host_key: t.Tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        """Work out which offered algorithms are not SHA-1 based."""
        self.modern_kex = tuple(a for a in self.kex if a in MODERN_KEX_ALGORITHMS)
        self.modern_host_key = tuple(a for a in self.host_key if a in MODERN_HOST_KEY_ALGORITHMS)

    @property
    def reachable(self) -> bool:
        """Whether the device answered the probe."""
        return self.error is None

    @property
    def legacy_only(self) -> bool:
        """Whether the device can only be reached with SHA-1 algorithms."""
        return self.reachable and not (self.modern_kex and self.modern_host_key)

    @property
    def verdict(self) -> str:
        """Summarise the result in a few words."""
        if not self.reachable:
            return f"not checked: {self.error}"
        missing = []
        if not self.modern_kex:
            missing.append("key exchange")
        if not self.modern_host_key:
            missing.append("host key")
        if missing:
            return f"legacy only ({' and '.join(missing)} need SHA-1)"
        return "ok"


def _read_exactly(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise SSHProbeError("connection closed before the key exchange message")
        data += chunk
    return data


def _read_version(sock: socket.socket) -> str:
    """Read lines until the server's `SSH-` version line (RFC 4253, 4.2)."""
    for _ in range(64):
        line = b""
        while not line.endswith(b"\n"):
            byte = sock.recv(1)
            if not byte:
                raise SSHProbeError("connection closed before the SSH version line")
            line += byte
            if len(line) > 1024:
                raise SSHProbeError("no SSH version line received")
        if line.startswith(b"SSH-"):
            return line.strip().decode("ascii", "replace")
    raise SSHProbeError("no SSH version line received")


def parse_kexinit(payload: bytes) -> t.Tuple[t.Tuple[str, ...], t.Tuple[str, ...]]:
    """Get the key exchange and host key algorithm lists from a KEXINIT payload."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise SSHProbeError("first packet was not a key exchange message")

    # 1 byte message type, 16 byte cookie, then ten name-lists.
    offset = 17
    lists: t.List[t.Tuple[str, ...]] = []
    for _ in range(2):
        if offset + 4 > len(payload):
            raise SSHProbeError("truncated key exchange message")
        (length,) = struct.unpack(">I", payload[offset : offset + 4])
        offset += 4
        if offset + length > len(payload):
            raise SSHProbeError("truncated key exchange message")
        names = payload[offset : offset + length].decode("ascii", "replace")
        offset += length
        lists.append(tuple(name for name in names.split(",") if name))
    return lists[0], lists[1]


def probe(host: str, port: int = 22, timeout: float = 10) -> SSHAlgorithms:
    """Ask an SSH server which key exchange and host key algorithms it offers."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            server_version = _read_version(sock)
            sock.sendall(CLIENT_VERSION)
            (packet_length,) = struct.unpack(">I", _read_exactly(sock, 4))
            if not 2 <= packet_length <= MAX_PACKET_BYTES:
                raise SSHProbeError("unexpected packet length")
            packet = _read_exactly(sock, packet_length)
            padding_length = packet[0]
            payload = packet[1 : packet_length - padding_length]
            kex, host_key = parse_kexinit(payload)
    except SSHProbeError as err:
        return SSHAlgorithms(host=host, port=port, error=str(err))
    except OSError as err:
        return SSHAlgorithms(host=host, port=port, error=err.strerror or type(err).__name__)

    return SSHAlgorithms(
        host=host, port=port, server_version=server_version, kex=kex, host_key=host_key
    )
