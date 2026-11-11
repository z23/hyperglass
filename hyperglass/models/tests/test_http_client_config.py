"""The HTTP device client must reach the configured port and apply its TLS settings."""

# Standard Library
import ssl
import asyncio
import datetime
import threading
from types import SimpleNamespace
from ipaddress import ip_address
from http.server import HTTPServer, BaseHTTPRequestHandler

# Third Party
import httpx
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Local
from ..config.http_client import HttpConfiguration


def _device(address="192.0.2.10", port=443):
    return SimpleNamespace(address=address, port=port, name="http-device")


def _ssl_context(client: httpx.AsyncClient) -> ssl.SSLContext:
    """Get the TLS context the client's transport will actually use."""
    return client._transport._pool._ssl_context


@pytest.mark.parametrize(
    ("address", "port", "expected"),
    [
        ("192.0.2.10", 443, "https://192.0.2.10"),
        ("192.0.2.10", 80, "https://192.0.2.10"),
        # 22 is the device model's default port, i.e. "not set".
        ("192.0.2.10", 22, "https://192.0.2.10"),
        ("192.0.2.10", 8443, "https://192.0.2.10:8443"),
        ("lg-api.example.net", 9000, "https://lg-api.example.net:9000"),
        ("2001:db8::10", 443, "https://[2001:db8::10]"),
        ("2001:db8::10", 8443, "https://[2001:db8::10]:8443"),
    ],
)
def test_base_url_includes_a_non_default_port(address, port, expected):
    client = HttpConfiguration().create_client(device=_device(address, port))
    assert str(client.base_url).rstrip("/") == expected


def test_verification_is_on_by_default():
    context = _ssl_context(HttpConfiguration().create_client(device=_device()))
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_verify_ssl_false_reaches_the_transport():
    context = _ssl_context(HttpConfiguration(verify_ssl=False).create_client(device=_device()))
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    """Create a self-signed server certificate for 127.0.0.1, with its key."""
    directory = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hyperglass test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file = directory / "cert.pem"
    key_file = directory / "key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return SimpleNamespace(cert=cert_file, key=key_file)


@pytest.fixture
def https_server(tls):
    """Serve HTTPS on a non-default port using the private certificate."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"route data"
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(tls.cert), keyfile=str(tls.key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _get(config: HttpConfiguration, port: int) -> httpx.Response:
    async def run():
        async with config.create_client(device=_device("127.0.0.1", port)) as client:
            # A relative URL: this only works if the base URL carries the port.
            return await client.request(method="GET", url="/lg")

    return asyncio.run(run())


def test_private_certificate_is_rejected_by_default(https_server):
    with pytest.raises(httpx.ConnectError):
        _get(HttpConfiguration(), https_server)


def test_ssl_ca_is_trusted_on_a_non_default_port(https_server, tls):
    response = _get(HttpConfiguration(ssl_ca=tls.cert), https_server)
    assert response.status_code == 200
    assert response.text == "route data"


def test_verify_ssl_false_accepts_a_private_certificate(https_server):
    assert _get(HttpConfiguration(verify_ssl=False), https_server).status_code == 200


def test_ssl_ca_does_not_also_trust_the_public_roots(tls):
    context = _ssl_context(HttpConfiguration(ssl_ca=tls.cert).create_client(device=_device()))
    assert context.cert_store_stats()["x509_ca"] == 1
