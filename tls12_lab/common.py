from __future__ import annotations

import socket
import ssl
from pathlib import Path

LOOPBACK_HOST = "127.0.0.1"
LOCALHOST_NAME = "localhost"
DEFAULT_PORT = 8443
CERT_PATH = Path("cert.pem")
KEY_PATH = Path("key.pem")
RECOVERED_KEY_PATH = Path("recovered_key.pem")
PARAMS_PATH = Path("weak_rsa_params.txt")
STATIC_RSA_CIPHERS = "AES128-SHA:@SECLEVEL=0"
STATIC_RSA_CIPHER_NAME = "AES128-SHA"
STATIC_RSA_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA"
TLS_VERSION = "TLSv1.2"
CLIENT_MESSAGE = "Discrete math makes RSA work.\n"
SERVER_BANNER = "Welcome to the local TLS 1.2 RSA demo.\n"


def require_loopback_host(host: str) -> str:
    if host != LOOPBACK_HOST:
        raise ValueError(f"only {LOOPBACK_HOST} is supported for this local lab")
    return host


def ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise NotADirectoryError(f"output path is not a directory: {path}")
    return path


def make_tls12_context(protocol: int, ciphers: str = STATIC_RSA_CIPHERS) -> ssl.SSLContext:
    ctx = ssl.SSLContext(protocol)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(ciphers)
    ctx.options |= ssl.OP_NO_TICKET
    return ctx


def assert_static_rsa_negotiated(sock: ssl.SSLSocket) -> None:
    version = sock.version()
    cipher = sock.cipher()
    cipher_name = cipher[0] if cipher else None
    if version != TLS_VERSION:
        raise ssl.SSLError(f"expected {TLS_VERSION}, negotiated {version!r}")
    if cipher_name != STATIC_RSA_CIPHER_NAME:
        raise ssl.SSLError(f"expected {STATIC_RSA_CIPHER_NAME}, negotiated {cipher_name!r}")


def is_port_free(host: str = LOOPBACK_HOST, port: int = DEFAULT_PORT) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


def artifact_path(output_dir: Path, name: str) -> Path:
    return ensure_output_dir(output_dir) / name
