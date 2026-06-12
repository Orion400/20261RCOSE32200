#!/usr/bin/env python3
"""Local TLS 1.2 RSA-key-exchange client for a Wireshark demo."""
from __future__ import annotations

import argparse
import socket
import ssl
from pathlib import Path

from tls12_lab.common import (
    CERT_PATH,
    CLIENT_MESSAGE,
    DEFAULT_PORT,
    LOCALHOST_NAME,
    LOOPBACK_HOST,
    SERVER_BANNER,
    STATIC_RSA_CIPHERS,
    assert_static_rsa_negotiated,
    make_tls12_context,
    require_loopback_host,
)

HOST = LOOPBACK_HOST
PORT = DEFAULT_PORT
CAFILE = str(CERT_PATH)
CIPHERS = STATIC_RSA_CIPHERS  # TLS_RSA_WITH_AES_128_CBC_SHA, non-PFS, for teaching only.
MESSAGE = CLIENT_MESSAGE
EXPECTED_REPLY = 'ECHO: ' + MESSAGE


def make_context(cafile: Path = CERT_PATH) -> ssl.SSLContext:
    ctx = make_tls12_context(ssl.PROTOCOL_TLS_CLIENT, CIPHERS)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(cafile))
    return ctx


def run_client(host: str, port: int, cafile: Path, timeout: float) -> int:
    require_loopback_host(host)
    ctx = make_context(cafile)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=LOCALHOST_NAME) as s:
            s.settimeout(timeout)
            assert_static_rsa_negotiated(s)
            print('[CLIENT] connected:', s.version(), s.cipher())
            banner = s.recv(4096).decode('utf-8', errors='replace')
            print('[CLIENT] server says:', banner.rstrip())
            if banner != SERVER_BANNER:
                raise RuntimeError(f'unexpected server banner: {banner!r}')
            print('[CLIENT] sending:', MESSAGE.rstrip())
            s.sendall(MESSAGE.encode('utf-8'))
            reply = s.recv(4096).decode('utf-8', errors='replace')
            print('[CLIENT] reply:', reply.rstrip())
            if reply != EXPECTED_REPLY:
                raise RuntimeError(f'unexpected echo reply: {reply!r}')
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the local TLS 1.2 static-RSA lab client.')
    parser.add_argument('--host', default=HOST, help='must remain 127.0.0.1')
    parser.add_argument('--port', type=int, default=PORT, help='default: 8443')
    parser.add_argument('--cafile', type=Path, default=CERT_PATH, help='trusted lab certificate; default: cert.pem')
    parser.add_argument('--timeout', type=float, default=10.0, help='connect and receive timeout in seconds')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return run_client(args.host, args.port, args.cafile, args.timeout)
    except (OSError, RuntimeError, ValueError, ssl.SSLError) as exc:
        print(f'[CLIENT] error: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
