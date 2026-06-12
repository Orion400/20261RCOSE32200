#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import ssl
from pathlib import Path

from tls12_lab.common import CERT_PATH, CLIENT_MESSAGE, LOCALHOST_NAME, LOOPBACK_HOST, SERVER_BANNER, make_tls12_context, require_loopback_host
from server_tls12_ecdhe import CONTROL_PORT, CIPHERS

EXPECTED_REPLY = 'ECHO: ' + CLIENT_MESSAGE


def make_context(cafile: Path) -> ssl.SSLContext:
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
        with ctx.wrap_socket(raw, server_hostname=LOCALHOST_NAME) as conn:
            conn.settimeout(timeout)
            cipher = conn.cipher()
            if conn.version() != 'TLSv1.2' or not cipher or not cipher[0].startswith('ECDHE-RSA'):
                raise ssl.SSLError(f'unexpected ECDHE control negotiation: {conn.version()} {cipher}')
            print('[ECDHE CLIENT] connected:', conn.version(), cipher)
            banner = conn.recv(4096).decode('utf-8', errors='replace')
            if banner != SERVER_BANNER:
                raise RuntimeError(f'unexpected server banner: {banner!r}')
            conn.sendall(CLIENT_MESSAGE.encode('utf-8'))
            reply = conn.recv(4096).decode('utf-8', errors='replace')
            print('[ECDHE CLIENT] reply:', reply.rstrip())
            if reply != EXPECTED_REPLY:
                raise RuntimeError(f'unexpected echo reply: {reply!r}')
    print('[ECDHE CLIENT] RSA authenticated the server; ephemeral ECDH supplied the session secret.')
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run a local TLS 1.2 ECDHE_RSA negative control client.')
    parser.add_argument('--host', default=LOOPBACK_HOST, help='must remain 127.0.0.1')
    parser.add_argument('--port', type=int, default=CONTROL_PORT, help='default: 8444')
    parser.add_argument('--cafile', type=Path, default=CERT_PATH)
    parser.add_argument('--timeout', type=float, default=10.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return run_client(args.host, args.port, args.cafile, args.timeout)
    except Exception as exc:
        print(f'[ECDHE CLIENT] error: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
