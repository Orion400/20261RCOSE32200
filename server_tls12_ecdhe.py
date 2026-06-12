#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import ssl
from pathlib import Path

from tls12_lab.common import CERT_PATH, DEFAULT_PORT, KEY_PATH, LOOPBACK_HOST, SERVER_BANNER, make_tls12_context, require_loopback_host

CIPHERS = 'ECDHE-RSA-AES128-SHA:@SECLEVEL=0'
CONTROL_PORT = DEFAULT_PORT + 1


def make_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = make_tls12_context(ssl.PROTOCOL_TLS_SERVER, CIPHERS)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


def run_server(host: str, port: int, cert: Path, key: Path, timeout: float) -> int:
    require_loopback_host(host)
    ctx = make_context(cert, key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.bind((host, port))
        sock.listen(1)
        print(f'[ECDHE SERVER] listening on {host}:{port}')
        raw, addr = sock.accept()
        with raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_side=True) as conn:
                conn.settimeout(timeout)
                cipher = conn.cipher()
                if conn.version() != 'TLSv1.2' or not cipher or not cipher[0].startswith('ECDHE-RSA'):
                    raise ssl.SSLError(f'unexpected ECDHE control negotiation: {conn.version()} {cipher}')
                print('[ECDHE SERVER] client:', addr)
                print('[ECDHE SERVER] negotiated:', conn.version(), cipher)
                conn.sendall(SERVER_BANNER.encode('utf-8'))
                data = conn.recv(4096)
                print('[ECDHE SERVER] received:', data.decode('utf-8', errors='replace').rstrip())
                conn.sendall(b'ECHO: ' + data)
    print('[ECDHE SERVER] done')
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run a local TLS 1.2 ECDHE_RSA negative control server.')
    parser.add_argument('--host', default=LOOPBACK_HOST, help='must remain 127.0.0.1')
    parser.add_argument('--port', type=int, default=CONTROL_PORT, help='default: 8444')
    parser.add_argument('--cert', type=Path, default=CERT_PATH)
    parser.add_argument('--key', type=Path, default=KEY_PATH)
    parser.add_argument('--timeout', type=float, default=10.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return run_server(args.host, args.port, args.cert, args.key, args.timeout)
    except Exception as exc:
        print(f'[ECDHE SERVER] error: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
