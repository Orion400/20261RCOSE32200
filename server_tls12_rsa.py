#!/usr/bin/env python3
"""Local TLS 1.2 RSA-key-exchange echo server for a Wireshark demo."""
from __future__ import annotations

import argparse
import signal
import socket
import ssl
from pathlib import Path

from tls12_lab.common import (
    CERT_PATH,
    DEFAULT_PORT,
    KEY_PATH,
    LOOPBACK_HOST,
    SERVER_BANNER,
    STATIC_RSA_CIPHERS,
    assert_static_rsa_negotiated,
    make_tls12_context,
    require_loopback_host,
)

HOST = LOOPBACK_HOST
PORT = DEFAULT_PORT
CERT = str(CERT_PATH)
KEY = str(KEY_PATH)
CIPHERS = STATIC_RSA_CIPHERS  # TLS_RSA_WITH_AES_128_CBC_SHA, non-PFS, for teaching only.
RECV_SIZE = 4096

_shutdown = False


def _request_shutdown(signum: int, _frame: object) -> None:
    global _shutdown
    _shutdown = True
    print(f'[SERVER] received signal {signum}; shutting down')


def make_context(cert: Path = CERT_PATH, key: Path = KEY_PATH) -> ssl.SSLContext:
    ctx = make_tls12_context(ssl.PROTOCOL_TLS_SERVER, CIPHERS)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


def handle_client(conn: ssl.SSLSocket, addr: tuple[str, int]) -> None:
    print('[SERVER] client:', addr)
    assert_static_rsa_negotiated(conn)
    print('[SERVER] negotiated:', conn.version(), conn.cipher())
    conn.sendall(SERVER_BANNER.encode('utf-8'))
    while not _shutdown:
        try:
            data = conn.recv(RECV_SIZE)
        except socket.timeout:
            print('[SERVER] receive timed out; closing client connection')
            return
        if not data:
            return
        print('[SERVER] received:', data.decode('utf-8', errors='replace').rstrip())
        conn.sendall(b'ECHO: ' + data)
        return


def serve_once(host: str, port: int, cert: Path, key: Path, timeout: float, ready_file: Path | None = None) -> int:
    require_loopback_host(host)
    ctx = make_context(cert, key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.bind((host, port))
        sock.listen(5)
        print(f'[SERVER] listening on {host}:{port}')
        if ready_file is not None:
            ready_file.write_text(f'{host}:{port}\n', encoding='utf-8')
        print('[SERVER] start Wireshark capture on loopback before running the client.')
        while not _shutdown:
            try:
                raw, addr = sock.accept()
            except socket.timeout:
                continue
            with raw:
                raw.settimeout(timeout)
                try:
                    with ctx.wrap_socket(raw, server_side=True) as conn:
                        conn.settimeout(timeout)
                        handle_client(conn, addr)
                        print('[SERVER] done')
                        return 0
                except ssl.SSLError as exc:
                    print(f'[SERVER] TLS handshake failed from {addr}: {exc}')
                    continue
                except OSError as exc:
                    print(f'[SERVER] connection error from {addr}: {exc}')
                    continue
    print('[SERVER] stopped before serving a client')
    return 130 if _shutdown else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the local TLS 1.2 static-RSA lab server.')
    parser.add_argument('--host', default=HOST, help='must remain 127.0.0.1')
    parser.add_argument('--port', type=int, default=PORT, help='default: 8443')
    parser.add_argument('--cert', type=Path, default=CERT_PATH, help='certificate path; default: cert.pem')
    parser.add_argument('--key', type=Path, default=KEY_PATH, help='private key path; default: key.pem')
    parser.add_argument('--timeout', type=float, default=10.0, help='accept and receive timeout in seconds')
    parser.add_argument('--ready-file', type=Path, help='optional file touched after the listening socket is ready')
    return parser.parse_args()


def main() -> int:
    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    args = parse_args()
    try:
        return serve_once(args.host, args.port, args.cert, args.key, args.timeout, args.ready_file)
    except (OSError, ValueError, ssl.SSLError) as exc:
        print(f'[SERVER] error: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
