#!/usr/bin/env python3
"""Local TLS 1.2 RSA-key-exchange echo server for a Wireshark demo."""
from __future__ import annotations

import socket
import ssl

HOST = '127.0.0.1'
PORT = 8443
CERT = 'cert.pem'
KEY = 'key.pem'
CIPHERS = 'AES128-SHA:@SECLEVEL=0'  # TLS_RSA_WITH_AES_128_CBC_SHA, non-PFS, for teaching only.

def make_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_TICKET
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    return ctx

def main() -> None:
    ctx = make_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f'[SERVER] listening on {HOST}:{PORT}')
        print('[SERVER] start Wireshark capture on loopback before running the client.')
        with ctx.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                print('[SERVER] client:', addr)
                print('[SERVER] negotiated:', conn.version(), conn.cipher())
                conn.sendall(b'Welcome to the local TLS 1.2 RSA demo.\n')
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    print('[SERVER] received:', data.decode('utf-8', errors='replace').rstrip())
                    conn.sendall(b'ECHO: ' + data)
        print('[SERVER] done')

if __name__ == '__main__':
    main()
