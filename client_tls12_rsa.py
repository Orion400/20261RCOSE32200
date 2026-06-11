#!/usr/bin/env python3
"""Local TLS 1.2 RSA-key-exchange client for a Wireshark demo."""
from __future__ import annotations

import socket
import ssl

HOST = '127.0.0.1'
PORT = 8443
CAFILE = 'cert.pem'
CIPHERS = 'AES128-SHA:@SECLEVEL=0'  # TLS_RSA_WITH_AES_128_CBC_SHA, non-PFS, for teaching only.
MESSAGE = 'Discrete math makes RSA work.\n'

def make_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_TICKET
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=CAFILE)
    return ctx

def main() -> None:
    ctx = make_context()
    with socket.create_connection((HOST, PORT)) as raw:
        with ctx.wrap_socket(raw, server_hostname='localhost') as s:
            print('[CLIENT] connected:', s.version(), s.cipher())
            banner = s.recv(4096)
            print('[CLIENT] server says:', banner.decode('utf-8', errors='replace').rstrip())
            print('[CLIENT] sending:', MESSAGE.rstrip())
            s.sendall(MESSAGE.encode('utf-8'))
            reply = s.recv(4096)
            print('[CLIENT] reply:', reply.decode('utf-8', errors='replace').rstrip())

if __name__ == '__main__':
    main()
