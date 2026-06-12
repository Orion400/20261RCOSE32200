#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from tls12_lab.common import DEFAULT_PORT, LOOPBACK_HOST, STATIC_RSA_SUITE

ALLOWED_INTERFACES = {"lo", "Loopback", "lo0"}
HANDSHAKES = {
    "1": "ClientHello",
    "2": "ServerHello",
    "11": "Certificate",
    "16": "ClientKeyExchange",
}


@dataclass(frozen=True)
class CaptureAnalysis:
    tls12: bool
    suite: bool
    client_hello: bool
    server_hello: bool
    certificate: bool
    client_key_exchange: bool
    application_data: bool
    loopback_port: bool
    plaintext_found: bool | None

    def ok_without_decryption(self) -> bool:
        return all([
            self.tls12,
            self.suite,
            self.client_hello,
            self.server_hello,
            self.certificate,
            self.client_key_exchange,
            self.application_data,
            self.loopback_port,
        ])


def find_capture_tool() -> str | None:
    for name in ("dumpcap", "tshark"):
        path = shutil.which(name)
        if path:
            return path
    return None


def validate_interface(name: str) -> str:
    if name not in ALLOWED_INTERFACES:
        raise ValueError('only loopback capture interfaces are supported')
    return name


def capture_loopback(output: Path, interface: str, port: int, duration: int) -> int:
    validate_interface(interface)
    tool = find_capture_tool()
    if tool is None:
        raise RuntimeError('dumpcap/tshark is not available')
    if Path(tool).name == 'dumpcap':
        cmd = [tool, '-i', interface, '-f', f'tcp port {port}', '-a', f'duration:{duration}', '-w', str(output)]
    else:
        cmd = [tool, '-i', interface, '-f', f'tcp port {port}', '-a', f'duration:{duration}', '-w', str(output)]
    print('[CAPTURE] running:', ' '.join(cmd))
    completed = subprocess.run(cmd, text=True)
    if completed.returncode != 0:
        print('[CAPTURE] capture failed; check loopback capture permissions without using sudo from this script')
    return completed.returncode


def tshark_fields(pcap: Path, fields: list[str], extra: list[str] | None = None) -> list[str]:
    tshark = shutil.which('tshark')
    if not tshark:
        raise RuntimeError('tshark is required for protocol analysis')
    cmd = [tshark, '-r', str(pcap)]
    if extra:
        cmd.extend(extra)
    cmd.extend(['-T', 'fields'])
    for field in fields:
        cmd.extend(['-e', field])
    completed = subprocess.run(cmd, text=True, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or 'tshark analysis failed')
    return completed.stdout.splitlines()


def analyze_capture(pcap: Path, port: int, recovered_key: Path | None = None) -> CaptureAnalysis:
    fields = ['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tls.record.version', 'tls.handshake.type', 'tls.handshake.ciphersuite', 'tls.record.content_type']
    lines = tshark_fields(pcap, fields)
    text = '\n'.join(lines)
    loopback_port = False
    handshake_types: set[str] = set()
    content_types: set[str] = set()
    for line in lines:
        parts = line.split('\t')
        if len(parts) >= 4 and LOOPBACK_HOST in parts[:2] and str(port) in parts[2:4]:
            loopback_port = True
        if len(parts) >= 6:
            handshake_types.update(value for value in parts[5].replace(',', ' ').split() if value)
        if len(parts) >= 8:
            content_types.update(value for value in parts[7].replace(',', ' ').split() if value)
    plaintext_found: bool | None = None
    if recovered_key is not None:
        key_opt = f'tls.keys_list:{LOOPBACK_HOST},{port},data,{recovered_key}'
        verbose = subprocess.run([
            shutil.which('tshark') or 'tshark', '-r', str(pcap), '-o', key_opt, '-V'
        ], text=True, capture_output=True)
        if verbose.returncode == 0:
            plaintext_found = 'Discrete math makes RSA work.' in verbose.stdout
        else:
            plaintext_found = False
    return CaptureAnalysis(
        tls12='0x0303' in text or 'TLS 1.2' in text,
        suite='0x002f' in text or STATIC_RSA_SUITE in text,
        client_hello='1' in handshake_types,
        server_hello='2' in handshake_types,
        certificate='11' in handshake_types,
        client_key_exchange='16' in handshake_types,
        application_data='23' in content_types,
        loopback_port=loopback_port,
        plaintext_found=plaintext_found,
    )


def print_analysis(result: CaptureAnalysis) -> None:
    print(f'[ANALYZE] TLS 1.2 negotiated: {result.tls12}')
    print(f'[ANALYZE] {STATIC_RSA_SUITE} selected: {result.suite}')
    print(f'[ANALYZE] ClientHello exists: {result.client_hello}')
    print(f'[ANALYZE] ServerHello exists: {result.server_hello}')
    print(f'[ANALYZE] Certificate exists: {result.certificate}')
    print(f'[ANALYZE] ClientKeyExchange exists: {result.client_key_exchange}')
    print(f'[ANALYZE] Application Data exists: {result.application_data}')
    print(f'[ANALYZE] loopback port flow: {result.loopback_port}')
    if result.plaintext_found is None:
        print('[ANALYZE] plaintext verification not requested')
    else:
        print(f'[ANALYZE] expected plaintext decoded by tshark: {result.plaintext_found}')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Restricted loopback capture and TLS 1.2 RSA analysis helper.')
    parser.add_argument('--interface', default='lo', help='loopback interface only; default: lo')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='TCP port; default: 8443')
    parser.add_argument('--duration', type=int, default=10, help='capture duration in seconds')
    parser.add_argument('--output', type=Path, default=Path('demo_loopback.pcapng'), help='pcapng output path')
    parser.add_argument('--analyze', type=Path, help='analyze an existing pcapng instead of capturing')
    parser.add_argument('--recovered-key', type=Path, help='optional recovered_key.pem for tshark TLS decryption check')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.analyze:
            result = analyze_capture(
                args.analyze,
                args.port,
                args.recovered_key,
            )
            print_analysis(result)
            if not result.ok_without_decryption():
                return 1
            if (
                args.recovered_key is not None
                and result.plaintext_found is not True
            ):
                return 1
            return 0
        return capture_loopback(args.output, args.interface, args.port, args.duration)
    except Exception as exc:
        print(f'[CAPTURE] error: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
