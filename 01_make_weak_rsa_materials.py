#!/usr/bin/env python3
"""
Create a deliberately weak RSA key for a LOCAL educational TLS 1.2 RSA-key-exchange demo.
The weakness is that p and q are intentionally very close, so Fermat factorization is fast.
Do not use these materials outside a local lab.
"""
from __future__ import annotations

import argparse
import ipaddress
import math
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls12_lab.common import CERT_PATH, KEY_PATH, PARAMS_PATH, ensure_output_dir

E = 65537
BITS = 2048          # RSA modulus size; p and q are roughly 1024-bit each.
DELTA = 1 << 20      # q is generated near p + DELTA, making Fermat factorization instant.
OUT_DIR = Path('.')

_SMALL_PRIMES = [
    3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
    101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,
    193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,
    293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401
]


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(32):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    if n <= 2:
        return 2
    if n % 2 == 0:
        n += 1
    while not is_probable_prime(n):
        n += 2
    return n


def make_close_primes(bits: int = BITS, delta: int = DELTA) -> tuple[int, int]:
    if bits < 512 or bits % 2:
        raise ValueError('bits must be an even integer of at least 512')
    if delta < 2:
        raise ValueError('delta must be at least 2')
    half = bits // 2
    while True:
        candidate = secrets.randbits(half)
        candidate |= (1 << (half - 1))
        candidate |= 1
        p = next_prime(candidate)
        q = next_prime(p + delta)
        if p == q:
            q = next_prime(q + 2)
        if p > q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        n = p * q
        if p != q and math.gcd(E, phi) == 1 and n.bit_length() == bits:
            return p, q


def build_private_key(p: int, q: int, e: int = E) -> rsa.RSAPrivateKey:
    if p == q:
        raise ValueError('p and q must be distinct')
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError('public exponent is not invertible modulo phi(n)')
    d = pow(e, -1, phi)
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    return numbers.private_key()


def build_certificate(private_key: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'KR'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Discrete Math RSA Local Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )


def write_cert(private_key: rsa.RSAPrivateKey, output_dir: Path = OUT_DIR) -> None:
    cert = build_certificate(private_key)
    (output_dir / CERT_PATH.name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def verify_key_matches_certificate(private_key: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
    cert_pub = cert.public_key().public_numbers()
    key_pub = private_key.public_key().public_numbers()
    if cert_pub != key_pub:
        raise ValueError('certificate public key does not match generated private key')


def write_materials(bits: int, delta: int, output_dir: Path, verbose: bool = False) -> tuple[Path, Path, Path]:
    output_dir = ensure_output_dir(output_dir)
    p, q = make_close_primes(bits, delta)
    key = build_private_key(p, q, E)
    cert = build_certificate(key)
    verify_key_matches_certificate(key, cert)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    if n.bit_length() != bits:
        raise ValueError(f'generated modulus has {n.bit_length()} bits, expected {bits}')
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = output_dir / KEY_PATH.name
    cert_path = output_dir / CERT_PATH.name
    params_path = output_dir / PARAMS_PATH.name
    key_path.write_bytes(key_pem)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    params = f"""# Deliberately weak RSA test key for a LOCAL educational lab only.
# Do not use outside this demo.

bits(n) = {n.bit_length()}
e = {E}
p = {p}
q = {q}
q - p = {q - p}
n = {n}
phi(n) = {phi}
d = {d}

Fermat relation:
a = (p + q) // 2 = {(p + q) // 2}
b = (q - p) // 2 = {(q - p) // 2}
n = a^2 - b^2 = (a-b)(a+b)
"""
    params_path.write_text(params, encoding='utf-8')
    print(f'[OK] Created {key_path.name}, {cert_path.name}, {params_path.name}')
    print(f'[INFO] bits(n)={n.bit_length()}, q-p={q-p}')
    if verbose:
        print(f'[INFO] output_dir={output_dir.resolve()}')
        print(f'[INFO] delta={delta}, e={E}')
    print('[INFO] This key is intentionally weak: p and q are close for Fermat factorization.')
    return key_path, cert_path, params_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create close-prime RSA materials for the local TLS 1.2 lab.')
    parser.add_argument('--bits', type=int, default=BITS, help='RSA modulus size; default: 2048')
    parser.add_argument('--delta', type=int, default=DELTA, help='starting gap between p and q candidates')
    parser.add_argument('--output-dir', type=Path, default=OUT_DIR, help='directory for key.pem, cert.pem, weak_rsa_params.txt')
    parser.add_argument('--verbose', action='store_true', help='print additional non-secret generation details')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    write_materials(args.bits, args.delta, args.output_dir, args.verbose)


if __name__ == '__main__':
    main()
