#!/usr/bin/env python3
"""
Create a deliberately weak RSA key for a LOCAL educational TLS 1.2 RSA-key-exchange demo.
The weakness is that p and q are intentionally very close, so Fermat factorization is fast.
Do not use these materials outside a local lab.
"""
from __future__ import annotations

import ipaddress
import math
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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
    # Miller-Rabin deterministic bases are not known for arbitrary 1024-bit ints;
    # 32 random bases gives negligible error for a teaching demo.
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

def make_close_primes(bits: int = BITS) -> tuple[int, int]:
    half = bits // 2
    # Generate a random 1024-bit odd candidate for p.
    candidate = secrets.randbits(half)
    candidate |= (1 << (half - 1))  # force bit length
    candidate |= 1
    p = next_prime(candidate)
    q = next_prime(p + DELTA)
    if p == q:
        q = next_prime(q + 2)
    if p > q:
        p, q = q, p
    # Ensure e is invertible mod phi.
    while math.gcd(E, (p - 1) * (q - 1)) != 1:
        p = next_prime(p + 2)
        q = next_prime(p + DELTA)
        if p > q:
            p, q = q, p
    return p, q

def build_private_key(p: int, q: int, e: int = E) -> rsa.RSAPrivateKey:
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    return numbers.private_key()

def write_cert(private_key: rsa.RSAPrivateKey) -> None:
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'KR'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Discrete Math RSA Local Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])
    now = datetime.now(timezone.utc)
    cert = (
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
    (OUT_DIR / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))

def main() -> None:
    p, q = make_close_primes(BITS)
    key = build_private_key(p, q, E)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # BEGIN RSA PRIVATE KEY; convenient for Wireshark RSA-key demo
        encryption_algorithm=serialization.NoEncryption(),
    )
    (OUT_DIR / 'key.pem').write_bytes(key_pem)
    write_cert(key)
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
    (OUT_DIR / 'weak_rsa_params.txt').write_text(params, encoding='utf-8')
    print('[OK] Created key.pem, cert.pem, weak_rsa_params.txt')
    print(f'[INFO] bits(n)={n.bit_length()}, q-p={q-p}')
    print('[INFO] This key is intentionally weak: p and q are close for Fermat factorization.')

if __name__ == '__main__':
    main()
