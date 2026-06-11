#!/usr/bin/env python3
"""
Recover the RSA private key from cert.pem when its public modulus n = p*q
was generated from deliberately close primes p and q.
Local educational demo only.
"""
from __future__ import annotations

import math
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT = Path('cert.pem')
OUT_KEY = Path('recovered_key.pem')

def ceil_sqrt(n: int) -> int:
    r = math.isqrt(n)
    return r if r * r == n else r + 1

def fermat_factor(n: int, max_iter: int = 5_000_000) -> tuple[int, int, int]:
    if n % 2 == 0:
        return 2, n // 2, 0
    a = ceil_sqrt(n)
    for i in range(max_iter + 1):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p * q == n:
                if p > q:
                    p, q = q, p
                return p, q, i
        a += 1
    raise RuntimeError(f'Fermat factorization did not finish within {max_iter} iterations')

def build_private_key(p: int, q: int, e: int) -> rsa.RSAPrivateKey:
    n = p * q
    phi = (p - 1) * (q - 1)
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

def main() -> None:
    cert = x509.load_pem_x509_certificate(CERT.read_bytes())
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError('Certificate public key is not RSA')
    nums = pub.public_numbers()
    n, e = nums.n, nums.e
    print('[1] Extracted public key from cert.pem')
    print(f'    bits(n) = {n.bit_length()}')
    print(f'    e       = {e}')
    print('[2] Running Fermat factorization...')
    p, q, iters = fermat_factor(n)
    print(f'    done in {iters} iteration(s)')
    print(f'    p bits = {p.bit_length()}, q bits = {q.bit_length()}')
    print(f'    q - p  = {q - p}')
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print('[3] Recovered private exponent')
    print(f'    phi(n) bits = {phi.bit_length()}')
    print(f'    d bits      = {d.bit_length()}')
    key = build_private_key(p, q, e)
    OUT_KEY.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    print(f'[OK] Wrote {OUT_KEY}')
    # sanity check
    rec_pub = key.public_key().public_numbers()
    assert rec_pub.n == n and rec_pub.e == e
    print('[OK] recovered_key.pem matches the certificate public key')

if __name__ == '__main__':
    main()
