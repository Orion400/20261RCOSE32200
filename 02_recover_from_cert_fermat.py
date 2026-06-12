#!/usr/bin/env python3
"""
Recover the RSA private key from cert.pem when its public modulus n = p*q
was generated from deliberately close primes p and q.
Local educational demo only.
"""
from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tls12_lab.common import CERT_PATH, RECOVERED_KEY_PATH

CERT = CERT_PATH
OUT_KEY = RECOVERED_KEY_PATH
DEFAULT_MAX_ITERATIONS = 5_000_000


@dataclass(frozen=True)
class FermatResult:
    p: int
    q: int
    iterations: int


@dataclass(frozen=True)
class RecoveryResult:
    n: int
    e: int
    p: int
    q: int
    d: int
    iterations: int
    output_key: Path


def ceil_sqrt(n: int) -> int:
    if n < 0:
        raise ValueError('ceil_sqrt is undefined for negative integers')
    r = math.isqrt(n)
    return r if r * r == n else r + 1


def is_perfect_square(n: int) -> tuple[bool, int]:
    if n < 0:
        return False, 0
    root = math.isqrt(n)
    return root * root == n, root


def validate_modulus(n: int) -> None:
    if n <= 1:
        raise ValueError('RSA modulus must be greater than 1')
    if n % 2 == 0:
        raise ValueError('expected an odd RSA modulus for this close-prime lab')


def fermat_factor(n: int, max_iter: int = DEFAULT_MAX_ITERATIONS, progress_interval: int = 0) -> tuple[int, int, int]:
    result = fermat_factor_result(n, max_iter, progress_interval)
    return result.p, result.q, result.iterations


def fermat_factor_result(n: int, max_iter: int = DEFAULT_MAX_ITERATIONS, progress_interval: int = 0) -> FermatResult:
    validate_modulus(n)
    if max_iter < 0:
        raise ValueError('max_iter must be nonnegative')
    if progress_interval < 0:
        raise ValueError('progress_interval must be nonnegative')
    a = ceil_sqrt(n)
    for i in range(max_iter + 1):
        b2 = a * a - n
        square, b = is_perfect_square(b2)
        if square:
            p = a - b
            q = a + b
            if p * q == n:
                if p > q:
                    p, q = q, p
                return FermatResult(p, q, i)
        if progress_interval and i and i % progress_interval == 0:
            print(f'    checked {i} Fermat candidate(s)')
        a += 1
    raise RuntimeError(f'Fermat factorization did not finish within {max_iter} iterations')


def read_rsa_public_numbers(cert_path: Path) -> rsa.RSAPublicNumbers:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError('Certificate public key is not RSA')
    return pub.public_numbers()


def verify_factorization(p: int, q: int, n: int, e: int) -> int:
    if p > q:
        raise ValueError('factor order invariant failed: expected p <= q')
    if p * q != n:
        raise ValueError('recovered factors do not multiply to n')
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError('public exponent is not invertible modulo phi(n)')
    d = pow(e, -1, phi)
    if (e * d) % phi != 1:
        raise ValueError('private exponent inverse check failed')
    return d


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


def self_test_reconstructed_key(key: rsa.RSAPrivateKey) -> None:
    message = b"rsa tls12 lab reconstructed key self-test"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def recover_private_key(cert_path: Path, output_key: Path, max_iterations: int, progress_interval: int = 0) -> RecoveryResult:
    nums = read_rsa_public_numbers(cert_path)
    n, e = nums.n, nums.e
    factors = fermat_factor_result(n, max_iterations, progress_interval)
    d = verify_factorization(factors.p, factors.q, n, e)
    key = build_private_key(factors.p, factors.q, e)
    rec_pub = key.public_key().public_numbers()
    if rec_pub.n != n or rec_pub.e != e:
        raise ValueError('reconstructed public key does not match certificate')
    self_test_reconstructed_key(key)
    output_key.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return RecoveryResult(n, e, factors.p, factors.q, d, factors.iterations, output_key)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Recover the lab RSA key from a close-prime certificate modulus.')
    parser.add_argument('--cert', type=Path, default=CERT, help='certificate to read; default: cert.pem')
    parser.add_argument('--output-key', type=Path, default=OUT_KEY, help='TraditionalOpenSSL PEM output; default: recovered_key.pem')
    parser.add_argument('--max-iterations', type=int, default=DEFAULT_MAX_ITERATIONS, help='bounded Fermat search limit')
    parser.add_argument('--progress-interval', type=int, default=0, help='print progress every N iterations; 0 disables progress')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    nums = read_rsa_public_numbers(args.cert)
    print(f'[1] Extracted public key from {args.cert}')
    print(f'    bits(n) = {nums.n.bit_length()}')
    print(f'    e       = {nums.e}')
    print('[2] Running Fermat factorization...')
    result = recover_private_key(args.cert, args.output_key, args.max_iterations, args.progress_interval)
    print(f'    done in {result.iterations} iteration(s)')
    print(f'    p bits = {result.p.bit_length()}, q bits = {result.q.bit_length()}')
    print(f'    q - p  = {result.q - result.p}')
    print('[3] Recovered private exponent')
    print(f'    phi(n) bits = {((result.p - 1) * (result.q - 1)).bit_length()}')
    print(f'    d bits      = {result.d.bit_length()}')
    print(f'[OK] Wrote {result.output_key}')
    print('[OK] reconstructed key passed a sign/verify self-test')
    print('[OK] recovered_key.pem matches the certificate public key')


if __name__ == '__main__':
    main()
