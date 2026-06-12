from __future__ import annotations

import math

import pytest

from conftest import load_script

recover = load_script("02_recover_from_cert_fermat.py")
make_materials = load_script("01_make_weak_rsa_materials.py")


def test_perfect_square_detection() -> None:
    assert recover.is_perfect_square(0) == (True, 0)
    assert recover.is_perfect_square(81) == (True, 9)
    assert recover.is_perfect_square(82) == (False, 9)
    assert recover.is_perfect_square(-1) == (False, 0)


def test_invalid_ceil_sqrt_input() -> None:
    with pytest.raises(ValueError, match="negative"):
        recover.ceil_sqrt(-4)


def test_invalid_modulus_inputs() -> None:
    with pytest.raises(ValueError, match="greater than 1"):
        recover.fermat_factor_result(1)
    with pytest.raises(ValueError, match="odd RSA modulus"):
        recover.fermat_factor_result(10)


def test_fermat_result_and_inverse_checks() -> None:
    p, q = 65_537, 65_539
    result = recover.fermat_factor_result(p * q, max_iter=10)
    assert result.p * result.q == p * q
    assert result.p <= result.q
    d = recover.verify_factorization(result.p, result.q, p * q, 17)
    phi = (result.p - 1) * (result.q - 1)
    assert math.gcd(17, phi) == 1
    assert (17 * d) % phi == 1


def test_factorization_exhaustion() -> None:
    with pytest.raises(RuntimeError, match="did not finish"):
        recover.fermat_factor_result(101 * 1009, max_iter=0)


def test_build_private_key_public_numbers() -> None:
    p, q = make_materials.make_close_primes(512)
    e = make_materials.E
    key = recover.build_private_key(p, q, e)
    pub = key.public_key().public_numbers()
    assert pub.n == p * q
    assert pub.e == e
    recover.self_test_reconstructed_key(key)


def test_make_close_primes_rejects_invalid_bits() -> None:
    with pytest.raises(ValueError, match="bits"):
        make_materials.make_close_primes(511)
