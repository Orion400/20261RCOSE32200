from __future__ import annotations

import pytest

from conftest import load_script

recover = load_script("02_recover_from_cert_fermat.py")
make_materials = load_script("01_make_weak_rsa_materials.py")


def test_ceil_sqrt_baseline_values() -> None:
    assert recover.ceil_sqrt(0) == 0
    assert recover.ceil_sqrt(1) == 1
    assert recover.ceil_sqrt(2) == 2
    assert recover.ceil_sqrt(15) == 4
    assert recover.ceil_sqrt(16) == 4


def test_fermat_factor_close_primes_baseline() -> None:
    p, q = 1_000_003, 1_000_033
    got_p, got_q, iterations = recover.fermat_factor(p * q, max_iter=100)
    assert (got_p, got_q) == (p, q)
    assert iterations >= 0


def test_fermat_factor_iteration_exhaustion_baseline() -> None:
    with pytest.raises(RuntimeError, match="did not finish"):
        recover.fermat_factor(101 * 1009, max_iter=0)


def test_small_prime_generation_baseline() -> None:
    assert make_materials.next_prime(14) == 17
    assert make_materials.is_probable_prime(1_000_003)
    assert not make_materials.is_probable_prime(1_000_005)
