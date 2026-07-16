"""
Regression test for aether_protocol_c/ephemeral_signer.py (F-28).

F-28 flagged that _point_mul (secret-scalar EC multiplication) and the
_modinv it relies on are hand-rolled, variable-time pure-Python code:
before the F-2 fix, _modinv used the extended Euclidean algorithm, whose
recursion depth/branch pattern varies with the operand (including secret
scalars/nonces), and _point_mul skipped work on zero bits. Both were
folded into a fixed-shape rewrite (see test_ephemeral_signer_timing_hygiene.py
for the _point_mul side).

This test locks in the _modinv side of that fix: it must be implemented
via Python's built-in fixed-shape modular exponentiation (`pow(a, m-2, m)`)
rather than a hand-rolled branchy extended-Euclidean loop, and it must
still compute correct modular inverses.
"""

import inspect

from aether_protocol_c.ephemeral_signer import N, P, _modinv


def test_modinv_computes_correct_inverse_mod_p():
    # Arrange
    a = 12345678901234567890

    # Act
    inv = _modinv(a, P)

    # Assert
    assert (a * inv) % P == 1


def test_modinv_computes_correct_inverse_mod_n():
    # Arrange
    a = 98765432109876543210

    # Act
    inv = _modinv(a, N)

    # Assert
    assert (a * inv) % N == 1


def test_modinv_rejects_zero_with_no_inverse():
    # Arrange / Act / Assert
    try:
        _modinv(0, P)
        assert False, "expected ValueError for a value with no modular inverse"
    except ValueError:
        pass


def test_modinv_uses_fixed_shape_pow_not_branchy_extended_euclidean():
    """
    Source-shape guard: _modinv must delegate to the built-in `pow()`
    (fixed-shape binary exponentiation, no operand-dependent branching)
    rather than a hand-rolled extended Euclidean algorithm, whose
    recursion/branch pattern is exactly the timing side-channel F-28
    flagged for scalars derived from secret key/nonce material.
    """
    # Arrange
    source = inspect.getsource(_modinv)

    # Act / Assert
    assert "pow(" in source
    # No manual recursive/iterative gcd-style branching left in the body.
    assert "while" not in source
    assert "def gcd" not in source
