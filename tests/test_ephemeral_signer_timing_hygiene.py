"""
Regression tests for aether_protocol_c/ephemeral_signer.py (F-2).

Verifies:
  1. Sign/verify round-trip still works after the modinv / point-mul rewrite.
  2. The rewritten scalar multiplication (_point_mul) performs the SAME
     number of curve operations (adds + doubles) regardless of the secret
     scalar's value -- i.e. it no longer "skips work" on zero bits, which
     was the concrete secret-dependent branching pattern flagged by F-2.
"""

from aether_protocol_c.ephemeral_signer import (
    EphemeralSigner,
    G,
    N,
    _point_add,
    _point_double,
    _point_mul,
)


def test_sign_and_verify_round_trip_still_works():
    # Arrange
    signer = EphemeralSigner(quantum_seed=0xDEADBEEF)
    manifest = {"action": "test", "value": 42}

    # Act
    signature = signer.sign_manifest(manifest)
    ok = signer.verify(manifest, signature)

    # Assert
    assert ok is True


def test_verify_rejects_tampered_manifest():
    # Arrange
    signer = EphemeralSigner(quantum_seed=0xC0FFEE)
    manifest = {"action": "test", "value": 42}
    signature = signer.sign_manifest(manifest)

    # Act
    tampered = {"action": "test", "value": 43}
    ok = signer.verify(tampered, signature)

    # Assert
    assert ok is False


def test_point_mul_operation_count_is_independent_of_scalar_value():
    """
    Pre-fix, _point_mul only called _point_add when a scalar bit was 1,
    so a scalar with few set bits (e.g. 1) took a measurably different
    number of point additions than a scalar with many set bits
    (e.g. N - 1, which is all-but-two bits set). That data-dependent
    operation count is exactly the timing side-channel F-2 flagged.

    Post-fix, the ladder walks a fixed bit_length and performs exactly
    one add + one double per iteration regardless of the bit value, so
    op counts must be identical across scalars.
    """
    # Arrange
    add_calls = {"count": 0}
    double_calls = {"count": 0}

    import aether_protocol_c.ephemeral_signer as signer_mod

    original_add = signer_mod._point_add
    original_double = signer_mod._point_double

    def counting_add(p1, p2):
        add_calls["count"] += 1
        return original_add(p1, p2)

    def counting_double(p):
        double_calls["count"] += 1
        return original_double(p)

    signer_mod._point_add = counting_add
    signer_mod._point_double = counting_double
    try:
        # Act: a scalar with very few set bits ...
        add_calls["count"] = 0
        double_calls["count"] = 0
        signer_mod._point_mul(1, G)
        few_bits_adds = add_calls["count"]
        few_bits_doubles = double_calls["count"]

        # ... vs a scalar with (almost) all bits set ...
        add_calls["count"] = 0
        double_calls["count"] = 0
        signer_mod._point_mul(N - 1, G)
        many_bits_adds = add_calls["count"]
        many_bits_doubles = double_calls["count"]
    finally:
        signer_mod._point_add = original_add
        signer_mod._point_double = original_double

    # Assert: identical operation counts regardless of scalar's bit pattern
    assert few_bits_adds == many_bits_adds == 256
    assert few_bits_doubles == many_bits_doubles == 256


def test_point_mul_matches_known_generator_multiple():
    """Sanity check: 2*G computed via the new ladder matches direct doubling."""
    # Arrange / Act
    via_ladder = _point_mul(2, G)
    via_double = _point_double(G)

    # Assert
    assert via_ladder.x == via_double.x
    assert via_ladder.y == via_double.y
