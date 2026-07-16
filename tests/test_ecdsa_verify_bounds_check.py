"""
tests/test_ecdsa_verify_bounds_check.py

Mutation-testing gap fix (LOOP-12): `_ecdsa_verify`'s range guard
``if not (1 <= r < N and 1 <= s < N): return False`` must reject a
signature when *either* component is out of range, not only when
*both* are. A mutant that flips the ``and`` to ``or`` only rejects
when both r and s are out of range, silently accepting a signature
with one malformed component -- this was not caught by the existing
suite because no test exercised r or s individually out of bounds
alongside a validly-shaped counterpart.
"""

import hashlib

from aether_protocol_c.ephemeral_signer import (
    N,
    P,
    EphemeralSigner,
    _ecdsa_verify,
    _Point,
)


def _valid_pubkey_and_hash():
    signer = EphemeralSigner(quantum_seed=42)
    manifest = {"foo": "bar"}
    sig = signer.sign_manifest(manifest)
    r = int(sig["r"], 16)
    s = int(sig["s"], 16)
    canonical = '{"foo":"bar"}'
    msg_hash = hashlib.sha256(canonical.encode("utf-8")).digest()
    pubkey_hex = sig["pubkey"]
    x = int(pubkey_hex[2:], 16)
    prefix = int(pubkey_hex[:2], 16)

    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if y % 2 != (prefix - 2):
        y = P - y
    pubkey = _Point(x, y)
    signer.destroy()
    return pubkey, msg_hash, r, s


def test_ecdsa_verify_rejects_r_out_of_range_even_when_s_is_valid():
    """r == 0 (out of [1, N)) must be rejected regardless of s's validity."""
    pubkey, msg_hash, _r, s = _valid_pubkey_and_hash()
    assert _ecdsa_verify(pubkey, msg_hash, 0, s) is False


def test_ecdsa_verify_rejects_r_at_or_above_n_even_when_s_is_valid():
    pubkey, msg_hash, _r, s = _valid_pubkey_and_hash()
    assert _ecdsa_verify(pubkey, msg_hash, N, s) is False


def test_ecdsa_verify_rejects_s_out_of_range_even_when_r_is_valid():
    """s == 0 (out of [1, N)) must be rejected regardless of r's validity."""
    pubkey, msg_hash, r, _s = _valid_pubkey_and_hash()
    assert _ecdsa_verify(pubkey, msg_hash, r, 0) is False


def test_ecdsa_verify_rejects_s_at_or_above_n_even_when_r_is_valid():
    pubkey, msg_hash, r, _s = _valid_pubkey_and_hash()
    assert _ecdsa_verify(pubkey, msg_hash, r, N) is False
