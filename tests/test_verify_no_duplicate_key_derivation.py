"""
Regression test for F-26: QuantumEphemeralKey.verify() and the module-level
crypto.verify_signature() must not each construct their own throwaway
EphemeralSigner(quantum_seed=1) instance just to call .verify() -- that
needlessly derives a private key and performs an EC point multiplication.

Both should delegate to a single, lightweight verification path
(EphemeralSigner.verify_static) that only parses the pubkey embedded in the
signature envelope, with no private-key derivation.
"""

from unittest.mock import patch

import aether_protocol_c.crypto as crypto
from aether_protocol_c.crypto import QuantumEphemeralKey, verify_signature
from aether_protocol_c.ephemeral_signer import EphemeralSigner


def _make_valid_signature():
    # Arrange: sign a message with a real ephemeral key so we have a
    # well-formed signature envelope to verify against.
    key = QuantumEphemeralKey(quantum_seed=12345, method="CSPRNG")
    message = {"amount": 100, "asset": "BTC"}
    signature = key.sign(message)
    return message, signature


def test_verify_signature_does_not_instantiate_ephemeral_signer():
    # Arrange
    message, signature = _make_valid_signature()

    # Act / Assert: verify_signature() must not construct a throwaway
    # EphemeralSigner (which would derive a private key) -- it should only
    # call the lightweight static verifier.
    with patch.object(
        EphemeralSigner, "__init__", side_effect=AssertionError(
            "verify_signature() must not instantiate EphemeralSigner"
        ),
    ):
        result = verify_signature(message, signature)

    assert result is True


def test_quantum_ephemeral_key_verify_does_not_instantiate_ephemeral_signer():
    # Arrange: construct the verifier key *before* patching, since key
    # construction legitimately derives its own signing key -- only the
    # subsequent .verify() call is under test.
    message, signature = _make_valid_signature()
    verifier_key = QuantumEphemeralKey(quantum_seed=1)

    # Act / Assert: QuantumEphemeralKey.verify() must delegate to the same
    # lightweight path rather than duplicating its own throwaway signer.
    with patch.object(
        EphemeralSigner, "__init__", side_effect=AssertionError(
            "QuantumEphemeralKey.verify() must not instantiate EphemeralSigner"
        ),
    ):
        result = verifier_key.verify(message, signature)

    assert result is True


def test_verify_static_is_callable_without_any_instance():
    # Arrange
    message, signature = _make_valid_signature()

    # Act: EphemeralSigner.verify_static() should be usable directly as a
    # staticmethod, with no instance / private key required at all.
    result = EphemeralSigner.verify_static(message, signature)

    # Assert
    assert result is True


def test_quantum_ephemeral_key_verify_delegates_to_module_verify_signature():
    # Arrange
    message, signature = _make_valid_signature()

    # Act: QuantumEphemeralKey.verify() should produce the same result as
    # the module-level verify_signature() it delegates to (no duplicated
    # divergent implementation).
    instance_result = QuantumEphemeralKey(quantum_seed=1).verify(message, signature)
    module_result = crypto.verify_signature(message, signature)

    # Assert
    assert instance_result is True
    assert module_result is True
