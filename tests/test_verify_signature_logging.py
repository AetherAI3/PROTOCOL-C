"""
Regression test for F-11: verify_signature() / EphemeralSigner.verify()
must emit a debug-level diagnostic before returning False on malformed
input, instead of silently swallowing the error with zero logging.
"""

import logging

import aether_protocol_c.crypto as crypto
from aether_protocol_c.ephemeral_signer import EphemeralSigner


def test_verify_signature_logs_diagnostic_on_malformed_envelope(caplog):
    # Arrange: a signature envelope missing required fields entirely,
    # which raises KeyError deep inside EphemeralSigner.verify().
    message = {"foo": "bar"}
    malformed_signature = {"not": "a valid envelope"}

    # Act
    with caplog.at_level(logging.DEBUG):
        result = crypto.verify_signature(message, malformed_signature)

    # Assert: fail-closed behavior is preserved...
    assert result is False
    # ...but now a diagnostic trail exists for operators investigating a
    # dispute (previously: dead silence, per F-11). verify_signature()
    # delegates to EphemeralSigner.verify(), which is where the KeyError
    # is actually raised and logged.
    assert any(
        "verify" in record.getMessage() for record in caplog.records
    ), "expected a debug log entry on malformed input, got none"


def test_ephemeral_signer_verify_logs_diagnostic_on_malformed_pubkey(caplog):
    # Arrange: valid r/s hex but a pubkey hex that is structurally garbage,
    # raising a ValueError while parsing the curve point.
    signer = EphemeralSigner(quantum_seed=42)
    message = {"foo": "bar"}
    bad_signature = {
        "r": "1" * 64,
        "s": "1" * 64,
        "pubkey": "zz",  # not valid hex -> ValueError
    }

    # Act
    with caplog.at_level(logging.DEBUG):
        result = signer.verify(message, bad_signature)
    signer.destroy()

    # Assert
    assert result is False
    assert any(
        "verify" in record.getMessage() for record in caplog.records
    ), "expected a debug log entry from EphemeralSigner.verify() on malformed input"
