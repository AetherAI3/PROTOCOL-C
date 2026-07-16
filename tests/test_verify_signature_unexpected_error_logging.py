"""
Regression test for F-27: verify_signature() must not silently swallow an
*unexpected* (non-parsing) exception with a bare `except Exception: return
False` and zero logging. Narrow parsing errors (KeyError/ValueError/TypeError)
were already covered by F-11; this test targets the separate catch-all branch
that guards truly unexpected failures (e.g. a bug unrelated to malformed
input), which must still be logged so operators can distinguish "our bug"
from "genuine tampering".
"""

import logging

import aether_protocol_c.crypto as crypto


def test_verify_signature_logs_diagnostic_on_unexpected_error(caplog, monkeypatch):
    # Arrange: force EphemeralSigner.verify_static to raise an exception type
    # that is NOT one of the narrowly-handled parsing errors, simulating an
    # unrelated bug surfacing during verification.
    def _boom(message, signature):
        raise RuntimeError("unexpected internal failure")

    monkeypatch.setattr(
        crypto.EphemeralSigner, "verify_static", staticmethod(_boom)
    )

    message = {"foo": "bar"}
    signature = {"r": "1" * 64, "s": "1" * 64, "pubkey": "02" + "1" * 64}

    # Act
    with caplog.at_level(logging.DEBUG):
        result = crypto.verify_signature(message, signature)

    # Assert: still fails closed...
    assert result is False
    # ...but the unexpected error is logged, not silently mapped to "invalid
    # signature" indistinguishable from real tampering (F-27).
    assert any(
        "unexpected" in record.getMessage() for record in caplog.records
    ), "expected a debug log entry for the unexpected-error branch, got none"
