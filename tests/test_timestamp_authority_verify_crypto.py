"""
tests/test_timestamp_authority_verify_crypto.py

Regression tests for F-1: RFC3161TimestampAuthority.verify() must
cryptographically parse the TSA's actual TimeStampResp (token_bytes) and
compare the *TSA-signed* messageImprint hash against sha256(data), instead
of trusting the caller-supplied, self-asserted ``message_imprint`` field.

Pre-fix, verify() only compared ``hashlib.sha256(data).hexdigest()`` to
``token.message_imprint`` -- a field ``stamp()`` sets from the input data
itself, never from anything extracted out of the TSA's response. That let
a forged/garbage ``token_bytes`` payload pass verification every time, as
long as ``message_imprint`` was set to match the caller's data.

Note: verify() also now requires the CMS signature over the response to
verify (see F-7 / test_timestamp_authority_cms_signature.py), so the
"genuine" fixture below is genuinely signed, not just hash-matching.
"""

import hashlib

import pytest

pyasn1 = pytest.importorskip("pyasn1")
pytest.importorskip("pyasn1_modules")
pytest.importorskip("cryptography")

from tests._rfc3161_test_support import (
    build_signed_timestamp_resp_der,
    generate_self_signed_tsa_cert,
)

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampToken,
)


def test_verify_accepts_genuine_tsa_response_matching_data():
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    key, cert = generate_self_signed_tsa_cert()
    resp_der = build_signed_timestamp_resp_der(digest, key, cert)
    tsa = RFC3161TimestampAuthority()
    token = TimestampToken(
        tsa_url=tsa._tsa_url,
        token_bytes=resp_der,
        token_hex=resp_der.hex(),
        stamped_at=0,
        hash_algorithm="sha-256",
        message_imprint=digest.hex(),
    )

    # Act
    result = tsa.verify(data, token)

    # Assert
    assert result is True


def test_verify_rejects_forged_token_bytes_with_matching_self_asserted_imprint():
    """
    CRITICAL regression: a network attacker or malicious TSA can return
    arbitrary garbage as token_bytes. Pre-fix, verify() ignored
    token_bytes entirely and only checked the caller-supplied
    message_imprint against sha256(data) -- so this forged token, whose
    token_bytes attest to nothing, passed verification. Post-fix it must
    fail because there is no genuine, parsable TSA attestation.
    """
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    forged_token_bytes = b"\x00\x01\x02not a real TimeStampResp at all"
    tsa = RFC3161TimestampAuthority()
    forged_token = TimestampToken(
        tsa_url=tsa._tsa_url,
        token_bytes=forged_token_bytes,
        token_hex=forged_token_bytes.hex(),
        stamped_at=0,
        hash_algorithm="sha-256",
        # Self-asserted by the attacker/caller to match the data --
        # this is exactly what stamp() would have produced too.
        message_imprint=digest.hex(),
    )

    # Act
    result = tsa.verify(data, forged_token)

    # Assert
    assert result is False


def test_verify_rejects_genuine_response_whose_signed_imprint_is_for_different_data():
    # Arrange: TSA genuinely attested to *other* data, not `data`.
    data = b"legitimate commitment payload"
    other_digest = hashlib.sha256(b"different data entirely").digest()
    key, cert = generate_self_signed_tsa_cert()
    resp_der = build_signed_timestamp_resp_der(other_digest, key, cert)
    tsa = RFC3161TimestampAuthority()
    token = TimestampToken(
        tsa_url=tsa._tsa_url,
        token_bytes=resp_der,
        token_hex=resp_der.hex(),
        stamped_at=0,
        hash_algorithm="sha-256",
        message_imprint=hashlib.sha256(data).hexdigest(),
    )

    # Act
    result = tsa.verify(data, token)

    # Assert
    assert result is False
