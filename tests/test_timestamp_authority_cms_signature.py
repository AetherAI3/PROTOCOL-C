"""
tests/test_timestamp_authority_cms_signature.py

Regression tests for F-7: RFC3161TimestampAuthority.verify() must
cryptographically verify the CMS SignerInfo signature over the TSA's
TimeStampToken, not just recompute/compare the messageImprint hash.

Pre-fix, verify() (and stamp()) accepted any well-formed TimeStampResp whose
TSTInfo.messageImprint happened to equal sha256(data) and whose PKIStatus
was granted -- with no check that the response was actually signed by
anyone. That let a malicious/compromised TSA, or an on-path attacker who
can forge DER bytes (no private key required), produce a "valid" token for
arbitrary data. Post-fix, verify() additionally requires the CMS
SignerInfo's signature to verify against the embedded signer certificate's
public key.
"""

import hashlib

import pytest

pyasn1 = pytest.importorskip("pyasn1")
pytest.importorskip("pyasn1_modules")
pytest.importorskip("cryptography")

from tests._rfc3161_test_support import (
    build_signed_timestamp_resp_der,
    build_unsigned_timestamp_resp_der,
    generate_self_signed_tsa_cert,
)

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampToken,
)


def _make_token(tsa: RFC3161TimestampAuthority, resp_der: bytes, digest_hex: str) -> TimestampToken:
    return TimestampToken(
        tsa_url=tsa._tsa_url,
        token_bytes=resp_der,
        token_hex=resp_der.hex(),
        stamped_at=0,
        hash_algorithm="sha-256",
        message_imprint=digest_hex,
    )


def test_verify_accepts_genuinely_signed_tsa_response():
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    key, cert = generate_self_signed_tsa_cert()
    resp_der = build_signed_timestamp_resp_der(digest, key, cert)
    tsa = RFC3161TimestampAuthority()
    token = _make_token(tsa, resp_der, digest.hex())

    # Act
    result = tsa.verify(data, token)

    # Assert
    assert result is True


def test_verify_rejects_response_with_correct_hash_but_no_cms_signature():
    """
    CRITICAL regression (F-7 core case): an attacker who can forge/replay
    DER bytes -- but does not hold the TSA's private key -- builds a
    TimeStampResp with a granted status and a TSTInfo whose messageImprint
    genuinely equals sha256(data), but with no CMS signerInfos at all.

    Pre-fix, verify() only checked the messageImprint hash and passed this.
    Post-fix it must fail because there is no signature to verify.
    """
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    resp_der = build_unsigned_timestamp_resp_der(digest)
    tsa = RFC3161TimestampAuthority()
    token = _make_token(tsa, resp_der, digest.hex())

    # Act
    result = tsa.verify(data, token)

    # Assert
    assert result is False


def test_verify_rejects_response_with_correct_hash_but_corrupted_signature():
    """
    A response with the right hash/status/certificate but a tampered
    signature (e.g. flipped by a MITM, or forged without the private key)
    must fail signature verification.
    """
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    key, cert = generate_self_signed_tsa_cert()
    resp_der = build_signed_timestamp_resp_der(digest, key, cert, corrupt_signature=True)
    tsa = RFC3161TimestampAuthority()
    token = _make_token(tsa, resp_der, digest.hex())

    # Act
    result = tsa.verify(data, token)

    # Assert
    assert result is False


def test_verify_rejects_signature_from_a_different_keypair_than_embedded_cert():
    """
    A signature produced by an attacker's own key, paired with a legitimate
    -looking (but mismatched) certificate, must not verify: the public key
    in the embedded certificate is what's actually used to check the
    signature, so a signature/cert mismatch is caught.
    """
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    _real_key, real_cert = generate_self_signed_tsa_cert()
    attacker_key, _attacker_cert = generate_self_signed_tsa_cert()
    # Sign with the attacker's key, but embed the *real* (unrelated) cert.
    resp_der = build_signed_timestamp_resp_der(digest, attacker_key, real_cert)
    tsa = RFC3161TimestampAuthority()
    token = _make_token(tsa, resp_der, digest.hex())

    # Act
    result = tsa.verify(data, token)

    # Assert
    assert result is False
