"""
tests/test_timestamp_authority_status_code.py

Mutation-testing gap fix (LOOP-12): ``RFC3161TimestampAuthority.verify()``
accepts a TSA response whose ``PKIStatusInfo.status`` is either 0
(granted) or 1 (grantedWithMods) per RFC 3161 -- ``if status not in
(0, 1): return False``. No existing test exercised the
``grantedWithMods`` (status == 1) branch, so a mutant that narrowed the
accepted set to only ``(0,)`` went undetected even though it would
reject every legitimately "granted with modifications" TSA response in
production.

This also guards the complementary direction: an explicitly-rejected
status value (e.g. 2, PKIStatus "rejection") must still be rejected.
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


def _make_token(resp_der: bytes, digest: bytes) -> TimestampToken:
    tsa = RFC3161TimestampAuthority()
    return TimestampToken(
        tsa_url=tsa._tsa_url,
        token_bytes=resp_der,
        token_hex=resp_der.hex(),
        stamped_at=0,
        hash_algorithm="sha-256",
        message_imprint=digest.hex(),
    )


def test_verify_accepts_granted_with_mods_status():
    """status == 1 (grantedWithMods) is a valid RFC 3161 success status."""
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    key, cert = generate_self_signed_tsa_cert()
    resp_der = build_signed_timestamp_resp_der(digest, key, cert, status=1)
    token = _make_token(resp_der, digest)

    tsa = RFC3161TimestampAuthority()
    assert tsa.verify(data, token) is True


def test_verify_rejects_explicit_rejection_status():
    """status == 2 (rejection) must never be accepted."""
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    key, cert = generate_self_signed_tsa_cert()
    resp_der = build_signed_timestamp_resp_der(digest, key, cert, status=2)
    token = _make_token(resp_der, digest)

    tsa = RFC3161TimestampAuthority()
    assert tsa.verify(data, token) is False
