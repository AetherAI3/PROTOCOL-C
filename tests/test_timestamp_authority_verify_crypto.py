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
"""

import hashlib

import pytest

pyasn1 = pytest.importorskip("pyasn1")

from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import tag, univ, useful

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampToken,
)

_SHA256_OID = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
_TST_INFO_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))
_SIGNED_DATA_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))


def _build_message_imprint(digest: bytes) -> univ.Sequence:
    algo_seq = univ.Sequence()
    algo_seq.setComponentByPosition(0, _SHA256_OID)
    imprint = univ.Sequence()
    imprint.setComponentByPosition(0, algo_seq)
    imprint.setComponentByPosition(1, univ.OctetString(digest))
    return imprint


def _build_tst_info_der(digest: bytes) -> bytes:
    """Build a minimal DER-encoded TSTInfo whose messageImprint == digest."""
    tst_info = univ.Sequence()
    tst_info.setComponentByPosition(0, univ.Integer(1))  # version
    tst_info.setComponentByPosition(1, univ.ObjectIdentifier((1, 2, 3)))  # policy
    tst_info.setComponentByPosition(2, _build_message_imprint(digest))
    tst_info.setComponentByPosition(3, univ.Integer(1))  # serialNumber
    tst_info.setComponentByPosition(4, useful.GeneralizedTime("20260101000000Z"))
    return der_encoder.encode(tst_info)


def _build_timestamp_resp_der(digest: bytes) -> bytes:
    """Build a full, decodable RFC 3161 TimeStampResp whose embedded
    TSTInfo genuinely attests to ``digest``."""
    tst_info_der = _build_tst_info_der(digest)

    # encapContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT OCTET STRING }
    econtent = univ.OctetString(tst_info_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )
    encap_content_info = univ.Sequence()
    encap_content_info.setComponentByPosition(0, _TST_INFO_OID)
    encap_content_info.setComponentByPosition(1, econtent)

    # SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    #                           signerInfos }
    signed_data = univ.Sequence()
    signed_data.setComponentByPosition(0, univ.Integer(3))
    signed_data.setComponentByPosition(1, univ.SetOf())
    signed_data.setComponentByPosition(2, encap_content_info)
    signed_data.setComponentByPosition(3, univ.SetOf())
    signed_data_der = der_encoder.encode(signed_data)

    # ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT ANY }
    content = univ.Any(signed_data_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    content_info = univ.Sequence()
    content_info.setComponentByPosition(0, _SIGNED_DATA_OID)
    content_info.setComponentByPosition(1, content)

    # PKIStatusInfo ::= SEQUENCE { status }
    status_info = univ.Sequence()
    status_info.setComponentByPosition(0, univ.Integer(0))  # granted

    # TimeStampResp ::= SEQUENCE { status, timeStampToken }
    resp = univ.Sequence()
    resp.setComponentByPosition(0, status_info)
    resp.setComponentByPosition(1, content_info)

    return der_encoder.encode(resp)


def test_verify_accepts_genuine_tsa_response_matching_data():
    # Arrange
    data = b"legitimate commitment payload"
    digest = hashlib.sha256(data).digest()
    resp_der = _build_timestamp_resp_der(digest)
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
    resp_der = _build_timestamp_resp_der(other_digest)
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
