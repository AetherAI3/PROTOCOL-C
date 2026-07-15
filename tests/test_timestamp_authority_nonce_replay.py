"""
tests/test_timestamp_authority_nonce_replay.py

Regression tests for F-19: RFC3161TimestampAuthority.stamp() must parse the
TSA's TimeStampResp and verify the echoed nonce matches the one sent in the
request, rejecting stale/substituted/replayed responses.

Pre-fix, stamp() never decoded resp_bytes at all -- it built a
TimestampToken using a locally-computed digest_hex, so a captured or
replayed TimeStampResp (with a matching or attacker-chosen message imprint)
for unrelated data could not be distinguished from a fresh response.
"""

from unittest.mock import MagicMock, patch

import pytest

pyasn1 = pytest.importorskip("pyasn1")

from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import tag, univ, useful

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampError,
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


def _build_tst_info_der(digest: bytes, nonce: int | None) -> bytes:
    """Build a DER-encoded TSTInfo, optionally echoing a nonce."""
    from aether_protocol_c.timestamp_authority import TSTInfo

    tst_info = TSTInfo()
    tst_info.setComponentByName("version", univ.Integer(1))
    tst_info.setComponentByName("policy", univ.ObjectIdentifier((1, 2, 3)))
    tst_info.setComponentByName("messageImprint", _build_message_imprint(digest))
    tst_info.setComponentByName("serialNumber", univ.Integer(1))
    tst_info.setComponentByName(
        "genTime", useful.GeneralizedTime("20260101000000Z")
    )
    tst_info.setComponentByName("ordering", univ.Boolean(False))
    if nonce is not None:
        tst_info.setComponentByName("nonce", univ.Integer(nonce))
    return der_encoder.encode(tst_info)


def _build_timestamp_resp_der(digest: bytes, nonce: int | None) -> bytes:
    """Build a full, decodable RFC 3161 TimeStampResp whose embedded
    TSTInfo attests to ``digest`` and (optionally) echoes ``nonce``."""
    tst_info_der = _build_tst_info_der(digest, nonce)

    econtent = univ.OctetString(tst_info_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )
    encap_content_info = univ.Sequence()
    encap_content_info.setComponentByPosition(0, _TST_INFO_OID)
    encap_content_info.setComponentByPosition(1, econtent)

    signed_data = univ.Sequence()
    signed_data.setComponentByPosition(0, univ.Integer(3))
    signed_data.setComponentByPosition(1, univ.SetOf())
    signed_data.setComponentByPosition(2, encap_content_info)
    signed_data.setComponentByPosition(3, univ.SetOf())
    signed_data_der = der_encoder.encode(signed_data)

    content = univ.Any(signed_data_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    content_info = univ.Sequence()
    content_info.setComponentByPosition(0, _SIGNED_DATA_OID)
    content_info.setComponentByPosition(1, content)

    status_info = univ.Sequence()
    status_info.setComponentByPosition(0, univ.Integer(0))  # granted

    resp = univ.Sequence()
    resp.setComponentByPosition(0, status_info)
    resp.setComponentByPosition(1, content_info)

    return der_encoder.encode(resp)


def _make_mock_response(body: bytes):
    mock_resp = MagicMock()
    mock_resp.read.side_effect = lambda n=-1: body[:n] if n and n > 0 else body
    mock_resp.headers = {}
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def test_stamp_rejects_response_with_mismatched_nonce_replay():
    """
    CRITICAL regression: a replayed/stale TimeStampResp for the current
    data's digest but a *different* (stale) nonce must be rejected, since
    it proves the response was not generated for this specific request.
    """
    # Arrange
    data = b"commitment payload"
    tsa = RFC3161TimestampAuthority()
    import hashlib

    digest = hashlib.sha256(data).digest()
    # A stale response with a nonce that can never match the freshly
    # generated random nonce sent by stamp().
    stale_nonce = 0xDEADBEEF
    resp_der = _build_timestamp_resp_der(digest, stale_nonce)
    mock_resp = _make_mock_response(resp_der)

    # Act / Assert: both primary and fallback TSA return the stale
    # replayed response, so stamp() must exhaust retries and raise.
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(TimestampError, match="nonce"):
            tsa.stamp(data)


def test_stamp_rejects_response_missing_nonce_entirely():
    # Arrange
    data = b"commitment payload"
    tsa = RFC3161TimestampAuthority()
    import hashlib

    digest = hashlib.sha256(data).digest()
    resp_der = _build_timestamp_resp_der(digest, nonce=None)
    mock_resp = _make_mock_response(resp_der)

    # Act / Assert
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(TimestampError, match="nonce"):
            tsa.stamp(data)


def test_stamp_accepts_response_with_matching_echoed_nonce():
    # Arrange
    data = b"commitment payload"
    tsa = RFC3161TimestampAuthority()
    import hashlib

    digest = hashlib.sha256(data).digest()
    captured_nonce = {}

    original_build = tsa._build_timestamp_request

    def _capture_build(d):
        req_bytes, nonce_val = original_build(d)
        captured_nonce["value"] = nonce_val
        return req_bytes, nonce_val

    def _urlopen_side_effect(*args, **kwargs):
        # Build the response only after the nonce has been captured, so
        # the mocked TSA can genuinely echo it back.
        resp_der = _build_timestamp_resp_der(digest, captured_nonce["value"])
        return _make_mock_response(resp_der)

    # Act
    with patch.object(tsa, "_build_timestamp_request", side_effect=_capture_build):
        with patch("urllib.request.urlopen", side_effect=_urlopen_side_effect):
            token = tsa.stamp(data)

    # Assert
    assert token.message_imprint == digest.hex()
