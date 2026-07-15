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
pytest.importorskip("pyasn1_modules")
pytest.importorskip("cryptography")

from tests._rfc3161_test_support import (
    build_signed_timestamp_resp_der,
    build_tst_info_der,
    generate_self_signed_tsa_cert,
)

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampError,
)

_TSA_KEY, _TSA_CERT = generate_self_signed_tsa_cert()


def _build_timestamp_resp_der(digest: bytes, nonce) -> bytes:
    """Build a full, decodable, genuinely CMS-signed RFC 3161 TimeStampResp
    whose embedded TSTInfo attests to ``digest`` and (optionally) echoes
    ``nonce``. stamp() now runs the response through verify() (which
    requires a valid CMS signature -- see F-7), so nonce-replay fixtures
    must be genuinely signed too, not just hash/nonce-matching."""
    tst_info_der = build_tst_info_der(digest, nonce=nonce)
    return build_signed_timestamp_resp_der(
        digest, _TSA_KEY, _TSA_CERT, tst_info_der=tst_info_der
    )


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
