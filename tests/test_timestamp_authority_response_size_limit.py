"""
tests/test_timestamp_authority_response_size_limit.py

Regression tests for F-16: RFC3161TimestampAuthority._send_request() must
bound the size of the TSA HTTP response it reads, so a malicious or
compromised TSA endpoint (or a MITM) cannot exhaust caller memory by
streaming an arbitrarily large response body.
"""

from unittest.mock import MagicMock, patch

import pytest

from aether_protocol_c.timestamp_authority import (
    MAX_TSA_RESPONSE_BYTES,
    RFC3161TimestampAuthority,
    TimestampError,
)


def _make_mock_response(body: bytes, content_length: str | None = None):
    """Build a context-manager mock resembling urlopen()'s return value."""
    mock_resp = MagicMock()
    mock_resp.read.side_effect = lambda n=-1: body[:n] if n and n > 0 else body
    headers = {}
    if content_length is not None:
        headers["Content-Length"] = content_length
    mock_resp.headers = headers
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def test_send_request_rejects_oversized_response_body():
    # Arrange: a TSA that streams far more than the allowed response size,
    # with no (or an understated) Content-Length header.
    oversized_body = b"x" * (MAX_TSA_RESPONSE_BYTES + 10)
    mock_resp = _make_mock_response(oversized_body)
    tsa = RFC3161TimestampAuthority()

    # Act / Assert
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(TimestampError, match="exceeded"):
            tsa._send_request(tsa._tsa_url, b"dummy-request-bytes")


def test_send_request_rejects_response_declaring_oversized_content_length():
    # Arrange: TSA declares an oversized Content-Length upfront.
    small_body = b"x" * 10
    mock_resp = _make_mock_response(
        small_body, content_length=str(MAX_TSA_RESPONSE_BYTES + 1)
    )
    tsa = RFC3161TimestampAuthority()

    # Act / Assert
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(TimestampError, match="Content-Length"):
            tsa._send_request(tsa._tsa_url, b"dummy-request-bytes")


def test_send_request_accepts_response_within_size_limit():
    # Arrange: a normal, small RFC 3161 response.
    normal_body = b"y" * 1024
    mock_resp = _make_mock_response(normal_body, content_length="1024")
    tsa = RFC3161TimestampAuthority()

    # Act
    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = tsa._send_request(tsa._tsa_url, b"dummy-request-bytes")

    # Assert
    assert result == normal_body
