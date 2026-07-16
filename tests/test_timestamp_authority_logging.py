"""
tests/test_timestamp_authority_logging.py

Regression tests for F-15: RFC3161TimestampAuthority._send_request must emit
structured log records (TSA host, exception type, elapsed time) on failure,
and must distinguish TLS/certificate errors from generic network errors
instead of silently flattening everything into an undifferentiated string.
"""

import ssl
import urllib.error
from unittest.mock import patch

import pytest

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampError,
)


def test_ssl_error_is_logged_at_error_level_with_host_and_exc_type(caplog):
    # Arrange
    tsa = RFC3161TimestampAuthority()
    cert_exc = ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED")

    # Act
    with caplog.at_level("ERROR", logger="aether_protocol_c.timestamp_authority"):
        with patch("urllib.request.urlopen", side_effect=cert_exc):
            with pytest.raises(TimestampError):
                tsa._send_request(tsa._tsa_url, b"req-bytes")

    # Assert
    assert any(
        tsa._tsa_url in record.message
        and "SSLCertVerificationError" in record.message
        for record in caplog.records
    )


def test_url_error_is_logged_distinctly_from_ssl_error(caplog):
    # Arrange
    tsa = RFC3161TimestampAuthority()
    network_exc = urllib.error.URLError("timed out")

    # Act
    with caplog.at_level("WARNING", logger="aether_protocol_c.timestamp_authority"):
        with patch("urllib.request.urlopen", side_effect=network_exc):
            with pytest.raises(TimestampError):
                tsa._send_request(tsa._tsa_url, b"req-bytes")

    # Assert: logged as a network-level warning, not conflated with a TLS error
    assert any(
        tsa._tsa_url in record.message and "URLError" in record.message
        for record in caplog.records
    )
    assert not any("SSLCertVerificationError" in record.message for record in caplog.records)


def test_unexpected_exception_still_raises_timestamp_error(caplog):
    # Arrange: bare-Exception fallback must remain so unanticipated errors
    # don't propagate unwrapped past this client method.
    tsa = RFC3161TimestampAuthority()

    # Act / Assert
    with patch("urllib.request.urlopen", side_effect=RuntimeError("boom")):
        with pytest.raises(TimestampError, match="boom"):
            tsa._send_request(tsa._tsa_url, b"req-bytes")
