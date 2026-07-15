"""
tests/test_timestamp_authority_url_validation.py

Regression tests for F-8: RFC3161TimestampAuthority must reject insecure
(plain http://) TSA URLs by default and must reject URLs that resolve to
private/loopback/link-local addresses (SSRF guard).
"""

import pytest

from aether_protocol_c.timestamp_authority import (
    RFC3161TimestampAuthority,
    TimestampError,
)


def test_default_tsa_urls_use_https():
    # Arrange / Act
    tsa = RFC3161TimestampAuthority()

    # Assert
    assert tsa._tsa_url.startswith("https://")
    assert tsa._fallback_url.startswith("https://")


def test_plain_http_tsa_url_rejected_by_default():
    # Arrange
    insecure_url = "http://timestamp.example.com"

    # Act / Assert
    with pytest.raises(TimestampError, match="Insecure TSA URL rejected"):
        RFC3161TimestampAuthority(tsa_url=insecure_url)


def test_plain_http_tsa_url_allowed_with_explicit_opt_in():
    # Arrange
    insecure_url = "http://timestamp.example.com"

    # Act
    tsa = RFC3161TimestampAuthority(
        tsa_url=insecure_url, allow_insecure_http=True
    )

    # Assert: scheme opt-in bypasses the http-rejection error path
    assert tsa._tsa_url == insecure_url


def test_loopback_tsa_url_rejected_even_with_https_scheme():
    # Arrange
    loopback_url = "https://127.0.0.1"

    # Act / Assert
    with pytest.raises(TimestampError, match="disallowed address"):
        RFC3161TimestampAuthority(tsa_url=loopback_url)


def test_link_local_metadata_endpoint_rejected():
    # Arrange: classic cloud metadata SSRF target
    metadata_url = "https://169.254.169.254/latest/meta-data/"

    # Act / Assert
    with pytest.raises(TimestampError, match="disallowed address"):
        RFC3161TimestampAuthority(tsa_url=metadata_url)


def test_private_rfc1918_fallback_url_rejected():
    # Arrange
    private_url = "https://10.0.0.5"

    # Act / Assert
    with pytest.raises(TimestampError, match="disallowed address"):
        RFC3161TimestampAuthority(fallback_url=private_url)


def test_unsupported_scheme_rejected():
    # Arrange
    bad_url = "ftp://timestamp.example.com"

    # Act / Assert
    with pytest.raises(TimestampError, match="must use http"):
        RFC3161TimestampAuthority(tsa_url=bad_url)
