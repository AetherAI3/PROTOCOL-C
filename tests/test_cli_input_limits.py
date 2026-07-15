"""
tests/test_cli_input_limits.py -- Regression test for F-9 (unbounded JSON input DoS).

_read_json() previously read the entire file/stdin stream with .read() before
calling json.loads(), with no size cap. This allowed an oversized payload
(file or stdin pipe) to exhaust memory. This test asserts that oversized
input is rejected with a clear error instead of being buffered wholesale.
"""

import io

import pytest

from aether_protocol_c.cli import MAX_JSON_INPUT_BYTES, _read_json


def test_read_json_rejects_oversized_stdin_input(monkeypatch):
    """_read_json raises ValueError when stdin exceeds MAX_JSON_INPUT_BYTES."""
    # Arrange: build a payload just over the size cap.
    oversized = "[" + ("1," * (MAX_JSON_INPUT_BYTES // 2 + 1)) + "1]"
    assert len(oversized) > MAX_JSON_INPUT_BYTES
    monkeypatch.setattr("sys.stdin", io.StringIO(oversized))

    # Act / Assert: reading from stdin (path=None) must raise, not hang or OOM.
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        _read_json(None)


def test_read_json_rejects_oversized_file_input(tmp_path):
    """_read_json raises ValueError when a file exceeds MAX_JSON_INPUT_BYTES."""
    # Arrange
    big_file = tmp_path / "oversized.json"
    oversized = "[" + ("1," * (MAX_JSON_INPUT_BYTES // 2 + 1)) + "1]"
    big_file.write_text(oversized, encoding="utf-8")

    # Act / Assert
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        _read_json(str(big_file))


def test_read_json_accepts_input_within_limit(tmp_path):
    """_read_json still parses normal, well-under-cap JSON input correctly."""
    # Arrange
    small_file = tmp_path / "small.json"
    small_file.write_text('{"hello": "world"}', encoding="utf-8")

    # Act
    result = _read_json(str(small_file))

    # Assert
    assert result == {"hello": "world"}
