"""
Regression test for F-3: _rebuild_index() must not silently swallow
corrupt JSONL lines.

Prior behavior: a corrupt/truncated line encountered while rebuilding
the SQLite index from an existing JSONL file (constructor path, when
the index is empty but the log has content) was silently skipped with
no error, log, or count -- allowing tampered/corrupted audit records to
vanish from query()/get_by_id() without any operator-visible signal.

Fixed behavior: AuditLog() now raises AuditError when it encounters a
corrupt line while rebuilding the index, matching the existing
behavior of read_all().
"""

import json
import os
import tempfile

import pytest

from aether_protocol_c.audit import AuditLog, AuditError, PHASE_COMMITMENT


def _write_line(path: str, obj) -> None:
    with open(path, "a", encoding="utf-8") as f:
        if isinstance(obj, str):
            f.write(obj + "\n")
        else:
            f.write(json.dumps(obj) + "\n")


def _valid_entry_dict(order_id: str) -> dict:
    return {
        "timestamp": 1234567890,
        "phase": PHASE_COMMITMENT,
        "order_id": order_id,
        "data": {"foo": "bar"},
        "signature": {"sig": "abc"},
        "quantum_proof": {"seed_commitment": "x", "key_temporal_window": {}},
    }


def test_rebuild_index_raises_auditerror_on_corrupt_line():
    # Arrange: build a JSONL file with a valid line followed by a
    # corrupt (unparsable JSON) line, with no companion .db index yet.
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.jsonl")

        _write_line(log_path, _valid_entry_dict("order-1"))
        _write_line(log_path, "{not valid json")

        # Act / Assert: opening the log must trigger _rebuild_index()
        # (line_count > 0, index empty) and raise AuditError instead of
        # silently continuing past the corrupt line.
        with pytest.raises(AuditError):
            AuditLog(log_path)


def test_rebuild_index_raises_auditerror_on_missing_key_line():
    # Arrange: a line that is valid JSON but missing a required key.
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.jsonl")

        _write_line(log_path, _valid_entry_dict("order-1"))
        _write_line(log_path, {"timestamp": 1, "phase": PHASE_COMMITMENT})

        # Act / Assert
        with pytest.raises(AuditError):
            AuditLog(log_path)


def test_rebuild_index_succeeds_when_all_lines_valid():
    # Arrange: all lines parse cleanly.
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.jsonl")

        _write_line(log_path, _valid_entry_dict("order-1"))
        _write_line(log_path, _valid_entry_dict("order-2"))

        # Act: should not raise.
        audit = AuditLog(log_path)
        try:
            entries = audit.read_all()
            # Assert
            assert len(entries) == 2
        finally:
            audit.close()
