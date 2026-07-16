"""
Regression test for LOOP17-R4-01: AuditLog._append() was not thread-safe.

Prior behavior: the SQLite connection is opened with
check_same_thread=False (signalling multi-thread use is expected), but
no lock protected the read-modify-write of self._line_count, the JSONL
append, and the SQLite index write. Two threads racing on
append_commitment() could both read the same stale self._line_count
before either incremented it, causing two index rows to be written
with the same jsonl_line/offset and corrupting the line index used by
get_trade_flow() -- while one entry's index row silently overwrote the
other via "INSERT OR REPLACE ... record_id", leaving the earlier
physical JSONL line unreachable from the index with no error raised.

Fixed behavior: _append() serializes the whole critical section under
a threading.RLock, so concurrent appends always get distinct,
monotonically increasing line numbers/offsets, and every JSONL line
has a corresponding, correct index row.
"""

import os
import tempfile
import threading

from aether_protocol_c.audit import AuditLog, PHASE_COMMITMENT


def _commitment(order_id: str) -> dict:
    return {
        "order_id": order_id,
        "seed_commitment": "x",
        "key_temporal_window": {},
    }


def test_concurrent_append_commitment_produces_no_duplicate_index_rows():
    """
    Arrange: one AuditLog shared across many threads (as check_same_thread
    =False implies is expected), each appending a distinct order's
    commitment concurrently.
    """
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "audit.jsonl")
        log = AuditLog(log_path)
        n_threads = 40
        errors = []

        def worker(i: int) -> None:
            try:
                log.append_commitment(_commitment(f"order-{i}"), {"sig": "s"})
            except Exception as exc:  # pragma: no cover - diagnostic only
                errors.append(exc)

        # Act
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"append_commitment raised under concurrency: {errors}"

        # Assert: every JSONL line has a distinct offset/line number, and
        # the count of index rows matches the count of JSONL lines --
        # no lost or duplicated index entries from the race.
        with open(log_path, "rb") as f:
            jsonl_lines = [line for line in f if line.strip()]
        assert len(jsonl_lines) == n_threads

        cur = log._conn.execute(
            "SELECT jsonl_line, jsonl_offset FROM audit_index "
            "WHERE record_type = ?",
            (PHASE_COMMITMENT,),
        )
        rows = cur.fetchall()
        assert len(rows) == n_threads, (
            "index row count must match appended entry count -- a race "
            "on _line_count would cause INSERT OR REPLACE collisions "
            "and silently drop rows"
        )

        line_numbers = [r[0] for r in rows]
        offsets = [r[1] for r in rows]
        assert len(set(line_numbers)) == n_threads, (
            "duplicate jsonl_line values indicate two threads read the "
            "same stale self._line_count before either incremented it"
        )
        assert len(set(offsets)) == n_threads, (
            "duplicate jsonl_offset values indicate two threads wrote "
            "to the same file position concurrently"
        )
        assert sorted(line_numbers) == list(range(n_threads))

        log.close()
