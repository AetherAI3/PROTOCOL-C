"""
aether_protocol_c/audit.py

Quantum-safe immutable audit log.

Append-only JSONL persistence of all trade decisions, executions, and
settlements.  Every entry includes quantum proof metadata (seed
commitment hash + temporal window) proving the signing key was
quantum-derived and destroyed within a documented window.

Format:
    Each line is a complete JSON object:
    {
        "timestamp": <unix_ts>,
        "phase": "DECISION_COMMITMENT" | "EXECUTION_ATTESTATION" | "SETTLEMENT_FINALITY",
        "order_id": "...",
        "data": { ... phase-specific payload ... },
        "signature": { ... signature envelope ... },
        "quantum_proof": {
            "seed_commitment": "sha256_hex",
            "key_temporal_window": {
                "created_at": <unix_ts>,
                "expires_at": <unix_ts>,
                "shor_earliest_attack": <unix_ts>
            }
        }
    }

Indexing:
    A companion SQLite database (same directory, .db suffix) provides
    fast O(1) lookups by record_id and filtered queries by record_type,
    timestamp range, or seed_method.  The JSONL file remains the source
    of truth; SQLite stores byte offsets for direct seeks.

Rotation:
    When the JSONL file exceeds max_file_size_mb (default 100 MB), both
    the JSONL and SQLite files are archived with a timestamp suffix and
    fresh files are created.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditError(Exception):
    """Raised when audit log operations fail."""


# Phase labels
PHASE_COMMITMENT = "DECISION_COMMITMENT"
PHASE_EXECUTION = "EXECUTION_ATTESTATION"
PHASE_SETTLEMENT = "SETTLEMENT_FINALITY"


@dataclass
class AuditEntry:
    """
    A single entry in the quantum audit log.

    Fields:
        timestamp: Unix timestamp of when the entry was created.
        phase: One of the PHASE_* constants.
        order_id: The order this entry pertains to.
        data: Phase-specific payload dict.
        signature: Signature envelope dict.
        quantum_proof: Quantum proof metadata dict.
    """

    timestamp: int
    phase: str
    order_id: str
    data: dict
    signature: dict
    quantum_proof: dict

    def to_json(self) -> dict:
        """Convert to JSON-serialisable dict."""
        return {
            "timestamp": self.timestamp,
            "phase": self.phase,
            "order_id": self.order_id,
            "data": self.data,
            "signature": self.signature,
            "quantum_proof": self.quantum_proof,
        }

    @staticmethod
    def from_dict(d: dict) -> "AuditEntry":
        """Reconstruct from dict.

        Raises:
            AuditError: if required keys are missing or the `data`,
                `signature`, or `quantum_proof` fields are not dicts.
                This keeps malformed/tampered JSONL lines from silently
                propagating non-dict values into downstream verification
                code, which would otherwise crash with an unhandled
                AttributeError instead of a clean tamper report.
        """
        try:
            data = d["data"]
            signature = d["signature"]
            quantum_proof = d["quantum_proof"]
            entry = AuditEntry(
                timestamp=d["timestamp"],
                phase=d["phase"],
                order_id=d["order_id"],
                data=data,
                signature=signature,
                quantum_proof=quantum_proof,
            )
        except KeyError as exc:
            raise AuditError(f"Malformed audit entry: missing key {exc}") from exc

        for field_name in ("data", "signature", "quantum_proof"):
            value = getattr(entry, field_name)
            if not isinstance(value, dict):
                raise AuditError(
                    f"Malformed audit entry: field '{field_name}' must be a "
                    f"dict, got {type(value).__name__}"
                )

        return entry


def _extract_quantum_proof(data: dict) -> dict:
    """
    Extract quantum proof metadata from a phase payload.

    Looks for seed commitment and temporal window in the data dict.
    Handles commitment, execution, and settlement payloads.

    Args:
        data: The phase-specific payload dict.

    Returns:
        Quantum proof dict with seed_commitment and key_temporal_window.
    """
    # Try commitment fields
    seed = (
        data.get("quantum_seed_commitment")
        or data.get("execution_quantum_seed_commitment")
        or data.get("settlement_quantum_seed_commitment")
        or ""
    )

    window = (
        data.get("key_temporal_window")
        or data.get("settlement_temporal_window")
        or {}
    )

    return {
        "seed_commitment": seed,
        "key_temporal_window": window,
    }


class AuditLog:
    """
    Append-only JSONL audit log with quantum proof metadata.

    Each line is a complete JSON object.  The log is never modified
    or deleted -- only appended to.

    A companion SQLite database provides fast indexed lookups without
    requiring full JSONL scans.  The JSONL file remains the source of
    truth; the SQLite index stores byte offsets for direct seeks.

    Args:
        log_path: Path to the JSONL log file.
        max_file_size_mb: Maximum JSONL file size before rotation
            (default 100 MB).  Set to 0 for tests to force rotation.
    """

    def __init__(
        self,
        log_path: str | Path,
        max_file_size_mb: int = 100,
    ) -> None:
        """
        Initialise the audit log.

        Args:
            log_path: File path for the JSONL log.  Created if it doesn't exist.
            max_file_size_mb: Maximum file size in MB before log rotation.
        """
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()

        self._max_file_size = max_file_size_mb * 1024 * 1024
        self._db_path = self._path.with_suffix(".db")

        # Set before _init_db so close()/__del__ are safe even if init fails.
        self._conn = None

        # Initialise SQLite index
        self._init_db()

        # Count existing lines for line numbering
        self._line_count = self._count_lines()

        # Rebuild index if SQLite is empty but JSONL has content
        if self._line_count > 0 and self._index_is_empty():
            self._rebuild_index()

    @property
    def path(self) -> Path:
        """Return the log file path."""
        return self._path

    # ── SQLite index management ──────────────────────────────────────

    def _init_db(self) -> None:
        """Create or connect to the SQLite index database."""
        self._conn = sqlite3.connect(
            str(self._db_path), check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_index (
                record_id     TEXT PRIMARY KEY,
                record_type   TEXT NOT NULL,
                timestamp     REAL NOT NULL,
                decision_hash TEXT NOT NULL,
                seed_method   TEXT,
                jsonl_offset  INTEGER NOT NULL,
                jsonl_line    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_record_type
                ON audit_index(record_type);
            CREATE INDEX IF NOT EXISTS idx_timestamp
                ON audit_index(timestamp);
            CREATE INDEX IF NOT EXISTS idx_seed_method
                ON audit_index(seed_method);
        """)
        self._conn.commit()

    def _index_is_empty(self) -> bool:
        """Check whether the SQLite index has any rows."""
        cur = self._conn.execute("SELECT COUNT(*) FROM audit_index")
        return cur.fetchone()[0] == 0

    def close(self) -> None:
        """Close the SQLite index connection. Idempotent and safe to call twice."""
        conn = getattr(self, "_conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._conn = None

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort cleanup; never raise from a finalizer.
        try:
            self.close()
        except Exception:
            pass

    def _count_lines(self) -> int:
        """Count existing lines in the JSONL file."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return 0
        count = 0
        with open(self._path, "rb") as f:
            for _ in f:
                count += 1
        return count

    def _rebuild_index(self) -> None:
        """Full-scan JSONL and populate SQLite index for existing data."""
        with open(self._path, "rb") as f:
            line_num = 0
            while True:
                offset = f.tell()
                raw = f.readline()
                if not raw:
                    break
                line_text = raw.decode("utf-8").strip()
                if not line_text:
                    continue
                try:
                    data = json.loads(line_text)
                    entry = AuditEntry.from_dict(data)
                    self._index_entry(entry, offset, line_num)
                    line_num += 1
                except (json.JSONDecodeError, KeyError) as exc:
                    self._conn.commit()
                    raise AuditError(
                        f"Corrupt audit log entry at line {line_num} "
                        f"while rebuilding index: {exc}"
                    ) from exc
        self._conn.commit()

    def _index_entry(
        self, entry: AuditEntry, offset: int, line_num: int
    ) -> None:
        """Write a single index row to SQLite (does NOT commit)."""
        record_id = f"{entry.order_id}_{entry.phase}"
        decision_hash = hashlib.sha256(
            json.dumps(
                entry.data, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        seed_method = entry.data.get("seed_measurement_method")

        self._conn.execute(
            "INSERT OR REPLACE INTO audit_index "
            "(record_id, record_type, timestamp, decision_hash, "
            " seed_method, jsonl_offset, jsonl_line) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record_id,
                entry.phase,
                float(entry.timestamp),
                decision_hash,
                seed_method,
                offset,
                line_num,
            ),
        )

    # ── Log rotation ─────────────────────────────────────────────────

    def _maybe_rotate(self) -> None:
        """Rotate the log if it exceeds the configured maximum size."""
        if self._max_file_size <= 0 and self._line_count > 0:
            # max_file_size_mb=0 means rotate on every append after the first
            self._rotate()
            return
        if (
            self._max_file_size > 0
            and self._path.exists()
            and self._path.stat().st_size >= self._max_file_size
        ):
            self._rotate()

    def _rotate(self) -> None:
        """
        Archive current JSONL + SQLite and create fresh files.

        Archives are named with a timestamp suffix:
            audit_20260316_143000.jsonl / audit_20260316_143000.db
        """
        # Use high-precision timestamp to avoid collisions on fast rotations
        ts = f"{time.strftime('%Y%m%d_%H%M%S')}_{int(time.time() * 1000) % 1000:03d}"

        # Close existing SQLite connection
        self._conn.close()
        self._conn = None

        # Build archive names
        archived_jsonl = self._path.parent / f"{self._path.stem}_{ts}.jsonl"
        archived_db = self._path.parent / f"{self._db_path.stem}_{ts}.db"

        # Rename current files (use replace for Windows compatibility)
        self._path.replace(archived_jsonl)
        if self._db_path.exists():
            self._db_path.replace(archived_db)

        # Create fresh files
        self._path.touch()
        self._init_db()
        self._line_count = 0

        # Write rotation event as first entry in new log
        rotation_entry = AuditEntry(
            timestamp=int(time.time()),
            phase="LOG_ROTATION",
            order_id="__system__",
            data={
                "previous_log": archived_jsonl.name,
                "previous_db": archived_db.name,
            },
            signature={},
            quantum_proof={},
        )
        self._append(rotation_entry)

    def list_archives(self) -> list[str]:
        """
        Return sorted list of archived JSONL filenames in the log directory.

        Returns:
            List of archive filenames (e.g. ["audit_20260316_143000.jsonl"]).
        """
        parent = self._path.parent
        stem = self._path.stem
        archives = sorted(
            p.name for p in parent.glob(f"{stem}_*.jsonl")
        )
        return archives

    # ── Core append ──────────────────────────────────────────────────

    def _append(self, entry: AuditEntry) -> None:
        """
        Append a single entry to the log.

        Writes to the JSONL file (binary mode for reliable byte offsets)
        and indexes the entry in SQLite.
        """
        # Check rotation before writing (but not for rotation entries
        # themselves, to avoid infinite recursion)
        if entry.phase != "LOG_ROTATION":
            self._maybe_rotate()

        line = json.dumps(
            entry.to_json(), sort_keys=True, separators=(",", ":")
        )

        # Write to JSONL in binary mode for reliable byte offsets
        with open(self._path, "ab") as f:
            offset = f.tell()
            f.write((line + "\n").encode("utf-8"))

        # Index in SQLite
        self._index_entry(entry, offset, self._line_count)
        self._conn.commit()
        self._line_count += 1

    def append_commitment(
        self, commitment: dict, signature: dict
    ) -> None:
        """
        Log a quantum decision commitment.

        Args:
            commitment: The commitment dict (with quantum_seed_commitment, etc.).
            signature: The signature envelope.

        Raises:
            AuditError: If order_id is missing.
        """
        order_id = commitment.get("order_id")
        if not order_id:
            raise AuditError("Commitment must contain an order_id")

        entry = AuditEntry(
            timestamp=int(time.time()),
            phase=PHASE_COMMITMENT,
            order_id=order_id,
            data=commitment,
            signature=signature,
            quantum_proof=_extract_quantum_proof(commitment),
        )
        self._append(entry)

    def append_execution(
        self, execution: dict, signature: dict
    ) -> None:
        """
        Log a quantum execution attestation.

        Args:
            execution: The execution attestation dict.
            signature: The signature envelope.

        Raises:
            AuditError: If order_id cannot be determined.
        """
        exec_result = execution.get("execution_result", {})
        order_id = exec_result.get("order_id", "")
        if not order_id:
            raise AuditError("Execution must contain order_id in execution_result")

        entry = AuditEntry(
            timestamp=int(time.time()),
            phase=PHASE_EXECUTION,
            order_id=order_id,
            data=execution,
            signature=signature,
            quantum_proof=_extract_quantum_proof(execution),
        )
        self._append(entry)

    def append_settlement(
        self, settlement: dict, signature: dict
    ) -> None:
        """
        Log a quantum settlement finality record.

        Args:
            settlement: The settlement dict.
            signature: The signature envelope.

        Raises:
            AuditError: If order_id is missing.
        """
        order_id = settlement.get("order_id")
        if not order_id:
            raise AuditError("Settlement must contain an order_id")

        entry = AuditEntry(
            timestamp=int(time.time()),
            phase=PHASE_SETTLEMENT,
            order_id=order_id,
            data=settlement,
            signature=signature,
            quantum_proof=_extract_quantum_proof(settlement),
        )
        self._append(entry)

    # ── Read methods ─────────────────────────────────────────────────

    def read_all(self) -> List[AuditEntry]:
        """Read all entries from the log."""
        entries: List[AuditEntry] = []
        if not self._path.exists():
            return entries

        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry.from_dict(data))
                except (json.JSONDecodeError, KeyError) as exc:
                    raise AuditError(f"Corrupt audit log entry: {exc}") from exc

        return entries

    def read_by_order_id(self, order_id: str) -> List[AuditEntry]:
        """Read all entries for a specific order."""
        return [e for e in self.read_all() if e.order_id == order_id]

    def get_trade_flow(self, order_id: str) -> dict:
        """
        Get the complete trade flow for an order.

        Returns a dict with commitment, execution, and settlement
        phases (if they exist).

        Args:
            order_id: The order to retrieve.

        Returns:
            Dict with data and signature for each phase.
        """
        flow: Dict[str, Any] = {
            "order_id": order_id,
            "commitment": None,
            "commitment_sig": None,
            "commitment_quantum_proof": None,
            "execution": None,
            "execution_sig": None,
            "execution_quantum_proof": None,
            "settlement": None,
            "settlement_sig": None,
            "settlement_quantum_proof": None,
        }

        phase_to_keys = {
            PHASE_COMMITMENT: ("commitment", "commitment_sig", "commitment_quantum_proof"),
            PHASE_EXECUTION: ("execution", "execution_sig", "execution_quantum_proof"),
            PHASE_SETTLEMENT: ("settlement", "settlement_sig", "settlement_quantum_proof"),
        }

        for phase, (data_key, sig_key, proof_key) in phase_to_keys.items():
            record = self.get_by_id(f"{order_id}_{phase}")
            if record is None:
                continue
            try:
                entry = AuditEntry.from_dict(record)
            except (KeyError, TypeError) as exc:
                raise AuditError(f"Corrupt audit log entry: {exc}") from exc
            flow[data_key] = entry.data
            flow[sig_key] = entry.signature
            flow[proof_key] = entry.quantum_proof

        return flow

    # ── Indexed query methods ────────────────────────────────────────

    def query(
        self,
        record_type: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        seed_method: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Query the audit log using the SQLite index.

        Uses indexed lookups to find matching records, then seeks
        directly to their byte offsets in the JSONL file.  Never
        full-scans the JSONL.

        Args:
            record_type: Filter by phase label (e.g. "DECISION_COMMITMENT").
            since: Minimum unix timestamp (inclusive).
            until: Maximum unix timestamp (inclusive).
            seed_method: Filter by seed measurement method.
            limit: Maximum number of results (default 100).

        Returns:
            List of parsed record dicts from the JSONL file.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if record_type is not None:
            conditions.append("record_type = ?")
            params.append(record_type)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            conditions.append("timestamp <= ?")
            params.append(until)
        if seed_method is not None:
            conditions.append("seed_method = ?")
            params.append(seed_method)

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        sql = (
            f"SELECT jsonl_offset FROM audit_index {where} "
            f"ORDER BY timestamp ASC LIMIT ?"
        )
        params.append(limit)

        cur = self._conn.execute(sql, params)
        offsets = [row[0] for row in cur.fetchall()]

        results: list[dict] = []
        if not offsets:
            return results

        with open(self._path, "rb") as f:
            for offset in offsets:
                f.seek(offset)
                raw = f.readline()
                if raw:
                    try:
                        results.append(json.loads(raw.decode("utf-8")))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue

        return results

    def get_by_id(self, record_id: str) -> dict | None:
        """
        Retrieve a single record by its record_id.

        Uses the SQLite primary key index for O(1) lookup, then
        seeks directly to the byte offset in the JSONL file.

        Args:
            record_id: The record identifier (e.g. "order_001_DECISION_COMMITMENT").

        Returns:
            Parsed record dict, or None if not found.
        """
        cur = self._conn.execute(
            "SELECT jsonl_offset FROM audit_index WHERE record_id = ?",
            (record_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None

        offset = row[0]
        with open(self._path, "rb") as f:
            f.seek(offset)
            raw = f.readline()
            if raw:
                try:
                    return json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return None
        return None
