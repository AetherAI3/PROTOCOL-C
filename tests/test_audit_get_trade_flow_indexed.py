"""
Regression test for F-23: get_trade_flow() must use the SQLite index
(get_by_id) instead of a full linear scan/parse of the JSONL file
(read_all()/read_by_order_id()).

Prior behavior: get_trade_flow() called read_by_order_id(), which calls
read_all(), performing a full-file scan+parse for every single order
lookup -- even though an O(1) SQLite index already exists.

Fixed behavior: get_trade_flow() looks up each of the three phases via
get_by_id() (indexed seek), never calling read_all()/read_by_order_id().
"""

import os
import tempfile

import pytest

from aether_protocol_c.audit import AuditLog


def _make_signature() -> dict:
    return {"sig": "abc", "public_key": "pub"}


def test_get_trade_flow_does_not_call_read_all():
    # Arrange: a fresh audit log with a full commitment/execution/
    # settlement trio for one order, plus noise from another order.
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.jsonl")
        audit = AuditLog(log_path)
        try:
            audit.append_commitment(
                {"order_id": "order-1", "quantum_seed_commitment": "seed"},
                _make_signature(),
            )
            audit.append_execution(
                {"execution_result": {"order_id": "order-1", "status": "filled"}},
                _make_signature(),
            )
            audit.append_settlement(
                {"order_id": "order-1", "status": "settled"},
                _make_signature(),
            )
            # Noise: another order that should not appear in the flow.
            audit.append_commitment(
                {"order_id": "order-2", "quantum_seed_commitment": "seed2"},
                _make_signature(),
            )

            # Act: force read_all()/read_by_order_id() to fail loudly if
            # get_trade_flow() ever falls back to a full-file scan.
            def _boom(*args, **kwargs):
                raise AssertionError(
                    "get_trade_flow() must not call read_all()/"
                    "read_by_order_id() -- it should use the SQLite index"
                )

            audit.read_all = _boom
            audit.read_by_order_id = _boom

            flow = audit.get_trade_flow("order-1")

            # Assert: indexed lookups still return the correct trade flow.
            assert flow["order_id"] == "order-1"
            assert flow["commitment"]["quantum_seed_commitment"] == "seed"
            assert flow["execution"]["execution_result"]["status"] == "filled"
            assert flow["settlement"]["status"] == "settled"
        finally:
            audit.close()


def test_get_trade_flow_returns_none_fields_for_unknown_order():
    # Arrange: an audit log with no records at all.
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.jsonl")
        audit = AuditLog(log_path)
        try:
            # Act
            flow = audit.get_trade_flow("nonexistent-order")

            # Assert
            assert flow["order_id"] == "nonexistent-order"
            assert flow["commitment"] is None
            assert flow["execution"] is None
            assert flow["settlement"] is None
        finally:
            audit.close()
