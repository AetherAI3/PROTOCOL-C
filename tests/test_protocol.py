"""
tests/test_protocol.py

Comprehensive test suite for aether-protocol-c.
30+ tests covering all protocol layers.
"""

import hashlib
import json
import os
import tempfile
import time

import pytest

# ── Import the package ──────────────────────────────────────────────────────

from aether_protocol_c import (
    commit,
    verify,
    batch_commit,
    get_seed,
    __version__,
)
from aether_protocol_c.ephemeral_signer import EphemeralSigner
from aether_protocol_c.crypto import (
    QuantumEphemeralKey,
    QuantumSeedCommitment,
    verify_signature,
    make_temporal_window,
    SHOR_EARLIEST_ATTACK_SECONDS,
    DEFAULT_KEY_LIFETIME_SECONDS,
    QuantumCryptoError,
    KeyDestroyedError,
)
from aether_protocol_c.state import AccountSnapshot, QuantumStateSnapshot, StateError
from aether_protocol_c.commitment import (
    QuantumDecisionCommitment,
    QuantumCommitmentVerifier,
    ReasoningCapture,
    CommitmentError,
)
from aether_protocol_c.execution import (
    ExecutionResult,
    QuantumExecutionAttestation,
    QuantumExecutionVerifier,
)
from aether_protocol_c.settlement import (
    QuantumSettlementRecord,
    QuantumSettlementVerifier,
    compute_flow_merkle,
)
from aether_protocol_c.audit import AuditLog, AuditEntry, PHASE_COMMITMENT
from aether_protocol_c.seed import (
    QuantumSeedResult,
    generate_quantum_seed,
)
from aether_protocol_c.verify import AuditVerifier


# ── Fixtures ─────────────────────────────────────────────────────────────────

ACCOUNT_STATE = {
    "capital": 100_000,
    "equity": 100_000,
    "open_positions": [],
    "risk_used": 0.0,
    "risk_limit": 1.0,
    "nonce": 1,
    "timestamp": int(time.time()),
}

TRADE_DETAILS = {
    "symbol": "BTC",
    "qty": 1,
    "side": "long",
    "price": 50_000,
}


@pytest.fixture
def seed():
    return get_seed()


@pytest.fixture
def temp_audit_path():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "test_audit.jsonl")
    yield path


# ═══════════════════════════════════════════════════════════════════════════
# 1. VERSION
# ═══════════════════════════════════════════════════════════════════════════

def test_version():
    assert __version__ == "0.1.0"


# ═══════════════════════════════════════════════════════════════════════════
# 2. SEED GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def test_get_seed_returns_csprng():
    s = get_seed()
    assert s.method == "CSPRNG"
    assert s.seed_int > 0
    assert len(s.seed_hash) == 64


def test_get_seed_unique():
    seeds = [get_seed() for _ in range(10)]
    hashes = {s.seed_hash for s in seeds}
    assert len(hashes) == 10, "Seeds should be unique"


def test_seed_result_to_dict():
    s = get_seed()
    d = s.to_dict()
    assert d["method"] == "CSPRNG"
    assert "seed_hash" in d


def test_generate_quantum_seed_ignores_requested_method():
    r = generate_quantum_seed(method="anything")
    assert r.method == "CSPRNG", "Protocol-C always returns CSPRNG"


# ═══════════════════════════════════════════════════════════════════════════
# 3. EPHEMERAL SIGNER
# ═══════════════════════════════════════════════════════════════════════════

def test_ephemeral_signer_sign_verify():
    signer = EphemeralSigner(quantum_seed=42)
    msg = {"hello": "world"}
    sig = signer.sign_manifest(msg)
    assert signer.verify(msg, sig)


def test_ephemeral_signer_destroy():
    signer = EphemeralSigner(quantum_seed=99)
    assert not signer.is_destroyed
    receipt = signer.destroy()
    assert signer.is_destroyed
    assert receipt["destroyed"]


def test_ephemeral_signer_sign_after_destroy_raises():
    signer = EphemeralSigner(quantum_seed=77)
    signer.destroy()
    with pytest.raises(RuntimeError, match="destroyed"):
        signer.sign_manifest({"test": True})


def test_ephemeral_signer_deterministic():
    s1 = EphemeralSigner(quantum_seed=123)
    s2 = EphemeralSigner(quantum_seed=123)
    msg = {"data": "test"}
    sig1 = s1.sign_manifest(msg)
    sig2 = s2.sign_manifest(msg)
    assert sig1["r"] == sig2["r"]
    assert sig1["s"] == sig2["s"]


def test_ephemeral_signer_zero_key_never_falls_back_to_known_constant(monkeypatch):
    """
    Regression test for F-5: when HMAC-derived key material reduces to 0 mod N,
    the signer must NOT fall back to the hardcoded, publicly-known private key
    of 1 (which would make pubkey == G and any signature trivially forgeable).
    Instead it must re-derive deterministically via a domain-separated re-hash.
    """
    import aether_protocol_c.ephemeral_signer as signer_module

    # Arrange: force the first HMAC digest to be all-zero bytes (== 0 mod N),
    # then let subsequent (domain-separated retry) calls behave normally.
    real_hmac_new = signer_module.hmac.new
    call_count = {"n": 0}

    class ZeroThenRealHmac:
        def __init__(self, key, msg, digestmod):
            call_count["n"] += 1
            self._first_call = call_count["n"] == 1
            self._real = real_hmac_new(key, msg, digestmod)

        def digest(self):
            if self._first_call:
                return b"\x00" * 32
            return self._real.digest()

    monkeypatch.setattr(signer_module.hmac, "new", ZeroThenRealHmac)

    # Act
    signer = EphemeralSigner(quantum_seed=42)

    # Assert: private key must never be the known-degenerate constant 1,
    # and must never be 0 either.
    assert signer._privkey != 1
    assert signer._privkey != 0


# ═══════════════════════════════════════════════════════════════════════════
# 4. QUANTUM SEED COMMITMENT
# ═══════════════════════════════════════════════════════════════════════════

def test_seed_commitment_creation():
    now = int(time.time())
    sc = QuantumSeedCommitment(
        seed_hash="a" * 64,
        measurement_timestamp=now,
        measurement_method="CSPRNG",
        key_creation_timestamp=now,
        key_expiration_timestamp=now + 3600,
    )
    assert sc.temporal_window_hours == 1.0


def test_seed_commitment_invalid_hash():
    with pytest.raises(QuantumCryptoError, match="64 hex"):
        QuantumSeedCommitment(
            seed_hash="short",
            measurement_timestamp=0,
            measurement_method="CSPRNG",
            key_creation_timestamp=0,
            key_expiration_timestamp=1,
        )


def test_seed_commitment_invalid_method():
    with pytest.raises(QuantumCryptoError, match="measurement_method"):
        QuantumSeedCommitment(
            seed_hash="a" * 64,
            measurement_timestamp=0,
            measurement_method="INVALID",
            key_creation_timestamp=0,
            key_expiration_timestamp=1,
        )


def test_seed_commitment_roundtrip():
    now = int(time.time())
    original = QuantumSeedCommitment(
        seed_hash="b" * 64,
        measurement_timestamp=now,
        measurement_method="CSPRNG",
        key_creation_timestamp=now,
        key_expiration_timestamp=now + 7200,
    )
    d = original.to_dict()
    restored = QuantumSeedCommitment.from_dict(d)
    assert restored.seed_hash == original.seed_hash
    assert restored.measurement_method == original.measurement_method


# ═══════════════════════════════════════════════════════════════════════════
# 5. QUANTUM EPHEMERAL KEY
# ═══════════════════════════════════════════════════════════════════════════

def test_ephemeral_key_sign_and_destroy():
    key = QuantumEphemeralKey(quantum_seed=42, method="CSPRNG")
    msg = {"test": "data"}
    sig = key.sign(msg)
    assert key.is_destroyed
    assert key.verify(msg, sig)


def test_ephemeral_key_double_sign_raises():
    key = QuantumEphemeralKey(quantum_seed=42, method="CSPRNG")
    key.sign({"first": True})
    with pytest.raises(KeyDestroyedError):
        key.sign({"second": True})


def test_ephemeral_key_seed_commitment():
    key = QuantumEphemeralKey(quantum_seed=42, method="CSPRNG")
    sc = key.seed_commitment
    assert len(sc.seed_hash) == 64
    assert sc.measurement_method == "CSPRNG"
    tw = sc.temporal_window_dict
    assert tw["expires_at"] < tw["shor_earliest_attack"]


# ═══════════════════════════════════════════════════════════════════════════
# 6. ACCOUNT SNAPSHOT
# ═══════════════════════════════════════════════════════════════════════════

def test_account_snapshot_from_dict():
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)
    assert snap.capital == 100_000
    assert snap.nonce == 1


def test_account_snapshot_hash_deterministic():
    s1 = AccountSnapshot.from_dict(ACCOUNT_STATE)
    s2 = AccountSnapshot.from_dict(ACCOUNT_STATE)
    assert s1.to_hash() == s2.to_hash()


def test_account_snapshot_missing_fields():
    with pytest.raises(StateError, match="Missing"):
        AccountSnapshot.from_dict({"capital": 100})


# ═══════════════════════════════════════════════════════════════════════════
# 7. COMMITMENT (HIGH-LEVEL)
# ═══════════════════════════════════════════════════════════════════════════

def test_commit_and_verify(seed):
    result = commit(
        seed,
        order_id="test_001",
        trade_details=TRADE_DETAILS,
        account_state=ACCOUNT_STATE,
    )
    assert result["verified"]
    assert result["commitment"]["order_id"] == "test_001"


def test_commit_with_reasoning(seed):
    result = commit(
        seed,
        order_id="test_002",
        trade_details=TRADE_DETAILS,
        account_state=ACCOUNT_STATE,
        reasoning_text="Market momentum is bullish based on volume analysis",
        reasoning_model="claude-sonnet-4-6",
    )
    assert result["verified"]
    assert "reasoning_hash" in result["commitment"]


def test_commit_with_audit_log(seed, temp_audit_path):
    result = commit(
        seed,
        order_id="test_003",
        trade_details=TRADE_DETAILS,
        account_state=ACCOUNT_STATE,
        log_path=temp_audit_path,
    )
    assert result["verified"]

    audit = AuditLog(temp_audit_path)
    entries = audit.read_all()
    assert len(entries) == 1
    assert entries[0].order_id == "test_003"


def test_verify_function():
    seed = get_seed()
    result = commit(
        seed,
        order_id="v_001",
        trade_details=TRADE_DETAILS,
        account_state=ACCOUNT_STATE,
    )
    assert verify(result["commitment"], result["signature"])


def test_verify_tampered_commitment():
    seed = get_seed()
    result = commit(
        seed,
        order_id="v_002",
        trade_details=TRADE_DETAILS,
        account_state=ACCOUNT_STATE,
    )
    # Tamper with the commitment
    result["commitment"]["order_id"] = "TAMPERED"
    assert not verify(result["commitment"], result["signature"])


# ═══════════════════════════════════════════════════════════════════════════
# 8. BATCH COMMIT
# ═══════════════════════════════════════════════════════════════════════════

def test_batch_commit():
    items = [
        {
            "order_id": f"batch_{i}",
            "trade_details": {"symbol": "BTC", "qty": i, "side": "long", "price": 50000},
            "account_state": {**ACCOUNT_STATE, "nonce": i + 1},
        }
        for i in range(3)
    ]
    results = batch_commit(items)
    assert len(results) == 3
    assert all(r["verified"] for r in results)

    # All seeds independent
    seed_hashes = {r["seed_info"]["seed_hash"] for r in results}
    assert len(seed_hashes) == 3


# ═══════════════════════════════════════════════════════════════════════════
# 9. COMMITMENT VERIFIER
# ═══════════════════════════════════════════════════════════════════════════

def test_commitment_verifier_signature():
    seed = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id="cv_001",
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed.seed_int,
        measurement_method=seed.method,
    )
    assert QuantumCommitmentVerifier.verify_signature(c_dict, c_sig)
    assert QuantumCommitmentVerifier.verify_state_binding(c_dict)
    assert QuantumCommitmentVerifier.verify_quantum_binding(c_dict)
    assert QuantumCommitmentVerifier.verify_temporal_safety(c_dict)


# ═══════════════════════════════════════════════════════════════════════════
# 10. REASONING CAPTURE
# ═══════════════════════════════════════════════════════════════════════════

def test_reasoning_capture_creation():
    rc = ReasoningCapture.from_text("Buy signal detected", model="gpt-4")
    assert rc.verify()
    assert rc.reasoning_model == "gpt-4"


def test_reasoning_capture_tamper_detection():
    rc = ReasoningCapture.from_text("Original reasoning")
    # Simulate tampering
    tampered = ReasoningCapture(
        reasoning_text="Tampered reasoning",
        reasoning_hash=rc.reasoning_hash,
        reasoning_model=rc.reasoning_model,
        captured_at=rc.captured_at,
        token_count=rc.token_count,
    )
    assert not tampered.verify()


def test_reasoning_capture_roundtrip():
    rc = ReasoningCapture.from_text("Test reasoning", model="human")
    d = rc.to_dict()
    restored = ReasoningCapture.from_dict(d)
    assert restored.reasoning_text == rc.reasoning_text
    assert restored.verify()


# ═══════════════════════════════════════════════════════════════════════════
# 11. EXECUTION ATTESTATION
# ═══════════════════════════════════════════════════════════════════════════

def test_execution_attestation():
    seed1 = get_seed()
    seed2 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id="exec_001",
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    er = ExecutionResult(
        order_id="exec_001",
        filled_qty=1,
        fill_price=50_000,
    )
    snap_after = AccountSnapshot.from_dict({**ACCOUNT_STATE, "nonce": 2})

    att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        execution_result=er,
        new_account_state=snap_after,
        quantum_seed=seed2.seed_int,
        measurement_method=seed2.method,
    )

    assert QuantumExecutionVerifier.verify_signature(att_dict, att_sig)
    assert QuantumExecutionVerifier.verify_references_commitment(att_dict, c_sig)
    assert QuantumExecutionVerifier.verify_nonce_increment(1, att_dict)


# ═══════════════════════════════════════════════════════════════════════════
# 12. SETTLEMENT
# ═══════════════════════════════════════════════════════════════════════════

def test_settlement_record():
    seed1 = get_seed()
    seed2 = get_seed()
    seed3 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id="settle_001",
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    er = ExecutionResult(order_id="settle_001", filled_qty=1, fill_price=50000)
    snap_after = AccountSnapshot.from_dict({**ACCOUNT_STATE, "nonce": 2})

    att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        execution_result=er,
        new_account_state=snap_after,
        quantum_seed=seed2.seed_int,
        measurement_method=seed2.method,
    )

    s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
        order_id="settle_001",
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        commitment_window=c_dict["key_temporal_window"],
        execution_sig=att_sig,
        execution_seed_hash=att_dict["execution_quantum_seed_commitment"],
        execution_window=att_dict["key_temporal_window"],
        broker_sig="broker_ack_001",
        quantum_seed=seed3.seed_int,
        measurement_method=seed3.method,
    )

    assert QuantumSettlementVerifier.verify_signature(s_dict, s_sig)
    assert QuantumSettlementVerifier.verify_chain(c_sig, att_sig, s_dict)
    assert QuantumSettlementVerifier.verify_all_seeds_independent(s_dict)
    assert QuantumSettlementVerifier.verify_all_temporal_windows(s_dict)


# ═══════════════════════════════════════════════════════════════════════════
# 13. FLOW MERKLE
# ═══════════════════════════════════════════════════════════════════════════

def test_flow_merkle_deterministic():
    c_sig = {"r": "aa" * 32, "s": "bb" * 32}
    e_sig = {"r": "cc" * 32, "s": "dd" * 32}
    broker = "ack"
    h1 = compute_flow_merkle(c_sig, e_sig, broker)
    h2 = compute_flow_merkle(c_sig, e_sig, broker)
    assert h1 == h2
    assert len(h1) == 64


# ═══════════════════════════════════════════════════════════════════════════
# 14. AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════

def test_audit_log_append_and_read(temp_audit_path):
    audit = AuditLog(temp_audit_path)
    seed = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id="audit_001",
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed.seed_int,
        measurement_method=seed.method,
    )
    audit.append_commitment(c_dict, c_sig)

    entries = audit.read_all()
    assert len(entries) == 1
    assert entries[0].order_id == "audit_001"
    assert entries[0].phase == PHASE_COMMITMENT


def test_audit_log_query(temp_audit_path):
    audit = AuditLog(temp_audit_path)
    seed = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id="query_001",
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed.seed_int,
        measurement_method=seed.method,
    )
    audit.append_commitment(c_dict, c_sig)

    results = audit.query(record_type=PHASE_COMMITMENT)
    assert len(results) >= 1


def test_audit_entry_from_dict_rejects_non_dict_data():
    # Arrange: a syntactically valid JSONL line where `data` is a string
    # instead of a dict (e.g. a tampered/corrupted record).
    malformed = {
        "timestamp": 1,
        "phase": PHASE_COMMITMENT,
        "order_id": "tampered_001",
        "data": "not-a-dict",
        "signature": {"alg": "ed25519"},
        "quantum_proof": {"seed_commitment": "abc"},
    }

    # Act / Assert: from_dict must reject it with AuditError, not let a
    # bad-typed field silently flow downstream into verification code.
    from aether_protocol_c.audit import AuditError

    with pytest.raises(AuditError, match="data"):
        AuditEntry.from_dict(malformed)


def test_audit_log_read_all_raises_audit_error_on_malformed_data_field(temp_audit_path):
    # Arrange: write a JSONL line directly with a non-dict `signature` field,
    # simulating a corrupted/tampered audit log entry on disk.
    malformed_line = {
        "timestamp": 1,
        "phase": PHASE_COMMITMENT,
        "order_id": "tampered_002",
        "data": {"quantum_seed_commitment": "abc"},
        "signature": ["unexpected", "list", "not", "dict"],
        "quantum_proof": {"seed_commitment": "abc"},
    }
    with open(temp_audit_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(malformed_line) + "\n")

    # Act / Assert: opening the log rebuilds the SQLite index by scanning
    # the JSONL file and calling AuditEntry.from_dict() on each line; a
    # malformed record must raise a clean AuditError (from from_dict's
    # type validation) instead of letting the bad-typed field propagate
    # silently or crash later with a raw AttributeError in verification
    # code.
    from aether_protocol_c.audit import AuditError

    with pytest.raises(AuditError):
        AuditLog(temp_audit_path)


# ═══════════════════════════════════════════════════════════════════════════
# 15. TEMPORAL WINDOW
# ═══════════════════════════════════════════════════════════════════════════

def test_make_temporal_window():
    now = int(time.time())
    w = make_temporal_window(created_at=now)
    assert w["expires_at"] == now + DEFAULT_KEY_LIFETIME_SECONDS
    assert w["shor_earliest_attack"] == now + SHOR_EARLIEST_ATTACK_SECONDS
    assert w["expires_at"] < w["shor_earliest_attack"]


# ═══════════════════════════════════════════════════════════════════════════
# 16. STANDALONE VERIFY
# ═══════════════════════════════════════════════════════════════════════════

def test_verify_signature_standalone():
    key = QuantumEphemeralKey(quantum_seed=42, method="CSPRNG")
    msg = {"hello": "world"}
    sig = key.sign(msg)
    assert verify_signature(msg, sig)


def test_verify_signature_invalid():
    assert not verify_signature({"any": "msg"}, {"r": "00" * 32, "s": "00" * 32, "pubkey": "02" + "00" * 32})
