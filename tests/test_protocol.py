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
    build_broker_attestation,
)
from aether_protocol_c.audit import AuditLog, AuditEntry, PHASE_COMMITMENT
from aether_protocol_c.seed import (
    QuantumSeedResult,
    generate_quantum_seed,
)
from aether_protocol_c.verify import AuditVerifier
from aether_protocol_c.identity import AccountKeyRegistry, IdentityError


def sign_broker_ack(order_id, commitment_sig, execution_sig, broker_sig):
    """
    Build a broker signature envelope for tests: a fresh keypair signs
    the broker attestation, standing in for a real registered broker's
    key. Returns (broker_signature_envelope, broker_pubkey_hex).
    """
    seed = get_seed()
    broker_key = QuantumEphemeralKey(
        quantum_seed=seed.seed_int, method=seed.method
    )
    attestation = build_broker_attestation(
        order_id, commitment_sig, execution_sig, broker_sig
    )
    broker_signature = broker_key.sign(attestation)
    return broker_signature, broker_signature["pubkey"]


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
        symbol="BTC",
        side="long",
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

    er = ExecutionResult(order_id="settle_001", symbol="BTC", side="long", filled_qty=1, fill_price=50000)
    snap_after = AccountSnapshot.from_dict({**ACCOUNT_STATE, "nonce": 2})

    att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        execution_result=er,
        new_account_state=snap_after,
        quantum_seed=seed2.seed_int,
        measurement_method=seed2.method,
    )

    broker_signature, _ = sign_broker_ack("settle_001", c_sig, att_sig, "broker_ack_001")
    s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
        order_id="settle_001",
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        commitment_window=c_dict["key_temporal_window"],
        execution_sig=att_sig,
        execution_seed_hash=att_dict["execution_quantum_seed_commitment"],
        execution_window=att_dict["key_temporal_window"],
        broker_sig="broker_ack_001",
        broker_signature=broker_signature,
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
    broker_signature = {"pubkey": "02" + "ee" * 32, "r": "11" * 32, "s": "22" * 32}
    h1 = compute_flow_merkle(c_sig, e_sig, broker, broker_signature)
    h2 = compute_flow_merkle(c_sig, e_sig, broker, broker_signature)
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


# ═══════════════════════════════════════════════════════════════════════════
# 17. AUDIT VERIFIER — VACUOUS TRUTH REGRESSION (LOOP-17)
# ═══════════════════════════════════════════════════════════════════════════

def test_verify_trade_flow_empty_flow_is_not_quantum_safe(temp_audit_path):
    """
    A bogus/never-created order_id has no commitment, execution, or
    settlement records at all, so AuditLog.get_trade_flow() returns all
    three phases as None. Previously, verify_trade_flow() computed
    chain_valid via all(v is True for v in [...] if v is not None), which
    is vacuously True over an empty list — falsely marking a flow with
    ZERO cryptographic evidence as quantum_safe=True. This must fail closed.
    """
    audit = AuditLog(temp_audit_path)
    verifier = AuditVerifier()

    result = verifier.verify_trade_flow("nonexistent-order-id", audit)

    assert result["commitment_valid"] is None
    assert result["execution_valid"] is None
    assert result["settlement_valid"] is None
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False


def test_verify_trade_flow_missing_commitment_is_not_quantum_safe(temp_audit_path):
    """
    Round-2 finding: a flow with valid, self-consistent execution and
    settlement records but NO commitment record at all (dropped, never
    logged, or a race where commitment write fails silently) must not
    be certified quantum_safe. Previously chain_valid was computed via
    all(v is True for v in phase_results if v is not None), which drops
    the None commitment_valid from the check entirely -- so a settlement
    lacking any commitment-phase evidence could still be reported
    chain_valid=True / quantum_safe=True. This must fail closed.
    """
    order_id = "missing_commit_001"
    seed1 = get_seed()
    seed2 = get_seed()
    seed3 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    # Commitment is created only to derive valid downstream references --
    # it is deliberately NEVER appended to the audit log, simulating a
    # dropped/pruned/never-written commitment record.
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    er = ExecutionResult(order_id=order_id, symbol="BTC", side="long", filled_qty=1, fill_price=50_000)
    snap_after = AccountSnapshot.from_dict({**ACCOUNT_STATE, "nonce": 2})

    att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        execution_result=er,
        new_account_state=snap_after,
        quantum_seed=seed2.seed_int,
        measurement_method=seed2.method,
    )

    broker_signature, broker_pubkey = sign_broker_ack(
        order_id, c_sig, att_sig, "broker_ack_missing_commit"
    )
    s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
        order_id=order_id,
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        commitment_window=c_dict["key_temporal_window"],
        execution_sig=att_sig,
        execution_seed_hash=att_dict["execution_quantum_seed_commitment"],
        execution_window=att_dict["key_temporal_window"],
        broker_sig="broker_ack_missing_commit",
        broker_signature=broker_signature,
        quantum_seed=seed3.seed_int,
        measurement_method=seed3.method,
    )

    audit = AuditLog(temp_audit_path)
    audit.append_execution(att_dict, att_sig)
    audit.append_settlement(s_dict, s_sig)

    # Identity binding (LOOP-17 round 3) is a separate, orthogonal
    # concern from this vacuous-truth regression: register the real
    # signer's keys so execution/settlement pass identity too, isolating
    # the missing-commitment-phase behaviour under test.
    registry = AccountKeyRegistry()
    registry.register(order_id, att_sig["pubkey"])
    registry.register(order_id, s_sig["pubkey"])
    registry.register(f"broker:{order_id}", broker_pubkey)

    verifier = AuditVerifier()
    result = verifier.verify_trade_flow(order_id, audit, registry=registry)

    assert result["commitment_valid"] is None
    assert result["execution_valid"] is True
    assert result["settlement_valid"] is True
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False


def test_verify_trade_flow_execution_terms_disconnected_from_commitment(
    temp_audit_path,
):
    """
    Round-5 finding (LOOP17-R5-01): commitment authorises BUY 10 shares
    @ $50, but the execution phase -- signed by a validly-registered key
    -- attests a fill of 10,000 shares @ $5,000. Every existing check
    (signature validity, quantum binding, temporal safety, nonce
    increment, seed independence, commitment_sig dict-equality via
    verify_references_commitment) only proves the SIGNATURE ENVELOPE
    chains together; none of them compare execution_result's
    filled_qty/fill_price against the commitment's trade_details. Before
    the fix, this flow was certified execution_valid=True/chain_valid=
    True/quantum_safe=True despite the economic terms being completely
    disconnected from what was authorised.

    Arrange: build a commitment authorising qty=10 @ price=50, then an
    execution attestation (validly signed, correctly chained) reporting
    filled_qty=10_000 @ fill_price=5_000.
    Act: run AuditVerifier.verify_trade_flow / detect_tampering and the
    unit-level verify_matches_commitment_terms check directly.
    Assert: the mismatch is caught everywhere -- execution_valid=False,
    chain_valid=False, quantum_safe=False, tampering flagged.
    """
    order_id = "terms_mismatch_001"
    seed1 = get_seed()
    seed2 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    authorised_trade = {"symbol": "BTC", "qty": 10, "side": "long", "price": 50}
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=authorised_trade,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    # Executed fill is wildly disconnected from what was committed to:
    # 1000x the authorised quantity, 100x the authorised price.
    er = ExecutionResult(order_id=order_id, symbol="BTC", side="long", filled_qty=10_000, fill_price=5_000)
    snap_after = AccountSnapshot.from_dict({**ACCOUNT_STATE, "nonce": 2})

    att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        execution_result=er,
        new_account_state=snap_after,
        quantum_seed=seed2.seed_int,
        measurement_method=seed2.method,
    )

    audit = AuditLog(temp_audit_path)
    audit.append_commitment(c_dict, c_sig)
    audit.append_execution(att_dict, att_sig)

    registry = AccountKeyRegistry()
    registry.register(order_id, c_sig["pubkey"])
    registry.register(order_id, att_sig["pubkey"])

    verifier = AuditVerifier()
    result = verifier.verify_trade_flow(order_id, audit, registry=registry)

    assert result["commitment_valid"] is True
    assert result["execution_valid"] is False
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False
    assert any(
        "Execution matches authorised trade terms: False" in d
        for d in result["details"]
    )

    # The unit-level check itself must also directly reject the mismatch.
    assert (
        QuantumExecutionVerifier.verify_matches_commitment_terms(
            authorised_trade, er.to_json()
        )
        is False
    )

    tamper = verifier.detect_tampering(order_id, audit, registry=registry)
    assert tamper["tampered"] is True
    assert any("EXECUTION_TERMS_MISMATCH" in issue for issue in tamper["issues"])


def test_verify_trade_flow_execution_symbol_side_substitution_rejected(
    temp_audit_path,
):
    """
    Round-6 finding (LOOP17-R6): commitment authorises BUY 10 AAPL @ $50,
    but the execution phase -- validly signed, correctly chained, with
    qty/price matching exactly -- reports a fill of SELL 10 TSLA @ $50.
    Before the fix, ExecutionResult had no symbol/side fields at all and
    verify_matches_commitment_terms never compared them, so this
    substitution passed every check (qty/price within tolerance).

    Arrange: build a commitment authorising symbol=AAPL/side=BUY/qty=10/
    price=50, then an execution attestation with matching qty/price but
    symbol=TSLA/side=SELL.
    Act: run AuditVerifier.verify_trade_flow and the unit-level
    verify_matches_commitment_terms check directly.
    Assert: the substitution is caught -- execution_valid=False,
    chain_valid=False, quantum_safe=False.
    """
    order_id = "symbol_side_substitution_001"
    seed1 = get_seed()
    seed2 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    authorised_trade = {"symbol": "AAPL", "qty": 10, "side": "BUY", "price": 50}
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=authorised_trade,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    # Qty and price exactly match the authorised terms, but the fill is
    # for a completely different instrument and the opposite side.
    er = ExecutionResult(
        order_id=order_id, symbol="TSLA", side="SELL", filled_qty=10, fill_price=50
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

    audit = AuditLog(temp_audit_path)
    audit.append_commitment(c_dict, c_sig)
    audit.append_execution(att_dict, att_sig)

    registry = AccountKeyRegistry()
    registry.register(order_id, c_sig["pubkey"])
    registry.register(order_id, att_sig["pubkey"])

    verifier = AuditVerifier()
    result = verifier.verify_trade_flow(order_id, audit, registry=registry)

    assert result["commitment_valid"] is True
    assert result["execution_valid"] is False
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False

    # The unit-level check itself must also directly reject the substitution.
    assert (
        QuantumExecutionVerifier.verify_matches_commitment_terms(
            authorised_trade, er.to_json()
        )
        is False
    )


def test_verify_trade_flow_execution_symbol_side_omitted_from_commitment_rejected(
    temp_audit_path,
):
    """
    Round-8 finding (LOOP17-R8-01): trade_details is a free-form dict
    supplied at commitment-creation time and neither
    QuantumCommitmentVerifier.verify_state_binding nor
    verify_quantum_binding require it to contain "symbol"/"side" -- only
    "account_state_hash" and "nonce" are mandated. Before the fix,
    verify_matches_commitment_terms only compared fill_symbol/fill_side
    against the commitment when `authorised_symbol is not None or
    authorised_side is not None`. If a commitment simply omitted
    "symbol"/"side" from trade_details (e.g. only "qty"/"price" given),
    that guard evaluated False and the symbol/side cross-check was
    skipped entirely -- letting the execution report a completely
    different instrument and/or the opposite side while qty/price still
    matched, and every other check (signature, quantum binding, nonce,
    chain linkage) still passed.

    Arrange: build a commitment whose trade_details authorises only
    qty=10 @ price=50 (no "symbol"/"side" keys at all), then an
    execution attestation with matching qty/price but a concrete
    symbol="TSLA"/side="SELL".
    Act: run AuditVerifier.verify_trade_flow and the unit-level
    verify_matches_commitment_terms check directly.
    Assert: the unauthorised fill is rejected -- execution_valid=False,
    chain_valid=False, quantum_safe=False -- instead of being silently
    approved because symbol/side were never specified.
    """
    order_id = "symbol_side_omitted_from_commitment_001"
    seed1 = get_seed()
    seed2 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    # trade_details deliberately omits "symbol" and "side" entirely.
    authorised_trade = {"qty": 10, "price": 50}
    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=authorised_trade,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    # Qty and price exactly match the (incomplete) authorised terms, but
    # the fill reports a concrete instrument/side that was never
    # actually sanctioned by the commitment.
    er = ExecutionResult(
        order_id=order_id, symbol="TSLA", side="SELL", filled_qty=10, fill_price=50
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

    audit = AuditLog(temp_audit_path)
    audit.append_commitment(c_dict, c_sig)
    audit.append_execution(att_dict, att_sig)

    registry = AccountKeyRegistry()
    registry.register(order_id, c_sig["pubkey"])
    registry.register(order_id, att_sig["pubkey"])

    verifier = AuditVerifier()
    result = verifier.verify_trade_flow(order_id, audit, registry=registry)

    assert result["commitment_valid"] is True
    assert result["execution_valid"] is False
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False

    # The unit-level check itself must also directly reject the
    # unauthorised symbol/side rather than skipping the comparison
    # because trade_details never specified them.
    assert (
        QuantumExecutionVerifier.verify_matches_commitment_terms(
            authorised_trade, er.to_json()
        )
        is False
    )


# ═══════════════════════════════════════════════════════════════════════════
# 18. AUDIT VERIFIER — SELF-REFERENTIAL SIGNATURE / MISSING IDENTITY BINDING
#     REGRESSION (LOOP-17 round 3)
# ═══════════════════════════════════════════════════════════════════════════

def _build_full_flow(order_id: str):
    """Build and sign a complete commitment/execution/settlement flow."""
    seed1 = get_seed()
    seed2 = get_seed()
    seed3 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    er = ExecutionResult(order_id=order_id, symbol="BTC", side="long", filled_qty=1, fill_price=50_000)
    snap_after = AccountSnapshot.from_dict({**ACCOUNT_STATE, "nonce": 2})

    att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        execution_result=er,
        new_account_state=snap_after,
        quantum_seed=seed2.seed_int,
        measurement_method=seed2.method,
    )

    broker_signature, broker_pubkey = sign_broker_ack(
        order_id, c_sig, att_sig, f"broker_ack_{order_id}"
    )
    s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
        order_id=order_id,
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        commitment_window=c_dict["key_temporal_window"],
        execution_sig=att_sig,
        execution_seed_hash=att_dict["execution_quantum_seed_commitment"],
        execution_window=att_dict["key_temporal_window"],
        broker_sig=f"broker_ack_{order_id}",
        broker_signature=broker_signature,
        quantum_seed=seed3.seed_int,
        measurement_method=seed3.method,
    )
    return c_dict, c_sig, att_dict, att_sig, s_dict, s_sig, broker_pubkey


def test_attacker_self_signed_flow_is_not_quantum_safe_without_registry(temp_audit_path):
    """
    Breaker finding (round 3, CRITICAL, missing-identity-binding): an
    attacker who can write to the audit log generates their OWN fresh
    quantum-derived keypair (no private-key theft, no ECDLP break --
    just a normal EphemeralSigner/QuantumEphemeralKey instance) and
    self-signs a completely fabricated commitment/execution/settlement
    flow for a victim's order_id. Every internal check (signature
    validity, state binding, quantum binding, temporal safety, nonce
    increment, seed independence, chain linkage) is satisfied because
    they only validate the envelope against the pubkey embedded in that
    SAME envelope -- a tautology. Before the fix, verify_trade_flow
    reported this fabricated flow as quantum_safe=True/chain_valid=True,
    which DisputeProofGenerator would then export as an "authorised"
    trade proof. It must never be certified quantum_safe absent an
    out-of-band identity binding.
    """
    order_id = "attacker_forged_001"
    c_dict, c_sig, att_dict, att_sig, s_dict, s_sig, _broker_pubkey = _build_full_flow(order_id)

    audit = AuditLog(temp_audit_path)
    # AuditLog.append_* accept any self-consistent envelope as-is -- this
    # models the attacker directly appending a fabricated flow.
    audit.append_commitment(c_dict, c_sig)
    audit.append_execution(att_dict, att_sig)
    audit.append_settlement(s_dict, s_sig)

    verifier = AuditVerifier()

    # No registry supplied -- there is no way to prove the account holder
    # (as opposed to the attacker) authorised this flow, so it must fail
    # closed even though every internal self-consistency check passes.
    result = verifier.verify_trade_flow(order_id, audit)
    assert result["identity_bound"] is False
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False

    tamper = verifier.detect_tampering(order_id, audit)
    assert any("IDENTITY_UNVERIFIED" in issue for issue in tamper["issues"])
    assert tamper["tampered"] is True


def test_attacker_key_rejected_by_registry_legit_key_accepted(temp_audit_path):
    """
    Same attacker scenario, but now an AccountKeyRegistry has been
    populated out-of-band with the account holder's real signing key
    (e.g. at onboarding). The attacker's self-signed forged flow for
    the SAME order_id must be rejected because its embedded pubkey was
    never registered -- while a flow legitimately signed by the
    registered key is accepted. This proves identity binding actually
    discriminates attacker keys from authorised keys, not just that it
    fails closed on empty registries.
    """
    registry = AccountKeyRegistry()
    verifier = AuditVerifier()

    # ── Legitimate flow: signed with the account holder's real key ────
    legit_order = "legit_holder_001"
    lc_dict, lc_sig, latt_dict, latt_sig, ls_dict, ls_sig, l_broker_pubkey = _build_full_flow(
        legit_order
    )
    # Each phase signs with its own fresh ephemeral key (by design -- P4
    # perfect forward secrecy), so all three pubkeys are registered as
    # authorised for this account/order scope.
    registry.register(legit_order, lc_sig["pubkey"])
    registry.register(legit_order, latt_sig["pubkey"])
    registry.register(legit_order, ls_sig["pubkey"])
    registry.register(f"broker:{legit_order}", l_broker_pubkey)

    legit_audit = AuditLog(str(temp_audit_path) + ".legit")
    legit_audit.append_commitment(lc_dict, lc_sig)
    legit_audit.append_execution(latt_dict, latt_sig)
    legit_audit.append_settlement(ls_dict, ls_sig)

    legit_result = verifier.verify_trade_flow(legit_order, legit_audit, registry=registry)
    assert legit_result["identity_bound"] is True
    assert legit_result["commitment_valid"] is True
    assert legit_result["execution_valid"] is True
    assert legit_result["settlement_valid"] is True
    assert legit_result["chain_valid"] is True
    assert legit_result["quantum_safe"] is True

    # ── Attacker forges a flow for a DIFFERENT order_id using their own
    #    fresh keypair, which was never registered for that order ─────
    forged_order = "attacker_forged_002"
    fc_dict, fc_sig, fatt_dict, fatt_sig, fs_dict, fs_sig, _f_broker_pubkey = _build_full_flow(
        forged_order
    )
    # Registry has no entry at all for forged_order -- models an
    # attacker targeting an order/account whose real key was simply
    # never (or not yet) registered, or attempting to reuse a key that
    # was never authorised for this scope.

    forged_audit = AuditLog(str(temp_audit_path) + ".forged")
    forged_audit.append_commitment(fc_dict, fc_sig)
    forged_audit.append_execution(fatt_dict, fatt_sig)
    forged_audit.append_settlement(fs_dict, fs_sig)

    forged_result = verifier.verify_trade_flow(forged_order, forged_audit, registry=registry)
    assert forged_result["identity_bound"] is True  # registry WAS supplied
    assert forged_result["commitment_valid"] is False
    assert forged_result["execution_valid"] is False
    assert forged_result["settlement_valid"] is False
    assert forged_result["chain_valid"] is False
    assert forged_result["quantum_safe"] is False

    forged_tamper = verifier.detect_tampering(forged_order, forged_audit, registry=registry)
    assert any("UNAUTHORIZED_KEY" in issue for issue in forged_tamper["issues"])
    assert forged_tamper["tampered"] is True


def test_account_key_registry_rejects_malformed_pubkey():
    registry = AccountKeyRegistry()
    with pytest.raises(IdentityError):
        registry.register("acct_1", "not-a-real-pubkey")
    with pytest.raises(IdentityError):
        registry.register("", "02" + "aa" * 32)


def test_account_key_registry_fails_closed_when_unregistered():
    registry = AccountKeyRegistry()
    assert registry.is_authorized("acct_1", "02" + "aa" * 32) is False
    assert registry.is_registered("acct_1") is False


# ═══════════════════════════════════════════════════════════════════════════
# 19. SETTLEMENT — BROKER ACKNOWLEDGEMENT AUTHENTICATION REGRESSION
#     (LOOP-17 round 7)
# ═══════════════════════════════════════════════════════════════════════════

def test_fabricated_broker_ack_rejected_by_verify_chain_and_trade_flow(
    temp_audit_path,
):
    """
    Breaker finding (round 7, HIGH, settlement-phase authentication gap):
    broker_settlement_sig was a bare, free-form string never
    independently authenticated anywhere. A party who legitimately
    controls the settlement-phase signing key (already authorised in
    the registry) could fabricate ANY broker_settlement_sig value --
    including an empty string, or text copy-pasted from an unrelated
    settlement -- and verify_chain / verify_trade_flow / the exported
    dispute proof would all certify the flow as fully verified with
    zero cryptographic proof any broker ever acknowledged it.

    Arrange: build a fully valid, correctly-signed, correctly-chained
    commitment/execution/settlement flow (registered legitimate
    settlement-phase key), but instead of a broker_signature envelope
    signed by a real broker key, embed a completely fabricated
    broker_settlement_sig string signed by nothing (an empty envelope) --
    reproducing the exact attack the finding describes.
    Act: run QuantumSettlementVerifier.verify_chain and
    AuditVerifier.verify_trade_flow / detect_tampering.
    Assert: the fabricated broker ack is rejected everywhere, even
    though every other phase and signature is perfectly valid.
    """
    order_id = "broker_forgery_001"
    seed1 = get_seed()
    seed2 = get_seed()
    seed3 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    er = ExecutionResult(
        order_id=order_id, symbol="BTC", side="long", filled_qty=1, fill_price=50_000
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

    # The settlement-phase signer fabricates a broker acknowledgement
    # string out of thin air -- no broker key ever signed it. This
    # models a compromised/dishonest holder of an authorised
    # settlement-phase key minting a fake broker_settlement_sig.
    fabricated_broker_sig = "broker fully acknowledges settlement -- trust me"
    s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
        order_id=order_id,
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        commitment_window=c_dict["key_temporal_window"],
        execution_sig=att_sig,
        execution_seed_hash=att_dict["execution_quantum_seed_commitment"],
        execution_window=att_dict["key_temporal_window"],
        broker_sig=fabricated_broker_sig,
        broker_signature={},  # no real broker key ever signed anything
        quantum_seed=seed3.seed_int,
        measurement_method=seed3.method,
    )

    # Unit-level: verify_chain must reject an unauthenticated broker ack
    # even though commitment/execution references and the merkle hash
    # were all computed self-consistently.
    assert QuantumSettlementVerifier.verify_chain(c_sig, att_sig, s_dict) is False

    audit = AuditLog(temp_audit_path)
    audit.append_commitment(c_dict, c_sig)
    audit.append_execution(att_dict, att_sig)
    audit.append_settlement(s_dict, s_sig)

    # Register the legitimate settlement-phase signer (and commitment/
    # execution signers) so the ONLY failure this test isolates is the
    # broker acknowledgement's own missing authentication.
    registry = AccountKeyRegistry()
    registry.register(order_id, c_sig["pubkey"])
    registry.register(order_id, att_sig["pubkey"])
    registry.register(order_id, s_sig["pubkey"])

    verifier = AuditVerifier()
    result = verifier.verify_trade_flow(order_id, audit, registry=registry)

    assert result["commitment_valid"] is True
    assert result["execution_valid"] is True
    assert result["settlement_valid"] is False
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False

    tamper = verifier.detect_tampering(order_id, audit, registry=registry)
    assert tamper["tampered"] is True
    assert any(
        "BROKER_IDENTITY_UNVERIFIED" in issue or "BROKER_UNAUTHORIZED_KEY" in issue
        or "SETTLEMENT_CHAIN_BROKEN" in issue
        for issue in tamper["issues"]
    )


def test_broker_ack_signed_by_unregistered_key_rejected(temp_audit_path):
    """
    Complementary case: the broker_settlement_sig IS accompanied by a
    real, cryptographically valid signature (verify_chain passes), but
    that key was never registered as an authorised broker for this
    scope -- e.g. an attacker's own fresh keypair, or a broker key
    that's real but for a different counterparty. This proves the
    fix requires *registered* broker identity, not merely *any* valid
    signature.
    """
    order_id = "broker_unregistered_001"
    seed1 = get_seed()
    seed2 = get_seed()
    seed3 = get_seed()
    snap = AccountSnapshot.from_dict(ACCOUNT_STATE)

    c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
        order_id=order_id,
        trade_details=TRADE_DETAILS,
        account_state=snap,
        quantum_seed=seed1.seed_int,
        measurement_method=seed1.method,
    )

    er = ExecutionResult(
        order_id=order_id, symbol="BTC", side="long", filled_qty=1, fill_price=50_000
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

    broker_signature, broker_pubkey = sign_broker_ack(
        order_id, c_sig, att_sig, "broker_ack_real_but_unregistered"
    )
    s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
        order_id=order_id,
        commitment_sig=c_sig,
        commitment_seed_hash=c_dict["quantum_seed_commitment"],
        commitment_window=c_dict["key_temporal_window"],
        execution_sig=att_sig,
        execution_seed_hash=att_dict["execution_quantum_seed_commitment"],
        execution_window=att_dict["key_temporal_window"],
        broker_sig="broker_ack_real_but_unregistered",
        broker_signature=broker_signature,
        quantum_seed=seed3.seed_int,
        measurement_method=seed3.method,
    )

    # verify_chain passes -- the signature is cryptographically valid.
    assert QuantumSettlementVerifier.verify_chain(c_sig, att_sig, s_dict) is True

    audit = AuditLog(temp_audit_path)
    audit.append_commitment(c_dict, c_sig)
    audit.append_execution(att_dict, att_sig)
    audit.append_settlement(s_dict, s_sig)

    registry = AccountKeyRegistry()
    registry.register(order_id, c_sig["pubkey"])
    registry.register(order_id, att_sig["pubkey"])
    registry.register(order_id, s_sig["pubkey"])
    # Deliberately do NOT register broker_pubkey under "broker:{order_id}".

    verifier = AuditVerifier()
    result = verifier.verify_trade_flow(order_id, audit, registry=registry)

    assert result["settlement_valid"] is False
    assert result["chain_valid"] is False
    assert result["quantum_safe"] is False
