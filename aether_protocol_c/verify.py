"""
aether_protocol_c/verify.py

Quantum-aware verification and dispute proof generation.

AuditVerifier: checks every signature, quantum binding, temporal window,
    and chain linkage in a trade flow.
DisputeProofGenerator: produces self-contained, exportable proofs with
    quantum safety guarantees suitable for brokers or regulators.

Quantum-Aware Verification Includes:
    - Checking all 3 quantum seed commitments are different (P4: PFS)
    - Verifying temporal windows prove all keys expired before Shor's
    - Proving the chain is unforgeable
    - Generating dispute proofs with quantum safety timeline
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .audit import AuditLog, PHASE_COMMITMENT, PHASE_EXECUTION, PHASE_SETTLEMENT
from .commitment import QuantumCommitmentVerifier
from .execution import QuantumExecutionVerifier
from .crypto import verify_signature, SHOR_EARLIEST_ATTACK_SECONDS
from .settlement import QuantumSettlementVerifier, compute_flow_merkle


class VerificationError(Exception):
    """Raised when verification operations fail."""


class AuditVerifier:
    """
    Quantum-aware verifier for complete trade flows.

    Checks every signature, quantum binding, temporal window, seed
    independence, and chain linkage.
    """

    def verify_trade_flow(self, order_id: str, audit_log: AuditLog) -> dict:
        """
        Verify the complete trade flow for an order.

        Checks:
        1. All signatures are valid
        2. All quantum bindings are present
        3. All temporal windows prove safety against Shor's
        4. All seeds are independent (P4: PFS)
        5. Chain linkage is correct

        Args:
            order_id: The order to verify.
            audit_log: The audit log to read from.

        Returns:
            Comprehensive verification result dict.
        """
        flow = audit_log.get_trade_flow(order_id)
        details: List[str] = []

        # ── Commitment verification ──────────────────────────────────
        commitment_valid: Optional[bool] = None
        if flow["commitment"] is not None and flow["commitment_sig"] is not None:
            sig_ok = QuantumCommitmentVerifier.verify_signature(
                flow["commitment"], flow["commitment_sig"]
            )
            state_ok = QuantumCommitmentVerifier.verify_state_binding(flow["commitment"])
            quantum_ok = QuantumCommitmentVerifier.verify_quantum_binding(flow["commitment"])
            temporal_ok = QuantumCommitmentVerifier.verify_temporal_safety(flow["commitment"])

            commitment_valid = sig_ok and state_ok and quantum_ok and temporal_ok

            details.append(f"Commitment signature valid: {sig_ok}")
            details.append(f"Commitment state binding: {state_ok}")
            details.append(f"Commitment quantum binding: {quantum_ok}")
            details.append(f"Commitment temporal safety: {temporal_ok}")
        else:
            details.append("Commitment phase: MISSING")

        # ── Execution verification ───────────────────────────────────
        execution_valid: Optional[bool] = None
        if flow["execution"] is not None and flow["execution_sig"] is not None:
            sig_ok = QuantumExecutionVerifier.verify_signature(
                flow["execution"], flow["execution_sig"]
            )
            quantum_ok = QuantumExecutionVerifier.verify_quantum_binding(flow["execution"])
            temporal_ok = QuantumExecutionVerifier.verify_temporal_safety(flow["execution"])

            execution_valid = sig_ok and quantum_ok and temporal_ok

            details.append(f"Execution signature valid: {sig_ok}")
            details.append(f"Execution quantum binding: {quantum_ok}")
            details.append(f"Execution temporal safety: {temporal_ok}")

            # Check commitment reference
            if flow["commitment_sig"] is not None:
                ref_ok = QuantumExecutionVerifier.verify_references_commitment(
                    flow["execution"], flow["commitment_sig"]
                )
                details.append(f"Execution references commitment: {ref_ok}")
                if not ref_ok:
                    execution_valid = False

            # Check nonce increment
            if flow["commitment"] is not None:
                commit_nonce = flow["commitment"].get("nonce", 0)
                nonce_ok = QuantumExecutionVerifier.verify_nonce_increment(
                    commit_nonce, flow["execution"]
                )
                details.append(f"Nonce increment valid: {nonce_ok}")
                if not nonce_ok:
                    execution_valid = False

            # Check seed independence
            if flow["commitment"] is not None:
                c_seed = flow["commitment"].get("quantum_seed_commitment", "")
                e_seed = flow["execution"].get("execution_quantum_seed_commitment", "")
                seeds_independent = QuantumExecutionVerifier.verify_independent_seeds(
                    c_seed, e_seed
                )
                details.append(f"Seeds independent (commitment vs execution): {seeds_independent}")
                if not seeds_independent:
                    execution_valid = False
        else:
            details.append("Execution phase: MISSING")

        # ── Settlement verification ──────────────────────────────────
        settlement_valid: Optional[bool] = None
        if flow["settlement"] is not None and flow["settlement_sig"] is not None:
            sig_ok = QuantumSettlementVerifier.verify_signature(
                flow["settlement"], flow["settlement_sig"]
            )
            details.append(f"Settlement signature valid: {sig_ok}")

            settlement_valid = sig_ok

            # Chain linkage
            if flow["commitment_sig"] is not None and flow["execution_sig"] is not None:
                chain_ok = QuantumSettlementVerifier.verify_chain(
                    flow["commitment_sig"], flow["execution_sig"], flow["settlement"]
                )
                details.append(f"Settlement chain valid: {chain_ok}")
                if not chain_ok:
                    settlement_valid = False

            # All seeds independent
            seeds_ok = QuantumSettlementVerifier.verify_all_seeds_independent(
                flow["settlement"]
            )
            details.append(f"All 3 seeds independent: {seeds_ok}")
            if not seeds_ok:
                settlement_valid = False

            # All temporal windows
            temporal_ok = QuantumSettlementVerifier.verify_all_temporal_windows(
                flow["settlement"]
            )
            details.append(f"All temporal windows safe: {temporal_ok}")
            if not temporal_ok:
                settlement_valid = False
        else:
            details.append("Settlement phase: MISSING")

        # ── Overall assessment ───────────────────────────────────────
        phase_results = [commitment_valid, execution_valid, settlement_valid]
        has_any_phase = any(v is not None for v in phase_results)
        chain_valid = has_any_phase and all(
            v is True for v in phase_results if v is not None
        )

        # Quantum safety summary
        # A flow with zero recorded phases has no cryptographic evidence at
        # all, so it must never be reported as quantum-safe (vacuous truth
        # over an empty all() would otherwise make chain_valid=True here).
        quantum_safe = chain_valid  # If all checks pass, the flow is quantum-safe

        return {
            "order_id": order_id,
            "quantum_safe": quantum_safe,
            "chain_valid": chain_valid,
            "commitment_valid": commitment_valid,
            "execution_valid": execution_valid,
            "settlement_valid": settlement_valid,
            "details": details,
        }

    def detect_tampering(self, order_id: str, audit_log: AuditLog) -> dict:
        """
        Detect tampering in a trade flow.

        Examines each phase and identifies specific discrepancies.

        Args:
            order_id: The order to check.
            audit_log: The audit log to read from.

        Returns:
            Dict with order_id, tampered (bool), issues (list of strings).
        """
        flow = audit_log.get_trade_flow(order_id)
        issues: List[str] = []

        # Check commitment
        if flow["commitment"] is not None and flow["commitment_sig"] is not None:
            if not QuantumCommitmentVerifier.verify_signature(
                flow["commitment"], flow["commitment_sig"]
            ):
                issues.append(
                    "COMMITMENT_SIG_INVALID: Commitment signature does not match data"
                )
            if not QuantumCommitmentVerifier.verify_state_binding(flow["commitment"]):
                issues.append("COMMITMENT_STATE_UNBOUND: Missing state hash or nonce")
            if not QuantumCommitmentVerifier.verify_quantum_binding(flow["commitment"]):
                issues.append("COMMITMENT_QUANTUM_UNBOUND: Missing quantum seed commitment")
            if not QuantumCommitmentVerifier.verify_temporal_safety(flow["commitment"]):
                issues.append(
                    "COMMITMENT_TEMPORAL_UNSAFE: Key may not expire before Shor's window"
                )

        # Check execution
        if flow["execution"] is not None and flow["execution_sig"] is not None:
            if not QuantumExecutionVerifier.verify_signature(
                flow["execution"], flow["execution_sig"]
            ):
                issues.append(
                    "EXECUTION_SIG_INVALID: Execution signature does not match data"
                )
            if not QuantumExecutionVerifier.verify_quantum_binding(flow["execution"]):
                issues.append(
                    "EXECUTION_QUANTUM_UNBOUND: Missing quantum seed commitment"
                )
            if flow["commitment_sig"] is not None:
                if not QuantumExecutionVerifier.verify_references_commitment(
                    flow["execution"], flow["commitment_sig"]
                ):
                    issues.append(
                        "EXECUTION_COMMITMENT_MISMATCH: Execution does not reference "
                        "correct commitment"
                    )
            if flow["commitment"] is not None:
                commit_nonce = flow["commitment"].get("nonce", -1)
                if not QuantumExecutionVerifier.verify_nonce_increment(
                    commit_nonce, flow["execution"]
                ):
                    issues.append(
                        f"EXECUTION_NONCE_INVALID: Expected {commit_nonce + 1}, "
                        f"got {flow['execution'].get('nonce_after')}"
                    )
                c_seed = flow["commitment"].get("quantum_seed_commitment", "")
                e_seed = flow["execution"].get("execution_quantum_seed_commitment", "")
                if not QuantumExecutionVerifier.verify_independent_seeds(c_seed, e_seed):
                    issues.append(
                        "SEED_REUSE: Commitment and execution used the same quantum seed"
                    )

        # Check settlement
        if flow["settlement"] is not None and flow["settlement_sig"] is not None:
            if not QuantumSettlementVerifier.verify_signature(
                flow["settlement"], flow["settlement_sig"]
            ):
                issues.append(
                    "SETTLEMENT_SIG_INVALID: Settlement signature does not match data"
                )
            if flow["commitment_sig"] is not None and flow["execution_sig"] is not None:
                if not QuantumSettlementVerifier.verify_chain(
                    flow["commitment_sig"], flow["execution_sig"], flow["settlement"]
                ):
                    issues.append(
                        "SETTLEMENT_CHAIN_BROKEN: Flow merkle does not match"
                    )
            if not QuantumSettlementVerifier.verify_all_seeds_independent(
                flow["settlement"]
            ):
                issues.append(
                    "SEED_REUSE_IN_CHAIN: Not all 3 quantum seeds are independent"
                )
            if not QuantumSettlementVerifier.verify_all_temporal_windows(
                flow["settlement"]
            ):
                issues.append(
                    "TEMPORAL_WINDOW_UNSAFE: Not all keys expire before Shor's"
                )

        return {
            "order_id": order_id,
            "tampered": len(issues) > 0,
            "issues": issues,
        }


class DisputeProofGenerator:
    """
    Generates self-contained, exportable dispute proofs with quantum
    safety guarantees.

    Proofs include all signatures, quantum seed commitments, temporal
    windows, and verification instructions.
    """

    def generate_proof(
        self, order_id: str, reason: str, audit_log: AuditLog
    ) -> dict:
        """
        Generate a general dispute proof with quantum safety context.

        Args:
            order_id: The order in dispute.
            reason: Human-readable reason for the dispute.
            audit_log: The audit log to read from.

        Returns:
            Self-contained proof dict.
        """
        flow = audit_log.get_trade_flow(order_id)

        return {
            "proof_type": "GENERAL_DISPUTE",
            "order_id": order_id,
            "reason": reason,
            "generated_at": int(time.time()),
            "quantum_safety": self._build_quantum_safety_summary(flow),
            "authorization": {
                "commitment": flow["commitment"],
                "commitment_sig": flow["commitment_sig"],
                "quantum_proof": flow["commitment_quantum_proof"],
            },
            "execution": {
                "attestation": flow["execution"],
                "execution_sig": flow["execution_sig"],
                "quantum_proof": flow["execution_quantum_proof"],
            },
            "settlement": {
                "record": flow["settlement"],
                "settlement_sig": flow["settlement_sig"],
                "quantum_proof": flow["settlement_quantum_proof"],
            },
        }

    def proof_authorization(self, order_id: str, audit_log: AuditLog) -> dict:
        """
        Generate proof that a trade was authorised with quantum-derived key.

        Proves: "I authorised this trade, signed with a quantum-derived
        ephemeral key that has since been destroyed."

        Args:
            order_id: The order.
            audit_log: The audit log.

        Returns:
            Proof dict focused on commitment phase.
        """
        flow = audit_log.get_trade_flow(order_id)

        return {
            "proof_type": "AUTHORIZATION",
            "order_id": order_id,
            "claim": "Trade was authorised by account holder with quantum-derived key",
            "generated_at": int(time.time()),
            "commitment": flow["commitment"],
            "commitment_sig": flow["commitment_sig"],
            "quantum_proof": flow["commitment_quantum_proof"],
            "verification_instructions": (
                "1. Verify the commitment signature against the embedded public key. "
                "2. Check quantum_seed_commitment is a valid 64-char hex hash. "
                "3. Check key_temporal_window.expires_at < key_temporal_window.shor_earliest_attack. "
                "4. The commitment binds order_id + trade_details + account_state_hash + nonce."
            ),
        }

    def proof_execution_mismatch(self, order_id: str, audit_log: AuditLog) -> dict:
        """
        Generate proof of execution mismatch.

        Proves: "I authorised X, but Y was executed."

        Args:
            order_id: The order.
            audit_log: The audit log.

        Returns:
            Proof dict highlighting mismatch with quantum proofs.
        """
        flow = audit_log.get_trade_flow(order_id)

        authorised = (
            flow["commitment"].get("trade_details", {})
            if flow["commitment"]
            else {}
        )
        executed = {}
        if flow["execution"] and "execution_result" in flow["execution"]:
            executed = flow["execution"]["execution_result"]

        return {
            "proof_type": "EXECUTION_MISMATCH",
            "order_id": order_id,
            "claim": "Execution does not match authorisation",
            "generated_at": int(time.time()),
            "quantum_safety": self._build_quantum_safety_summary(flow),
            "authorised": {
                "trade_details": authorised,
                "commitment": flow["commitment"],
                "commitment_sig": flow["commitment_sig"],
                "quantum_proof": flow["commitment_quantum_proof"],
            },
            "executed": {
                "execution_result": executed,
                "attestation": flow["execution"],
                "execution_sig": flow["execution_sig"],
                "quantum_proof": flow["execution_quantum_proof"],
            },
            "verification_instructions": (
                "1. Verify both signatures (commitment and execution). "
                "2. Compare trade_details in commitment vs execution_result. "
                "3. Check both quantum seed commitments are different (independent keys). "
                "4. Verify both temporal windows prove keys expired before Shor's."
            ),
        }

    def proof_settlement_mismatch(self, order_id: str, audit_log: AuditLog) -> dict:
        """
        Generate proof of settlement mismatch.

        Proves: "Settlement does not match execution."

        Args:
            order_id: The order.
            audit_log: The audit log.

        Returns:
            Proof dict with quantum safety context.
        """
        flow = audit_log.get_trade_flow(order_id)

        return {
            "proof_type": "SETTLEMENT_MISMATCH",
            "order_id": order_id,
            "claim": "Settlement does not match execution",
            "generated_at": int(time.time()),
            "quantum_safety": self._build_quantum_safety_summary(flow),
            "execution": {
                "attestation": flow["execution"],
                "execution_sig": flow["execution_sig"],
                "quantum_proof": flow["execution_quantum_proof"],
            },
            "settlement": {
                "record": flow["settlement"],
                "settlement_sig": flow["settlement_sig"],
                "quantum_proof": flow["settlement_quantum_proof"],
            },
            "verification_instructions": (
                "1. Verify execution and settlement signatures. "
                "2. Recompute flow_merkle_hash from commitment_sig + execution_sig + broker_sig. "
                "3. Compare to recorded flow_merkle_hash. Mismatch = tampering. "
                "4. Check all 3 quantum seeds are independent. "
                "5. Verify all temporal windows."
            ),
        }

    @staticmethod
    def to_exportable_json(proof: dict) -> str:
        """
        Convert a proof dict to clean, formatted JSON.

        Suitable for sharing with brokers, regulators, or archiving.

        Args:
            proof: A proof dict from any of the proof_* methods.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(proof, indent=2, sort_keys=True, default=str)

    @staticmethod
    def _build_quantum_safety_summary(flow: dict) -> dict:
        """
        Build a quantum safety summary from a trade flow.

        Extracts seed commitments and temporal windows from all phases
        to create a concise safety overview.
        """
        seeds = {}
        temporal = {}

        if flow.get("commitment"):
            seeds["commitment_seed"] = flow["commitment"].get(
                "quantum_seed_commitment", "MISSING"
            )
            temporal["commitment_key_window"] = flow["commitment"].get(
                "key_temporal_window", {}
            )

        if flow.get("execution"):
            seeds["execution_seed"] = flow["execution"].get(
                "execution_quantum_seed_commitment", "MISSING"
            )
            temporal["execution_key_window"] = flow["execution"].get(
                "key_temporal_window", {}
            )

        if flow.get("settlement"):
            seeds["settlement_seed"] = flow["settlement"].get(
                "settlement_quantum_seed_commitment", "MISSING"
            )
            temporal["settlement_key_window"] = flow["settlement"].get(
                "settlement_temporal_window", {}
            )

        # Check independence
        seed_values = [v for v in seeds.values() if v != "MISSING"]
        all_unique = len(seed_values) == len(set(seed_values))

        return {
            "seed_commitments": seeds,
            "all_seeds_unique": all_unique,
            "temporal_timeline": temporal,
            "shor_attack_timeline": {
                "fastest_estimate": "7 days",
                "likely_estimate": "2-4 weeks",
            },
            "quantum_safety_margin": (
                "6.9+ days buffer (key lifetime: ~1 hour, Shor's minimum: ~7 days)"
            ),
        }
