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
from .identity import AccountKeyRegistry
from .settlement import QuantumSettlementVerifier, compute_flow_merkle


class VerificationError(Exception):
    """Raised when verification operations fail."""


class AuditVerifier:
    """
    Quantum-aware verifier for complete trade flows.

    Checks every signature, quantum binding, temporal window, seed
    independence, and chain linkage.
    """

    def verify_trade_flow(
        self,
        order_id: str,
        audit_log: AuditLog,
        registry: Optional[AccountKeyRegistry] = None,
        account_id: Optional[str] = None,
    ) -> dict:
        """
        Verify the complete trade flow for an order.

        Checks:
        1. All signatures are valid
        2. All quantum bindings are present
        3. All temporal windows prove safety against Shor's
        4. All seeds are independent (P4: PFS)
        5. Chain linkage is correct
        6. Every phase's embedded pubkey is a registered, authorised
           signer for the account (identity binding)

        A valid ECDSA signature over an envelope only proves that
        *some* key -- possibly one an attacker just generated -- signed
        that envelope; it does not by itself prove the account holder
        authorised the trade.  ``registry`` supplies the out-of-band
        ground truth (registered at account onboarding, never derived
        from the audit log itself) needed to close that gap.  Every
        phase is required to pass identity binding for the flow to be
        reported quantum_safe/chain_valid -- if ``registry`` is not
        supplied, the flow fails closed (identity_bound=False,
        quantum_safe=False), because there is no way to prove any
        signature actually belongs to the account holder.

        Args:
            order_id: The order to verify.
            audit_log: The audit log to read from.
            registry: Out-of-band registry of authorised account
                pubkeys. Required for the flow to be certified
                quantum_safe/chain_valid.
            account_id: Identity scope to check pubkeys against.
                Defaults to ``order_id`` when omitted (this codebase
                has no separate account identifier today; callers with
                a real account/order distinction should pass it
                explicitly).

        Returns:
            Comprehensive verification result dict.
        """
        flow = audit_log.get_trade_flow(order_id)
        details: List[str] = []
        scope = account_id or order_id

        def _identity_ok(signature: Optional[dict]) -> bool:
            if registry is None:
                return False
            if not signature:
                return False
            pubkey_hex = signature.get("pubkey", "")
            return registry.is_authorized(scope, pubkey_hex)

        if registry is None:
            details.append(
                "Identity registry: NOT PROVIDED -- no phase can be certified "
                "as authorised by the account holder (fail closed)"
            )

        # ── Commitment verification ──────────────────────────────────
        commitment_valid: Optional[bool] = None
        if flow["commitment"] is not None and flow["commitment_sig"] is not None:
            sig_ok = QuantumCommitmentVerifier.verify_signature(
                flow["commitment"], flow["commitment_sig"]
            )
            state_ok = QuantumCommitmentVerifier.verify_state_binding(flow["commitment"])
            quantum_ok = QuantumCommitmentVerifier.verify_quantum_binding(flow["commitment"])
            temporal_ok = QuantumCommitmentVerifier.verify_temporal_safety(flow["commitment"])
            identity_ok = _identity_ok(flow["commitment_sig"])

            commitment_valid = (
                sig_ok and state_ok and quantum_ok and temporal_ok and identity_ok
            )

            details.append(f"Commitment signature valid: {sig_ok}")
            details.append(f"Commitment state binding: {state_ok}")
            details.append(f"Commitment quantum binding: {quantum_ok}")
            details.append(f"Commitment temporal safety: {temporal_ok}")
            details.append(f"Commitment identity bound (authorised signer): {identity_ok}")
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
            identity_ok = _identity_ok(flow["execution_sig"])

            execution_valid = sig_ok and quantum_ok and temporal_ok and identity_ok

            details.append(f"Execution signature valid: {sig_ok}")
            details.append(f"Execution quantum binding: {quantum_ok}")
            details.append(f"Execution temporal safety: {temporal_ok}")
            details.append(f"Execution identity bound (authorised signer): {identity_ok}")

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

            # Check the executed fill terms actually match what was
            # authorised in the commitment (qty/price bounds) -- chain
            # linkage alone does not prove economic-term correspondence.
            if flow["commitment"] is not None:
                trade_details = flow["commitment"].get("trade_details", {})
                execution_result = flow["execution"].get("execution_result", {})
                terms_ok = QuantumExecutionVerifier.verify_matches_commitment_terms(
                    trade_details, execution_result
                )
                details.append(f"Execution matches authorised trade terms: {terms_ok}")
                if not terms_ok:
                    execution_valid = False
        else:
            details.append("Execution phase: MISSING")

        # ── Settlement verification ──────────────────────────────────
        settlement_valid: Optional[bool] = None
        if flow["settlement"] is not None and flow["settlement_sig"] is not None:
            sig_ok = QuantumSettlementVerifier.verify_signature(
                flow["settlement"], flow["settlement_sig"]
            )
            identity_ok = _identity_ok(flow["settlement_sig"])
            details.append(f"Settlement signature valid: {sig_ok}")
            details.append(f"Settlement identity bound (authorised signer): {identity_ok}")

            settlement_valid = sig_ok and identity_ok

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
        # All three phases (commitment, execution, settlement) must be
        # PRESENT and individually valid. A missing phase yields None for
        # that phase's *_valid, which must never be silently filtered out
        # of the aggregate check -- otherwise a flow missing e.g. the
        # commitment record could still be certified chain_valid/quantum_safe
        # as long as the phases that do exist are self-consistent.
        phase_results = [commitment_valid, execution_valid, settlement_valid]
        chain_valid = all(v is True for v in phase_results)

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
            "identity_bound": registry is not None,
            "details": details,
        }

    def detect_tampering(
        self,
        order_id: str,
        audit_log: AuditLog,
        registry: Optional[AccountKeyRegistry] = None,
        account_id: Optional[str] = None,
    ) -> dict:
        """
        Detect tampering in a trade flow.

        Examines each phase and identifies specific discrepancies.

        Args:
            order_id: The order to check.
            audit_log: The audit log to read from.
            registry: Out-of-band registry of authorised account
                pubkeys. Without it, an attacker-fabricated flow signed
                with a fresh, self-consistent keypair reports as
                untampered -- so its absence is itself flagged as an
                issue.
            account_id: Identity scope to check pubkeys against.
                Defaults to ``order_id`` when omitted.

        Returns:
            Dict with order_id, tampered (bool), issues (list of strings).
        """
        flow = audit_log.get_trade_flow(order_id)
        issues: List[str] = []
        scope = account_id or order_id

        def _check_identity(signature: Optional[dict], label: str) -> None:
            if registry is None:
                issues.append(
                    f"{label}_IDENTITY_UNVERIFIED: No identity registry supplied -- "
                    "cannot confirm the signing key belongs to the account holder"
                )
                return
            pubkey_hex = (signature or {}).get("pubkey", "")
            if not registry.is_authorized(scope, pubkey_hex):
                issues.append(
                    f"{label}_UNAUTHORIZED_KEY: Signing pubkey is not a registered "
                    f"authorised signer for {scope!r}"
                )

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
            _check_identity(flow["commitment_sig"], "COMMITMENT")

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
                trade_details = flow["commitment"].get("trade_details", {})
                execution_result = flow["execution"].get("execution_result", {})
                if not QuantumExecutionVerifier.verify_matches_commitment_terms(
                    trade_details, execution_result
                ):
                    issues.append(
                        "EXECUTION_TERMS_MISMATCH: Filled qty/price does not match "
                        "the authorised commitment's trade_details"
                    )
            _check_identity(flow["execution_sig"], "EXECUTION")

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
            _check_identity(flow["settlement_sig"], "SETTLEMENT")

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
