"""
aether_protocol_c/execution.py

Quantum-chained execution attestations.

A QuantumExecutionAttestation proves that an execution matched the
authorised commitment, signed with a DIFFERENT ephemeral key derived
from a DIFFERENT quantum seed.

Chain:
    Commitment Sig (quantum seed #1, destroyed)
          |
    Execution Sig (quantum seed #2, destroyed) [references commitment sig]
          |
    Settlement Sig (quantum seed #3, destroyed) [references both prior sigs]

Quantum Safety:
    - Two independent quantum seeds (commitment + execution)
    - Two independent ephemeral keys (both destroyed)
    - Even if one key is somehow recovered, the other remains safe (P4: PFS)
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from .crypto import (
    QuantumEphemeralKey,
    verify_signature,
    make_temporal_window,
)
from .state import AccountSnapshot


class ExecutionError(Exception):
    """Raised when execution attestation operations fail."""


@dataclass(frozen=True)
class ExecutionResult:
    """
    Immutable record of a trade execution result.

    Fields:
        order_id: The order that was executed.
        filled_qty: Quantity actually filled.
        fill_price: Price at which the fill occurred.
        execution_timestamp: Unix timestamp of execution.
        broker_response: Raw broker response dict.
    """

    order_id: str
    filled_qty: float
    fill_price: float
    execution_timestamp: int = field(default_factory=lambda: int(time.time()))
    broker_response: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        """Canonical JSON-serialisable representation."""
        return {
            "order_id": self.order_id,
            "filled_qty": self.filled_qty,
            "fill_price": self.fill_price,
            "execution_timestamp": self.execution_timestamp,
            "broker_response": self.broker_response,
        }

    def to_hash(self) -> str:
        """Compute canonical SHA-256 hash of the execution result."""
        canonical = json.dumps(self.to_json(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class QuantumExecutionAttestation:
    """
    Proof of execution, signed with a DIFFERENT ephemeral key from a
    DIFFERENT quantum seed than the commitment.

    Fields:
        commitment_sig: The commitment's signature envelope (immutable reference).
        commitment_quantum_seed_commitment: Hash of commitment's quantum seed.
        execution_result: Dict of execution results.
        execution_quantum_seed_commitment: Hash of THIS phase's quantum seed.
        new_account_state_hash: Account state hash AFTER the fill.
        nonce_after: Nonce after execution (commitment nonce + 1).
        key_temporal_window: Temporal window of THIS key.
    """

    commitment_sig: dict
    commitment_quantum_seed_commitment: str
    execution_result: dict
    execution_quantum_seed_commitment: str
    new_account_state_hash: str
    nonce_after: int
    key_temporal_window: dict

    def to_signable_dict(self) -> dict:
        """
        Canonical signable representation.

        References the commitment via its signature and seed commitment.
        Includes execution result, new state, and this phase's quantum binding.

        Returns:
            Canonical dict ready for signing.
        """
        return {
            "commitment_sig": self.commitment_sig,
            "commitment_quantum_seed_commitment": self.commitment_quantum_seed_commitment,
            "execution_result": self.execution_result,
            "execution_quantum_seed_commitment": self.execution_quantum_seed_commitment,
            "new_account_state_hash": self.new_account_state_hash,
            "nonce_after": self.nonce_after,
            "key_temporal_window": self.key_temporal_window,
        }

    @classmethod
    def create_and_sign(
        cls,
        commitment_sig: dict,
        commitment_seed_hash: str,
        execution_result: ExecutionResult,
        new_account_state: AccountSnapshot,
        quantum_seed: int | bytes,
        measurement_method: str = "OS_URANDOM",
    ) -> Tuple[dict, dict, "QuantumExecutionAttestation"]:
        """
        Attest execution with a NEW quantum seed (independent from commitment).

        Args:
            commitment_sig: Signature envelope from the commitment phase.
            commitment_seed_hash: Quantum seed hash from the commitment.
            execution_result: ExecutionResult with fill details.
            new_account_state: Account state after execution.
            quantum_seed: NEW quantum seed for this phase.
            measurement_method: Source of the seed.

        Returns:
            Tuple of (attestation_dict, signature_envelope, attestation_object).

        Raises:
            ExecutionError: If signing fails.
        """
        # Derive NEW ephemeral key from NEW quantum seed
        ephemeral_key = QuantumEphemeralKey(
            quantum_seed=quantum_seed,
            method=measurement_method,
        )

        attestation = cls(
            commitment_sig=commitment_sig,
            commitment_quantum_seed_commitment=commitment_seed_hash,
            execution_result=execution_result.to_json(),
            execution_quantum_seed_commitment=ephemeral_key.seed_commitment.seed_hash,
            new_account_state_hash=new_account_state.to_hash(),
            nonce_after=new_account_state.nonce,
            key_temporal_window=ephemeral_key.seed_commitment.temporal_window_dict,
        )

        signable = attestation.to_signable_dict()

        try:
            signature = ephemeral_key.sign(signable)
        except Exception as exc:
            raise ExecutionError(f"Failed to sign attestation: {exc}") from exc

        if not ephemeral_key.is_destroyed:
            raise ExecutionError("CRITICAL: Key not destroyed after signing")

        return signable, signature, attestation


class QuantumExecutionVerifier:
    """
    Verifies quantum execution attestation signatures and linkage.
    """

    @staticmethod
    def verify_signature(attestation: dict, signature: dict) -> bool:
        """Verify the execution attestation signature."""
        return verify_signature(attestation, signature)

    @staticmethod
    def verify_references_commitment(attestation: dict, commitment_sig: dict) -> bool:
        """Verify the attestation references the correct commitment."""
        return attestation.get("commitment_sig") == commitment_sig

    @staticmethod
    def verify_matches_commitment_terms(
        trade_details: dict,
        execution_result: dict,
        price_tolerance: float = 0.02,
    ) -> bool:
        """
        Verify the execution's actual fill terms correspond to what the
        commitment authorised.

        A valid ``commitment_sig`` reference (dict-equality of the
        signature envelope, see ``verify_references_commitment``) only
        proves the execution phase points at the right commitment
        record -- it says nothing about whether the economic terms that
        were actually filled (quantity, price) stay within what
        ``trade_details`` authorised. Without this check, a validly
        signed execution attestation could report an arbitrarily larger
        filled_qty and/or wildly different fill_price than what was
        committed to, and every other check (signature, quantum
        binding, nonce, seed independence, chain linkage) would still
        pass.

        Args:
            trade_details: The commitment's authorised trade terms
                (expects "qty" and "price" keys).
            execution_result: The execution's ``execution_result`` dict
                (expects "filled_qty" and "fill_price" keys).
            price_tolerance: Maximum allowed fractional deviation of
                fill_price from the authorised price (default 2%).

        Returns:
            True if filled_qty does not exceed the authorised qty and
            fill_price is within tolerance of the authorised price.
            False if required fields are missing or terms diverge.
        """
        if not isinstance(trade_details, dict) or not isinstance(execution_result, dict):
            return False

        authorised_qty = trade_details.get("qty")
        authorised_price = trade_details.get("price")
        filled_qty = execution_result.get("filled_qty")
        fill_price = execution_result.get("fill_price")

        if authorised_qty is None or authorised_price is None:
            return False
        if filled_qty is None or fill_price is None:
            return False

        try:
            authorised_qty = float(authorised_qty)
            authorised_price = float(authorised_price)
            filled_qty = float(filled_qty)
            fill_price = float(fill_price)
        except (TypeError, ValueError):
            return False

        if filled_qty < 0 or filled_qty > authorised_qty:
            return False

        if authorised_price == 0:
            return fill_price == 0

        deviation = abs(fill_price - authorised_price) / abs(authorised_price)
        return deviation <= price_tolerance

    @staticmethod
    def verify_nonce_increment(commitment_nonce: int, attestation: dict) -> bool:
        """Verify that nonce_after == commitment_nonce + 1."""
        return attestation.get("nonce_after") == commitment_nonce + 1

    @staticmethod
    def verify_independent_seeds(
        commitment_seed_hash: str, execution_seed_hash: str
    ) -> bool:
        """
        Verify that commitment and execution used different quantum seeds.

        P4 (Perfect Forward Secrecy): each phase must use an independent seed.

        Args:
            commitment_seed_hash: Seed hash from commitment.
            execution_seed_hash: Seed hash from execution.

        Returns:
            True if seeds are different (independent measurements).
        """
        return commitment_seed_hash != execution_seed_hash

    @staticmethod
    def verify_quantum_binding(attestation: dict) -> bool:
        """Check that quantum seed binding is present and valid."""
        seed_hash = attestation.get("execution_quantum_seed_commitment", "")
        if not seed_hash or len(seed_hash) != 64:
            return False

        window = attestation.get("key_temporal_window", {})
        if not isinstance(window, dict):
            return False
        if "created_at" not in window or "expires_at" not in window:
            return False

        return True

    @staticmethod
    def verify_temporal_safety(attestation: dict) -> bool:
        """Verify key expires before Shor's earliest attack window."""
        window = attestation.get("key_temporal_window", {})
        expires_at = window.get("expires_at", 0)
        shor_attack = window.get("shor_earliest_attack", 0)

        if not expires_at or not shor_attack:
            return False
        return expires_at < shor_attack
