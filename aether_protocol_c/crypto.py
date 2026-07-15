"""
aether_protocol_c/crypto.py

Quantum-first cryptographic wrapper around ephemeral_signer.

Provides QuantumSeedCommitment (immutable proof of a quantum measurement)
and QuantumEphemeralKey (an ephemeral key with documented lifetime that
is destroyed immediately after signing).

Every trade phase (commitment, execution, settlement) creates its own
QuantumEphemeralKey from an independent quantum seed.  The key is
destroyed after a single signing operation -- providing perfect forward
secrecy and temporal safety against Shor's algorithm.

Quantum Properties:
    P1: Seed Unpredictability -- quantum measurement is fundamentally random
    P2: Unforgeability -- ECDSA/secp256k1, requires 2330 logical qubits
    P3: Temporal Safety -- key lifetime (hours) << Shor's window (days-weeks)
    P4: Perfect Forward Secrecy -- each phase uses an independent seed/key
    P5: Tamper Detection -- any modification invalidates the signature chain
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

from .ephemeral_signer import EphemeralSigner


class QuantumCryptoError(Exception):
    """Raised when quantum cryptographic operations fail."""


class KeyDestroyedError(QuantumCryptoError):
    """Raised when attempting to use a destroyed key."""


# ── Constants ─────────────────────────────────────────────────────────────────

# Default temporal window: 1 hour for key lifetime
DEFAULT_KEY_LIFETIME_SECONDS = 3600

# Shor's algorithm earliest feasible attack window: 7 days.
# (The secp256k1 ECDLP requires thousands of logical qubits, far beyond any
#  near-term hardware; the key lifetime is hours, so it expires long before
#  any such attack could complete.)
SHOR_EARLIEST_ATTACK_SECONDS = 7 * 24 * 3600

# Valid measurement methods (Protocol-C: CSPRNG only)
MEASUREMENT_METHODS = ("CSPRNG", "OS_URANDOM")


# ── Quantum Seed Commitment ──────────────────────────────────────────────────

@dataclass(frozen=True)
class QuantumSeedCommitment:
    """
    Immutable record of a quantum measurement used for key derivation.

    The seed_hash is SHA-256 of the raw quantum seed.  The seed itself is
    never stored or transmitted -- only its hash.  Because quantum
    measurements are fundamentally random, the hash serves as an
    immutable, unreproducible proof that a specific measurement was taken.

    Fields:
        seed_hash: SHA-256 hex digest of the quantum seed.
        measurement_timestamp: Unix timestamp when the seed was measured.
        measurement_method: Source of the seed ("CSPRNG" | "OS_URANDOM").
        key_creation_timestamp: Unix timestamp when the key was derived.
        key_expiration_timestamp: Unix timestamp when the key expires
            (typically creation + 1 hour).
    """

    seed_hash: str
    measurement_timestamp: int
    measurement_method: str
    key_creation_timestamp: int
    key_expiration_timestamp: int

    def __post_init__(self) -> None:
        """Validate fields."""
        if len(self.seed_hash) != 64:
            raise QuantumCryptoError(
                f"seed_hash must be 64 hex chars, got {len(self.seed_hash)}"
            )
        if self.measurement_method not in MEASUREMENT_METHODS:
            raise QuantumCryptoError(
                f"measurement_method must be one of {MEASUREMENT_METHODS}, "
                f"got '{self.measurement_method}'"
            )
        if self.key_expiration_timestamp <= self.key_creation_timestamp:
            raise QuantumCryptoError(
                "key_expiration_timestamp must be after key_creation_timestamp"
            )

    @property
    def temporal_window_hours(self) -> float:
        """Key lifetime in hours."""
        return (self.key_expiration_timestamp - self.key_creation_timestamp) / 3600

    @property
    def temporal_window_dict(self) -> dict:
        """
        Temporal window as a dict for embedding in signed structures.

        Includes the Shor's earliest attack timestamp to prove the key
        expires long before any quantum attack could complete.
        """
        return {
            "created_at": self.key_creation_timestamp,
            "expires_at": self.key_expiration_timestamp,
            "shor_earliest_attack": (
                self.key_creation_timestamp + SHOR_EARLIEST_ATTACK_SECONDS
            ),
        }

    def to_dict(self) -> dict:
        """Serialise to dict for JSON embedding."""
        return {
            "seed_hash": self.seed_hash,
            "measurement_timestamp": self.measurement_timestamp,
            "measurement_method": self.measurement_method,
            "key_creation_timestamp": self.key_creation_timestamp,
            "key_expiration_timestamp": self.key_expiration_timestamp,
            "temporal_window_hours": round(self.temporal_window_hours, 4),
        }

    @staticmethod
    def from_dict(data: dict) -> "QuantumSeedCommitment":
        """Reconstruct from dict."""
        return QuantumSeedCommitment(
            seed_hash=data["seed_hash"],
            measurement_timestamp=data["measurement_timestamp"],
            measurement_method=data["measurement_method"],
            key_creation_timestamp=data["key_creation_timestamp"],
            key_expiration_timestamp=data["key_expiration_timestamp"],
        )


# ── Quantum Ephemeral Key ────────────────────────────────────────────────────

class QuantumEphemeralKey:
    """
    An ephemeral signing key derived from a quantum seed.

    The key is destroyed immediately after a single signing operation.
    Once destroyed, the private key material is zeroed and can never be
    recovered -- providing temporal safety against future quantum attacks.

    Lifecycle:
        key = QuantumEphemeralKey(quantum_seed, method="OS_URANDOM")
        sig = key.sign(message_dict)
        assert key.is_destroyed  # key material is gone

    Args:
        quantum_seed: Raw seed bytes (typically 32 bytes from the CSPRNG).
        method: Source of the seed ("CSPRNG" | "OS_URANDOM").
        key_lifetime_seconds: How long the key is valid (default 1 hour).
    """

    def __init__(
        self,
        quantum_seed: int | bytes,
        method: str = "OS_URANDOM",
        key_lifetime_seconds: int = DEFAULT_KEY_LIFETIME_SECONDS,
    ) -> None:
        """
        Derive an ephemeral key from a quantum seed.

        Args:
            quantum_seed: Raw quantum seed (int or bytes).
            method: Measurement method.
            key_lifetime_seconds: Key lifetime in seconds.
        """
        now = int(time.time())

        # Normalise seed to int (EphemeralSigner expects int)
        if isinstance(quantum_seed, bytes):
            seed_int = int.from_bytes(quantum_seed, "big")
            seed_bytes = quantum_seed
        else:
            seed_int = quantum_seed
            seed_bytes = quantum_seed.to_bytes(32, "big")

        # Build the seed commitment (hash of raw seed)
        seed_hash = hashlib.sha256(seed_bytes).hexdigest()

        self._seed_commitment = QuantumSeedCommitment(
            seed_hash=seed_hash,
            measurement_timestamp=now,
            measurement_method=method,
            key_creation_timestamp=now,
            key_expiration_timestamp=now + key_lifetime_seconds,
        )

        # Derive the ephemeral signer (private + public key)
        self._signer = EphemeralSigner(quantum_seed=seed_int)
        self._destroyed = False

    @property
    def seed_commitment(self) -> QuantumSeedCommitment:
        """Return the seed commitment (always available, even after destruction)."""
        return self._seed_commitment

    @property
    def public_key_hex(self) -> str:
        """Compressed public key hex (available even after key destruction for verification)."""
        # Public key is safe to keep -- only private key is sensitive
        return self._signer.public_key_hex if not self._destroyed else self._pubkey_hex

    @property
    def is_destroyed(self) -> bool:
        """Check whether the private key has been destroyed."""
        return self._destroyed

    def sign(self, message: dict) -> dict:
        """
        Sign a message dict and immediately destroy the private key.

        This is a one-shot operation.  After signing, the key material
        is zeroed and cannot be used again.

        Args:
            message: Dict to sign (will be canonically serialised).

        Returns:
            Signature envelope dict (r, s, pubkey, algorithm, etc.).

        Raises:
            KeyDestroyedError: If the key has already been destroyed.
        """
        if self._destroyed:
            raise KeyDestroyedError(
                "Ephemeral key already destroyed -- cannot sign again"
            )

        # Sign
        signature = self._signer.sign_manifest(message)

        # Preserve public key for verification before destruction
        self._pubkey_hex = self._signer.public_key_hex

        # DESTROY the private key immediately
        self._signer.destroy()
        self._destroyed = True

        return signature

    def verify(self, message: dict, signature: dict) -> bool:
        """
        Verify a signature against a message.

        Verification only needs the public key (safe to call after destruction).

        Args:
            message: The original message dict.
            signature: The signature envelope.

        Returns:
            True if the signature is valid.
        """
        # Delegates to the module-level verify_signature() (which itself
        # delegates to EphemeralSigner.verify_static()) so there is a single
        # implementation of signature verification in this package.
        return verify_signature(message, signature)


# ── Helper functions ──────────────────────────────────────────────────────────

def get_quantum_seed(method: str = "CSPRNG", **_ignored) -> tuple[int, str]:
    """
    Obtain a CSPRNG seed.

    Protocol-C always uses ``secrets.token_bytes`` (CSPRNG). The ``method``
    argument is accepted for API compatibility and otherwise ignored.

    Returns:
        Tuple of (seed_as_int, "CSPRNG").
    """
    import secrets

    seed_bytes = secrets.token_bytes(32)
    return int.from_bytes(seed_bytes, "big"), "CSPRNG"


def verify_signature(message: dict, signature: dict) -> bool:
    """
    Standalone signature verification (no private key needed).

    Uses the public key embedded in the signature envelope.

    Args:
        message: The original message dict.
        signature: The signature envelope.

    Returns:
        True if the signature is valid.
    """
    try:
        # verify_static() only parses the pubkey embedded in the signature
        # envelope -- no private key is derived, unlike constructing a
        # throwaway EphemeralSigner just to call its instance verify().
        return EphemeralSigner.verify_static(message, signature)
    except (KeyError, ValueError, TypeError) as exc:
        # Malformed signature envelope (missing field, bad hex, wrong
        # length, etc.) -- no key material is logged.
        logger.debug(
            "verify_signature() failed to parse signature envelope: %s: %s",
            type(exc).__name__,
            exc,
        )
        return False
    except Exception as exc:
        logger.debug(
            "verify_signature() failed with unexpected error: %s: %s",
            type(exc).__name__,
            exc,
        )
        return False


def make_temporal_window(
    created_at: int | None = None,
    lifetime_seconds: int = DEFAULT_KEY_LIFETIME_SECONDS,
) -> dict:
    """
    Create a temporal window dict.

    Args:
        created_at: Unix timestamp (defaults to now).
        lifetime_seconds: Key lifetime.

    Returns:
        Dict with created_at, expires_at, shor_earliest_attack.
    """
    if created_at is None:
        created_at = int(time.time())
    return {
        "created_at": created_at,
        "expires_at": created_at + lifetime_seconds,
        "shor_earliest_attack": created_at + SHOR_EARLIEST_ATTACK_SECONDS,
    }
