"""
aether_protocol_c/identity.py

Out-of-band account identity binding.

The signature envelopes produced by EphemeralSigner / QuantumEphemeralKey
prove only that *a* valid ECDSA signature was produced by *some* key
embedded in that same envelope ("pubkey" field) -- they say nothing
about who controls that key.  Anyone can mint a fresh secp256k1
keypair, self-sign a fabricated commitment/execution/settlement flow
for any order_id, and every check in commitment.py / execution.py /
settlement.py / verify.py will report it as valid, because none of
them ever compare the embedded pubkey against a known, authorised
identity.

AccountKeyRegistry closes that gap: it lets an operator register, out-
of-band (e.g. at account onboarding, via a trusted channel -- NEVER
derived from the audit log or from a signature envelope itself), the
public key(s) that are actually authorised to sign on behalf of a
given account/order identity scope.  AuditVerifier.verify_trade_flow()
requires every phase's embedded pubkey to match a registered key
before that phase -- and the overall flow -- is treated as
authorised, so quantum_safe/chain_valid can no longer be satisfied by
a purely self-referential signature.
"""

from __future__ import annotations

import re
from typing import Dict, FrozenSet, Set

# ── Compressed secp256k1 pubkey format ───────────────────────────────────────
# 33-byte compressed key: "02"/"03" prefix + 32-byte x-coordinate, as hex.

_PUBKEY_RE = re.compile(r"^(02|03)[0-9a-f]{64}$")


# ── Errors ────────────────────────────────────────────────────────────────

class IdentityError(Exception):
    """Raised when identity registry operations fail."""


# ── Account -> authorised-key registry ───────────────────────────────────────

class AccountKeyRegistry:
    """
    Maps an account/order identity scope to the set of public keys
    authorised to sign on its behalf.

    This registry must be populated out-of-band (account onboarding,
    key-rotation ceremony, etc.).  It must NEVER be populated from data
    read out of the audit log or out of a signature envelope itself --
    doing so would recreate the exact self-referential tautology this
    class exists to prevent.
    """

    def __init__(self) -> None:
        self._authorized: Dict[str, Set[str]] = {}

    # -- mutation: register / revoke --

    def register(self, account_id: str, pubkey_hex: str) -> None:
        """
        Register a public key as authorised to sign for ``account_id``.

        Args:
            account_id: The account/order identity scope.
            pubkey_hex: Compressed secp256k1 public key -- 33-byte hex
                (66 chars, "02"/"03" prefix), as produced by
                ``EphemeralSigner.public_key_hex``.

        Raises:
            IdentityError: If account_id is empty or pubkey_hex is not
                a well-formed compressed pubkey.
        """
        if not account_id:
            raise IdentityError("account_id must be non-empty")
        pubkey_hex = pubkey_hex.lower()
        if not _PUBKEY_RE.match(pubkey_hex):
            raise IdentityError(f"Malformed compressed pubkey: {pubkey_hex!r}")
        self._authorized.setdefault(account_id, set()).add(pubkey_hex)

    def revoke(self, account_id: str, pubkey_hex: str) -> None:
        """Remove a previously registered key for ``account_id``."""
        self._authorized.get(account_id, set()).discard(pubkey_hex.lower())

    # -- query: fail-closed authorization checks --

    def is_authorized(self, account_id: str, pubkey_hex: str) -> bool:
        """
        Check whether ``pubkey_hex`` is a registered, authorised signer
        for ``account_id``.

        Fails closed: an account with no registered keys at all, or a
        key that was never registered (or was revoked), is NOT
        authorised.

        Args:
            account_id: The account/order identity scope.
            pubkey_hex: Compressed pubkey hex extracted from a
                signature envelope.

        Returns:
            True only if ``pubkey_hex`` is a currently registered key
            for ``account_id``.
        """
        if not account_id or not pubkey_hex:
            return False
        return pubkey_hex.lower() in self._authorized.get(account_id, set())

    def is_registered(self, account_id: str) -> bool:
        """Whether ``account_id`` has any registered keys at all."""
        return bool(self._authorized.get(account_id))

    def is_broker_authorized(self, scope: str, pubkey_hex: str) -> bool:
        """
        Check whether ``pubkey_hex`` is a registered broker key for ``scope``.

        Brokers are registered under a separate ``"broker:" + scope``
        namespace from account signers (see ``register``), so a
        compromised account-signer key can never also pass as an
        authorised broker key. Callers must use this instead of
        re-deriving the ``"broker:"`` prefix at each call site.
        """
        return self.is_authorized(f"broker:{scope}", pubkey_hex)

    def get_authorized_pubkeys(self, account_id: str) -> FrozenSet[str]:
        """Return the frozen set of pubkeys authorised for ``account_id``."""
        return frozenset(self._authorized.get(account_id, set()))
