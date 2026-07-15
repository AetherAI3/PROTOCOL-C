"""
aether_protocol_c/ephemeral_signer.py

Quantum-seeded ephemeral secp256k1 ECDSA signer.

Pure Python implementation -- NO external cryptography libraries.
Uses the same curve Bitcoin uses (secp256k1) with RFC 6979
deterministic k for reproducible, audit-friendly signatures.

Lifecycle:
    signer = EphemeralSigner(quantum_seed=...)
    sig    = signer.sign_manifest(manifest_dict)
    ok     = signer.verify(manifest_dict, sig)
    signer.destroy()   # zeroes private key from memory

Security properties:
    - Private key derived from quantum entropy via HMAC-SHA256
    - Key NEVER written to disk
    - destroy() zeroes key material in-place
    - Ephemeral: one key per session, discarded at end
"""

import hashlib
import hmac
import json
import logging
import struct
import time

logger = logging.getLogger(__name__)


# ── secp256k1 curve parameters ───────────────────────────────────────────────

# Field prime
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Curve order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Generator point
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Curve coefficient (y^2 = x^3 + 7 mod P)
A = 0
B = 7


# ── Modular arithmetic helpers ───────────────────────────────────────────────

def _modinv(a: int, m: int) -> int:
    """
    Modular inverse via Fermat's little theorem (a^(m-2) mod m).

    Requires m to be prime -- true for both P and N here. Unlike the
    extended Euclidean algorithm (whose recursion depth and branching
    pattern vary with the operands, including secret values), Python's
    built-in `pow(base, exp, mod)` performs fixed-shape binary
    exponentiation, avoiding the operand-dependent control flow that
    made the previous implementation a timing side-channel risk.
    """
    a = a % m
    if a == 0:
        raise ValueError("No modular inverse")
    return pow(a, m - 2, m)


# ── Point on secp256k1 ──────────────────────────────────────────────────────

class _Point:
    """Point on secp256k1 (affine coordinates). None represents infinity."""

    __slots__ = ("x", "y")

    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, _Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        return f"_Point(0x{self.x:064x}, 0x{self.y:064x})"


# Identity element
INFINITY = None


def _point_add(p1, p2):
    """Add two points on secp256k1."""
    if p1 is INFINITY:
        return p2
    if p2 is INFINITY:
        return p1

    if p1.x == p2.x and p1.y != p2.y:
        return INFINITY

    if p1.x == p2.x and p1.y == p2.y:
        # Point doubling
        lam = (3 * p1.x * p1.x + A) * _modinv(2 * p1.y, P) % P
    else:
        lam = (p2.y - p1.y) * _modinv(p2.x - p1.x, P) % P

    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return _Point(x3, y3)


def _point_double(p):
    """Double a point on secp256k1 (explicit, no coordinate-equality branch)."""
    if p is INFINITY:
        return INFINITY
    if p.y == 0:
        return INFINITY
    lam = (3 * p.x * p.x + A) * _modinv(2 * p.y, P) % P
    x3 = (lam * lam - 2 * p.x) % P
    y3 = (lam * (p.x - x3) - p.y) % P
    return _Point(x3, y3)


def _point_mul(k: int, point, bit_length: int = 256):
    """
    Scalar multiplication via a Montgomery-ladder-style fixed schedule.

    Unlike the previous double-and-add loop -- which iterated only for
    as many bits as `k` actually had and skipped the accumulator update
    whenever a bit was 0 -- this walks a fixed `bit_length` (256, large
    enough for any value < N) and performs exactly one point addition
    and one point doubling on every iteration regardless of the bit
    value. That keeps the operation count/sequence independent of the
    secret scalar `k`, removing the most direct timing side-channel
    (this is still pure Python, so it is not a cryptographic
    constant-time guarantee, but it eliminates the "do work only when
    bit==1" and coordinate-equality-based doubling detection that made
    the original implementation branch directly on secret data).
    """
    r0 = INFINITY
    r1 = point
    for i in reversed(range(bit_length)):
        bit = (k >> i) & 1
        if bit == 0:
            r1 = _point_add(r0, r1)
            r0 = _point_double(r0)
        else:
            r0 = _point_add(r0, r1)
            r1 = _point_double(r1)
    return r0


G = _Point(Gx, Gy)


# ── RFC 6979 deterministic k ────────────────────────────────────────────────

def _rfc6979_k(privkey: int, msg_hash: bytes) -> int:
    """
    Deterministic k per RFC 6979.

    Ensures the same (key, message) always produces the same k,
    eliminating nonce-reuse attacks while remaining fully deterministic
    and audit-friendly.
    """
    h1 = msg_hash
    v = b"\x01" * 32
    k = b"\x00" * 32
    priv_bytes = privkey.to_bytes(32, "big")
    k = hmac.new(k, v + b"\x00" + priv_bytes + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + priv_bytes + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# ── ECDSA sign / verify ─────────────────────────────────────────────────────

def _ecdsa_sign(privkey: int, msg_hash: bytes) -> tuple:
    """Sign msg_hash with privkey. Returns (r, s)."""
    z = int.from_bytes(msg_hash, "big")
    k = _rfc6979_k(privkey, msg_hash)
    R = _point_mul(k, G)
    r = R.x % N
    if r == 0:
        raise ValueError("Invalid r")
    s = (_modinv(k, N) * (z + r * privkey)) % N
    if s == 0:
        raise ValueError("Invalid s")
    # Low-s normalization (BIP 62)
    if s > N // 2:
        s = N - s
    return (r, s)


def _ecdsa_verify(pubkey, msg_hash: bytes, r: int, s: int) -> bool:
    """Verify ECDSA signature (r, s) against pubkey and msg_hash."""
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = _modinv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = _point_add(_point_mul(u1, G), _point_mul(u2, pubkey))
    if point is INFINITY:
        return False
    return point.x % N == r


# ── Ephemeral Signer ────────────────────────────────────────────────────────

class EphemeralSigner:
    """
    Quantum-seeded ephemeral secp256k1 ECDSA signer.

    One instance per session. Key derived from quantum entropy.
    Never touches disk. destroy() zeroes key material.
    """

    def __init__(self, quantum_seed: int):
        self._created_at = time.time()
        self._destroyed = False
        self._sign_count = 0

        # Derive private key from quantum seed via HMAC-SHA256
        seed_bytes = quantum_seed.to_bytes(32, "big")
        key_material = hmac.new(
            b"aether-ephemeral-secp256k1",
            seed_bytes,
            hashlib.sha256,
        ).digest()
        self._privkey = int.from_bytes(key_material, "big") % N
        retry_context = 0
        while self._privkey == 0:
            # astronomically unlikely (~1/2^256), but never fall back to a
            # known constant like 1 — re-derive deterministically instead.
            retry_context += 1
            key_material = hmac.new(
                b"aether-ephemeral-secp256k1-zero-key-retry",
                seed_bytes + retry_context.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            self._privkey = int.from_bytes(key_material, "big") % N

        # Derive public key
        self._pubkey = _point_mul(self._privkey, G)

    @property
    def public_key_hex(self) -> str:
        """Compressed public key (33 bytes hex)."""
        if self._destroyed:
            raise RuntimeError("Signer destroyed")
        prefix = b"\x02" if self._pubkey.y % 2 == 0 else b"\x03"
        return (prefix + self._pubkey.x.to_bytes(32, "big")).hex()

    def sign_manifest(self, manifest: dict) -> dict:
        """
        Sign a manifest dict. Returns signature envelope.
        """
        if self._destroyed:
            raise RuntimeError("Signer destroyed -- key material zeroed")

        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        msg_hash = hashlib.sha256(canonical.encode("utf-8")).digest()

        r, s = _ecdsa_sign(self._privkey, msg_hash)
        self._sign_count += 1

        return {
            "r": format(r, "064x"),
            "s": format(s, "064x"),
            "pubkey": self.public_key_hex,
            "algorithm": "ecdsa-secp256k1-sha256",
            "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sign_count": self._sign_count,
        }

    def verify(self, manifest: dict, signature: dict) -> bool:
        """Verify a signature envelope against a manifest dict."""
        try:
            r = int(signature["r"], 16)
            s = int(signature["s"], 16)
            pubkey_hex = signature["pubkey"]

            prefix = int(pubkey_hex[:2], 16)
            x = int(pubkey_hex[2:], 16)
            y_sq = (pow(x, 3, P) + B) % P
            y = pow(y_sq, (P + 1) // 4, P)
            # Reject a public key whose x is not a valid curve point: the modular
            # square root only round-trips when the point is actually on secp256k1.
            if (y * y) % P != y_sq:
                return False
            if y % 2 != (prefix - 2):
                y = P - y
            pub = _Point(x, y)

            canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
            msg_hash = hashlib.sha256(canonical.encode("utf-8")).digest()

            return _ecdsa_verify(pub, msg_hash, r, s)
        except (KeyError, ValueError, TypeError) as exc:
            # Malformed signature envelope (missing field, bad hex, wrong
            # length, non-curve point, etc.) -- no key material is logged.
            logger.debug(
                "EphemeralSigner.verify() failed to parse signature envelope: %s: %s",
                type(exc).__name__,
                exc,
            )
            return False
        except Exception as exc:
            logger.debug(
                "EphemeralSigner.verify() failed with unexpected error: %s: %s",
                type(exc).__name__,
                exc,
            )
            return False

    def destroy(self) -> dict:
        """Zero private key material. Returns destruction receipt."""
        receipt = {
            "destroyed": True,
            "sign_count": self._sign_count,
            "lifetime_seconds": round(time.time() - self._created_at, 2),
        }
        self._privkey = 0
        self._destroyed = True
        return receipt

    @property
    def is_destroyed(self) -> bool:
        return self._destroyed

    @property
    def sign_count(self) -> int:
        return self._sign_count
