# Security Policy

Protocol-C is a cryptographic commitment library. This document states what it
does and does not protect against, and how to report a vulnerability.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the
[repository](https://github.com/DBarr3/protocol-c/security/advisories/new),
or email the maintainer at the address listed on
[aethersystems.net](https://aethersystems.net).

Please include a description, reproduction steps, and impact. We aim to
acknowledge reports within a few days and to coordinate a fix and disclosure
timeline with you.

## Supported versions

Protocol-C is pre-1.0. Security fixes target the latest released version and
`main`. Pin a version in production and watch releases.

## Threat model

**What Protocol-C protects:**

- **Integrity / tamper-evidence.** Any modification to committed data
  invalidates its signature. A stored commitment cannot be silently altered.
- **Non-repudiation.** A valid signature proves the committed bytes existed and
  were signed by the holder of the ephemeral key at signing time.
- **Forward secrecy.** Each commitment uses an independent CSPRNG seed and a
  single-use key whose private half is zeroed immediately after signing.
  Compromise of one commitment's key reveals nothing about others.

**What Protocol-C does NOT provide:**

- **Post-quantum cryptography.** secp256k1 ECDSA is not quantum-resistant. See
  "On 'quantum-safe'" below. If you need standardized PQC signatures
  (ML-DSA / SLH-DSA), this is not a drop-in.
- **Confidentiality.** Commitments are signed, not encrypted. Do not put secrets
  in the committed payload; the data is recoverable from the audit log.
- **Trusted timestamping by default.** The temporal window uses local system
  time. For third-party-verifiable time, use the optional `[timestamp]` extra
  (RFC 3161) or an external timestamp authority.
- **Key custody for long-lived identities.** There is intentionally no long-lived
  private key to manage — that's the design. If you need a stable signing
  identity, layer it above Protocol-C.

## On "quantum-safe"

The "quantum-safe" claim is a **temporal-safety** argument, not a claim of
post-quantum security:

- The signature scheme (secp256k1 ECDSA) is classical and would be breakable by a
  sufficiently large fault-tolerant quantum computer running Shor's algorithm.
  No such machine exists today; breaking secp256k1 is estimated to require on the
  order of thousands of logical qubits.
- Protocol-C's mitigation is that the **private key is destroyed within ~1 hour
  (default, configurable) of creation** — far inside any plausible attack window.
  Shor's algorithm needs the key to exist to be useful; a zeroed key cannot be
  recovered. The defense is the key's *absence*, not the algorithm's strength.

Treat Protocol-C as a **forward-secret, tamper-evident commitment layer** with a
documented temporal margin — not as post-quantum cryptography.

This public package is **CSPRNG-only**: all entropy comes from
`secrets.token_bytes`. The quantum-hardware entropy variant is a separate,
private project and ships no code here.

## Security hardening & SOC 2 Type II readiness

Protocol-C is not SOC 2 certified — no independent auditor has issued a
report. What's here is an honest account of the engineering work done so
far toward that posture, so anyone evaluating the library for a
compliance-relevant use case can see exactly what's been checked and
what's still open.

**2026-07-15 hardening pass** (tracked in [PR #8](https://github.com/DBarr3/protocol-c/pull/8)):
a multi-round audit → adversarial review → fix cycle, followed by standing
red-team/blue-team sparring rounds against the hardened surface. Every
fix carries a dedicated regression test (suite: 137 tests). Summary —
full detail in [CHANGELOG.md](CHANGELOG.md#unreleased---2026-07-15):

| Area | What was found and fixed |
|---|---|
| TSA verification | `verify()` wasn't checking the TSA's actual signed attestation — now parses and verifies the real CMS/TSTInfo structure. |
| Network (SSRF) | Outbound TSA requests now require HTTPS and reject private/loopback/link-local/metadata-endpoint hosts. |
| Timing side-channels | Modular inverse and scalar multiplication in the secp256k1 signer moved to fixed-shape/constant-iteration implementations. |
| Key hygiene | `destroy()` now zeroes the private-key buffer in place. |
| Business-logic integrity | Execution attestations are now cross-checked against the commitment's authorised trade terms; broker settlement acknowledgements are now cryptographically authenticated. |
| Identity binding | New `AccountKeyRegistry` closes a gap where any self-signed key could pass every check with no proof of account ownership. |
| Concurrency | Audit-log writes are now lock-guarded against a race that could silently overwrite a duplicate record. |
| Availability | DoS bounds added on unbounded JSON/HTTP-response reads. |
| Observability | Silent exception swallowing removed from the audit-rebuild and TSA request paths in favor of structured logging. |

This addresses SOC 2 control areas most relevant to a signing/attestation
library — **change integrity** (tamper detection, non-repudiation),
**logical access** (identity binding on signers), and **availability**
(DoS bounds, graceful failure) — but a hardening pass is not a
certification. Still open before any real SOC 2 Type II claim: an
independent third-party audit, formal control documentation, and
continuous-monitoring evidence over the required observation period. If
you're evaluating Protocol-C for a compliance-relevant deployment, treat
this section as "here's what's been checked," not "this is certified."

## Cryptographic implementation notes

- **Signer:** original pure-Python secp256k1 ECDSA in `ephemeral_signer.py`,
  using RFC 6979 deterministic-k (eliminates nonce-reuse) and BIP 62 low-s
  normalization. No third-party crypto library is used in the core path.
- **Key derivation:** the private key is derived from seed entropy via
  HMAC-SHA256, reduced mod the curve order `N`.
- **Canonicalization:** messages are signed over canonical JSON
  (`sort_keys=True`, compact separators) hashed with SHA-256, so verification is
  byte-stable across platforms.
- **Audit log:** append-only JSONL is the source of truth; the SQLite companion
  is an index only. Treat the JSONL file as immutable in storage (write-once
  media or object-lock buckets recommended for high-assurance use).

If you find a flaw in any of the above, please report it privately as described
at the top of this document.
