# Changelog

## [Unreleased] - 2026-07-15

### Security

Multi-round security-hardening pass (audit → adversarial review → fix,
followed by standing red-team/blue-team sparring rounds) ahead of SOC 2
Type II control-mapping work. See [SECURITY.md](SECURITY.md#security-hardening--soc-2-type-ii-readiness)
for the full readiness summary. Highlights:

- **`verify()` on TSA timestamps was not actually verifying the TSA's
  attestation** — it compared `sha256(data)` against a caller-supplied
  `message_imprint` field instead of the hash the TSA itself signed. Now
  DER/CMS-decodes the real response and checks the TSA-attested hash and
  `SignerInfo` signature.
- **SSRF**: outbound TSA requests now require `https://` and resolved hosts
  are checked against private/loopback/link-local/metadata-endpoint ranges.
- **Timing side-channels** in the pure-Python secp256k1 signer: modular
  inverse moved to fixed-shape exponentiation; scalar multiplication moved
  to a constant-iteration schedule.
- **Key hygiene**: `destroy()` now overwrites the private-key buffer in
  place instead of just dropping the reference.
- **Execution/settlement integrity**: execution attestations are now
  cross-validated against the commitment's authorised trade terms
  (qty/price/symbol/side); broker settlement acknowledgements are now
  cryptographically authenticated instead of accepted as a free-form string.
- **Identity binding**: new `AccountKeyRegistry` (`identity.py`) closes a
  gap where any self-signed key could pass every check with no proof it
  belonged to the account holder.
- **Concurrency**: audit-log JSONL/SQLite-index writes are now lock-guarded
  against a race that could silently overwrite a duplicate order/phase
  record.
- DoS bounds on unbounded JSON/HTTP-response reads; silent exception
  swallowing removed from the audit-rebuild and TSA request paths.
- Every fix carries a dedicated regression test; suite grew to 137 tests.

## [0.1.0] - 2026-06-03

### Added
- Initial public release of Protocol-C: CSPRNG, forward-secret, tamper-evident
  data commitments.
- High-level API: `get_seed`, `commit`, `verify`, `batch_commit`.
- Pure-Python secp256k1 ECDSA signer (RFC 6979) with one-shot ephemeral keys
  destroyed immediately after signing.
- Three-phase chain: decision commitment, execution attestation, settlement.
- Append-only JSONL audit log with SQLite indexing.
- CLI: `seed`, `commit`, `verify`, `init`, `info`, `demo`, `logs`.
- Optional `[timestamp]` extra (RFC 3161).
