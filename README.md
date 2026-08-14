<div align="center">

# 🔏 Aether Protocol-C

**Tamper-proof receipts for any decision your software makes.** Sign a piece of structured data with a key that is **born, used once, and destroyed in the same breath** — then prove, forever, that the record was never touched. Pure Python, zero mandatory dependencies, local-first. 

[![CI](https://github.com/AetherAI3/PROTOCOL-C/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AetherAI3/PROTOCOL-C/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache--2.0-06b6d4)](LICENSE) [![Python](https://img.shields.io/badge/python-3.10%2B-14b8a6)](https://www.python.org) [![Dependencies](https://img.shields.io/badge/core%20deps-0-22c55e)](pyproject.toml) [![Built by Aether](https://img.shields.io/badge/built%20by-Aether-7c3aed)](https://aethersystems.net)

**An open project from [Aether](https://aethersystems.net)** · Apache-2.0 · `pip install git+https://github.com/AetherAI3/PROTOCOL-C.git`

</div>

---

<div align="center">

> **A signature you can't repudiate, from a key that no longer exists.**
> Protocol-C turns any dict into a signed, append-only commitment. Each commitment gets its own one-shot signing key derived from fresh CSPRNG entropy — the key signs exactly once, then its private half is zeroed from memory. What's left on disk is a record that anyone can verify and nobody can forge or alter after the fact.
<img width="1562" height="498" alt="image" src="https://github.com/user-attachments/assets/d6245182-8e7c-4a06-8f35-25a747399b3e" />

<p align="center">
  <a href="#the-problem">Problem</a> ·
  <a href="#how-it-works-60-seconds">How it works</a> ·
  <a href="#what-you-get">What you get</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#command-line">CLI</a> ·
  <a href="#the-three-phase-protocol">Three phases</a> ·
  <a href="#honest-about-quantum-safe">Honest about "quantum-safe"</a> ·
  <a href="#citation">Cite</a>
</p>

</div>

---

<div align="center">

## The problem

Software makes consequential decisions all day — a trade fires, a model picks an action, a transaction settles — and the **audit trail is usually an afterthought**: a log line you can edit, a database row you can `UPDATE`, a timestamp you have to take on faith. When something goes wrong and someone asks *"what did the system actually decide, and when?"*, you're left arguing about logs that have no way to prove they weren't changed.

The usual fix — sign everything with one long-lived private key — just moves the risk. That key becomes a **single point of catastrophe**: steal it once and every past and future record is forgeable. Keep it alive on a server and it's a standing target.

## The fix: one key per decision, destroyed on use

Protocol-C signs each decision with its **own ephemeral key**, then **destroys the private half immediately** after a single signature. There's no long-lived secret to steal, and because every commitment has an independent key, breaking one tells you nothing about the others (**perfect forward secrecy**). The record is canonicalized, hashed, and signed with **secp256k1 ECDSA + RFC 6979** — the same battle-tested curve Bitcoin uses, in an auditable pure-Python implementation with no third-party crypto dependency.

<p align="center"><strong>Edit-the-log ✗ &nbsp;→&nbsp; Sign-and-destroy ✓</strong></p>

```
    decision (dict)                                          anyone, anytime
         │                                                         │
         ▼                                                         ▼
   ┌───────────┐   CSPRNG    ┌──────────────┐   ECDSA    ┌──────────────────┐
   │  get_seed │ ─ seed ──▶  │ ephemeral key│ ─ sign ──▶ │ signed commitment│ ──▶ verify ✓
   └───────────┘             └──────┬───────┘            └────────┬─────────┘
                                    │ zeroed                      │ append-only
                                    ▼ after 1 use                 ▼ JSONL + SQLite
                              (key destroyed)                 (audit trail)
```

## How it works (60 seconds)

Think of it as a **notary that shreds its own stamp after every seal.** Map it to that and it clicks:

| Notary | Protocol-C |
|---|---|
| Fresh wax for each seal | a new **CSPRNG seed** per commitment (independent entropy) |
| A stamp carved for one document | an **ephemeral secp256k1 key** derived from that seed |
| Pressing the seal, once | a single **ECDSA signature** (RFC 6979 deterministic-k) |
| Shredding the stamp on the spot | the private key is **zeroed from memory** right after signing |
| The sealed document in the ledger | an **append-only JSONL** entry, indexed in SQLite |
| Holding the seal up to the light | **`verify()`** — public-key only, no secret needed |

The seal proves *who* and *what*; shredding the stamp proves it can't be re-used or back-dated. → full explainer in [`docs/how-it-works.md`](docs/how-it-works.md).

## What you get

- 🔏 **Non-repudiable receipts** — every commitment is a self-contained, signed object. Re-verify it years later with nothing but the public key embedded in the signature.
- 🧨 **One-shot keys** — the private key signs exactly once, then `destroy()` zeroes it in place. No long-lived secret to leak, rotate, or guard.
- 🔗 **Tamper-evident by construction** — change a single byte of the committed data and the signature stops verifying. There's no "edit the log" attack.
- 🧱 **Perfect forward secrecy** — each commitment (and each phase of the three-phase chain) uses an independent seed and key. Compromising one reveals nothing about the rest.
- 📜 **Audit trail built in** — append-only JSONL is the source of truth; a companion SQLite index gives O(1) lookups and filtered queries, with automatic rotation.
- 🪶 **Zero mandatory dependencies** — the core is Python stdlib only. The secp256k1 ECDSA signer is pure Python and fully auditable. `pip install` and go.
- 🖥️ **Library *and* CLI** — call it from Python, or pipe JSON through `aether-protocol-c commit | … | aether-protocol-c verify` in any shell.

## Quickstart

```bash
pip install git+https://github.com/AetherAI3/PROTOCOL-C.git
```

> **Not on PyPI yet.** `pip install aether-protocol-c` will not resolve until the
> first release is published. Install from git (above) — same package, same
> `aether_protocol_c` import, same `aether-protocol-c` CLI entry point.

```python
from aether_protocol_c import commit, verify, get_seed

# 1. Fresh CSPRNG entropy → a one-shot signing key
seed = get_seed()

# 2. Commit a decision. The key signs once, then is destroyed.
result = commit(
    seed,
    order_id="order_001",
    trade_details={"symbol": "BTC", "qty": 1, "side": "long", "price": 50000},
    account_state={
        "capital": 100000, "equity": 100000, "open_positions": [],
        "risk_used": 0.0, "risk_limit": 1.0, "nonce": 1, "timestamp": 0,
    },
)

# 3. The receipt verifies forever — public key only, no secret involved.
assert result["verified"]
assert verify(result["commitment"], result["signature"])
```

That's the whole thing: one call to commit a decision, one call to prove it. No keyring, no server, no daemon.

## Setup (30 seconds)

```bash
pip install git+https://github.com/AetherAI3/PROTOCOL-C.git   # install
aether-protocol-c info            # confirm Python, entropy source, key lifetime
aether-protocol-c init            # scaffold aether.config.json + audit/ dir
aether-protocol-c demo            # run a sample commit -> verify end to end
```

That's the whole onboarding: install, check, scaffold, prove it works.

## Command line

The same library, exposed as a Unix-friendly tool that reads JSON in and writes JSON out:

```bash
# generate a seed and see its provenance
aether-protocol-c seed

# commit a decision described in a JSON file, appending to an audit log
aether-protocol-c commit --file order.json --log audit.jsonl

# verify a {commitment, signature} envelope — exit 0 if valid, 1 if tampered
echo '{"commitment": {...}, "signature": {...}}' | aether-protocol-c verify
```

| Command | What it's for |
|---|---|
| `aether-protocol-c seed` | Generate a CSPRNG seed and print its provenance metadata. |
| `aether-protocol-c commit -f order.json` | Sign a JSON payload (`order_id` / `trade_details` / `account_state`) and print the commitment + signature. |
| `aether-protocol-c commit -l audit.jsonl` | …and append the result to an append-only JSONL audit log. |
| `aether-protocol-c verify -f env.json` | Verify a `{commitment, signature}` envelope; exit code doubles as the verdict. |
| `aether-protocol-c init` | Scaffold `aether.config.json` and an `audit/` directory (use `--force` to overwrite). |
| `aether-protocol-c info` | Print version, Python, platform, entropy source, key lifetime, and signature scheme. |
| `aether-protocol-c demo` | Run a sample commit → verify end to end and print the receipt. |
| `aether-protocol-c logs -l audit.jsonl [--verify] [--tail N] [--type T]` | List, tail, or re-verify audit-log entries; nonzero exit if any signature fails. |

> **Tip:** `commit` and `verify` both default to stdin/stdout, so they pipe straight into `jq`, `tee audit.jsonl`, or each other.

## Batch commitments

```python
from aether_protocol_c import batch_commit

account = {
    "capital": 100_000, "equity": 100_000, "open_positions": [],
    "risk_used": 0.0, "risk_limit": 1.0, "nonce": 1, "timestamp": 0,
}

results = batch_commit([
    {"order_id": "b001",
     "trade_details": {"symbol": "BTC", "qty": 1, "side": "long", "price": 50_000},
     "account_state": account},
    {"order_id": "b002",
     "trade_details": {"symbol": "ETH", "qty": 4, "side": "short", "price": 3_000},
     "account_state": {**account, "nonce": 2}},
], log_path="audit.jsonl")

assert all(r["verified"] for r in results)

# Each item gets its own independent seed and key — full forward secrecy across the batch.
```

## The three-phase protocol

For workflows that decide, act, then settle — each phase is its own independently-keyed commitment, so the chain is tamper-evident end to end:

```python
import time

from aether_protocol_c import get_seed
from aether_protocol_c.audit import AuditLog
from aether_protocol_c.commitment import QuantumDecisionCommitment
from aether_protocol_c.crypto import QuantumEphemeralKey
from aether_protocol_c.execution import ExecutionResult, QuantumExecutionAttestation
from aether_protocol_c.settlement import (
    QuantumSettlementRecord,
    build_broker_attestation,
)
from aether_protocol_c.state import AccountSnapshot

order_id = "ord_001"
account = {
    "capital": 100_000, "equity": 100_000, "open_positions": [],
    "risk_used": 0.0, "risk_limit": 1.0, "nonce": 1,
    "timestamp": int(time.time()),
}
log = AuditLog("audit.jsonl")

# ── Phase 1 — commit the decision (seed #1) ────────────────────────────────
seed1 = get_seed()
c_dict, c_sig, _ = QuantumDecisionCommitment.create_and_sign(
    order_id=order_id,
    trade_details={"symbol": "BTC", "qty": 1, "side": "long", "price": 50_000},
    account_state=AccountSnapshot.from_dict(account),
    quantum_seed=seed1.seed_int,
    measurement_method=seed1.method,
)
log.append_commitment(c_dict, c_sig)

# ── Phase 2 — attest the execution (seed #2, independent) ──────────────────
seed2 = get_seed()
att_dict, att_sig, _ = QuantumExecutionAttestation.create_and_sign(
    commitment_sig=c_sig,
    commitment_seed_hash=c_dict["quantum_seed_commitment"],
    execution_result=ExecutionResult(
        order_id=order_id, symbol="BTC", side="long",
        filled_qty=1, fill_price=50_000,
    ),
    new_account_state=AccountSnapshot.from_dict({**account, "nonce": 2}),
    quantum_seed=seed2.seed_int,
    measurement_method=seed2.method,
)
log.append_execution(att_dict, att_sig)

# ── Phase 3 — record settlement (seed #3, independent) ─────────────────────
# The broker signs the attestation with its OWN key, so `broker_sig` is
# authenticated rather than an arbitrary string the settlement signer typed in.
# Register that pubkey in an AccountKeyRegistry under scope f"broker:{account_id}"
# for AuditVerifier.verify_trade_flow to certify the flow.
bseed = get_seed()
broker_key = QuantumEphemeralKey(quantum_seed=bseed.seed_int, method=bseed.method)
broker_signature = broker_key.sign(
    build_broker_attestation(order_id, c_sig, att_sig, "broker_ack_001")
)

seed3 = get_seed()
s_dict, s_sig, _ = QuantumSettlementRecord.create_and_sign(
    order_id=order_id,
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
log.append_settlement(s_dict, s_sig)
```

Each `create_and_sign` mints its own seed, key, and temporal window, then returns
`(dict, signature_envelope, object)` — it does **not** touch the audit log. You append
explicitly via `AuditLog.append_commitment` / `append_execution` / `append_settlement`,
which land under the phase labels `DECISION_COMMITMENT`, `EXECUTION_ATTESTATION`, and
`SETTLEMENT_FINALITY` respectively. Verify a completed chain with
`QuantumSettlementVerifier.verify_chain(c_sig, att_sig, s_dict)` and
`QuantumSettlementVerifier.verify_all_seeds_independent(s_dict)`.

## Security properties

| | Property | What backs it |
|---|---|---|
| **P1** | Seed unpredictability | CSPRNG (`secrets`) entropy is computationally unpredictable |
| **P2** | Unforgeability | secp256k1 ECDSA; forging a signature means solving the ECDLP |
| **P3** | Temporal safety | key lifetime (~1 hour, default) ≪ any near-term quantum attack window |
| **P4** | Perfect forward secrecy | each phase/commitment uses an independent seed + key pair |
| **P5** | Tamper detection | any change to the committed bytes invalidates the signature |

See [SECURITY.md](SECURITY.md) for the full threat model, assumptions, and how to report a vulnerability. The full technical white paper — the CVE-2025-59536 problem, the design, and honest scope — is in [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md).

**Security hardening.** Protocol-C went through a multi-round audit → adversarial-review → fix cycle plus standing red-team/blue-team sparring in July 2026 — TSA verification, SSRF, signer timing side-channels, key hygiene, execution/settlement integrity, identity binding, and audit-log concurrency. Not SOC 2 certified — see [SECURITY.md#security-hardening--soc-2-type-ii-readiness](SECURITY.md#security-hardening--soc-2-type-ii-readiness) for exactly what's covered and what isn't.

## Honest about "quantum-safe"

Read this part. "Quantum-safe" here is a **temporal** argument, **not** post-quantum cryptography:

- secp256k1 ECDSA is **not** quantum-resistant. A large fault-tolerant quantum computer running Shor's algorithm could recover a private key from its public key.
- Protocol-C's defense is that **the private key no longer exists.** It's destroyed milliseconds after signing — long before any such machine (which does not exist today, and which needs on the order of thousands of logical qubits) could attack it. You can't steal a key from the future if it was zeroed in the past.
- This protects the **signing key**, not the signature scheme itself. The scheme is classical. If your threat model requires standardized post-quantum signatures (e.g. ML-DSA / SLH-DSA), Protocol-C is **not** a drop-in for that; it's a forward-secret, tamper-evident commitment layer that happens to age out its keys faster than the attack.
- Hardware entropy sources are out of scope for this library. This public package is CSPRNG-only; its quantum-safety is purely the temporal-margin argument above.

In short: **strong, auditable, forward-secret commitments today** — with an explicit, documented temporal margin against tomorrow's quantum attacks. No magic, no overclaiming.

## Examples

Runnable scripts live in [`examples/`](examples/):

- [`basic_commit.py`](examples/basic_commit.py) — one commitment, verified, with the temporal window printed.
- [`batch_commit.py`](examples/batch_commit.py) — many commitments, each independently keyed.
- [docs/integrating.md](docs/integrating.md) — drop signed audit logging into your app.

## Citation

If Protocol-C supports your work, please cite it. Built and maintained by **Aether**.

```bibtex
@software{aether_protocol_c_2026,
  title        = {Aether Protocol-C: forward-secret, tamper-evident data commitments},
  author       = {Barrante, Brandon},
  organization = {Aether},
  year         = {2026},
  url          = {https://github.com/AetherAI3/PROTOCOL-C},
  license      = {Apache-2.0}
}
```

GitHub's "Cite this repository" button reads [`CITATION.cff`](CITATION.cff) directly.

## ⭐ Star, share, contribute

If this gave your audit trail teeth, **drop a star** — it's how other people find it. **PRs and issues are welcome** — see [CONTRIBUTING.md](CONTRIBUTING.md). Crypto changes get extra scrutiny; read [SECURITY.md](SECURITY.md) first.

## License

**Apache-2.0** — including an explicit patent grant. Use it, fork it, ship it in your product. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

</div>

---

<div align="center">

Built by **Brandon Barrante** · [Aether](https://aethersystems.net)
<img width="2752" height="1536" alt="image" src="https://github.com/user-attachments/assets/66047e92-73d4-47ad-9da7-5441b196352a" />

*A signature you can't repudiate, from a key that no longer exists.*

</div>
