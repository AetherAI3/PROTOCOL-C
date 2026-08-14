# Protocol-C: A Free, Auditable Authentication Layer for AI Decisions

**A technical white paper on closing the instruction-to-execution gap that CVE-2025-59536 exposed — with classical, dependency-free cryptography.**

*Brandon Barrante · Aether AI · 2026 · Apache-2.0 · [github.com/AetherAI3/PROTOCOL-C](https://github.com/AetherAI3/PROTOCOL-C)*

---

## Abstract

Modern AI systems decide one thing and execute another through an unauthenticated pipeline: config files, tool calls, MCP servers, message queues, shared state. Nothing cryptographically binds *what the AI decided* to *what the runtime executed*. CVE-2025-59536 — a critical (CVSS 8.7) code-injection flaw in Claude Code disclosed by Check Point Research — is a concrete instance of this class: attacker-controlled project files reached execution because there was no authentication layer between instruction and action.

Protocol-C is an open-source, pure-Python implementation of that missing layer. Every decision is signed with a **single-use secp256k1 key** that is derived from fresh CSPRNG entropy, used exactly once, and **zeroed from memory immediately after signing**. Execution layers verify the signature before acting; unsigned or tampered instructions are rejected. The result is a tamper-evident, append-only record that anyone can verify and no party can forge or back-date — with **zero mandatory dependencies** and **zero per-operation entropy cost**.

This paper is deliberately honest about scope. Protocol-C is **classical cryptography**, not post-quantum and not quantum-sourced. Its resistance to future quantum attack is a *temporal* argument — the key no longer exists by the time any such attack could run — not a hardness claim. The quantum-entropy variant (Protocol-L) is a separate system; this document is about Protocol-C only.

---

## 1. The problem: a missing layer, not a reasoning bug

On disclosure by Check Point Research, **CVE-2025-59536** (CVSS 8.7) allowed attacker-authored project configuration — Hooks, `.mcp.json`, `settings.json`, environment variables — to execute arbitrary shell commands and exfiltrate API keys when a developer merely opened an untrusted repository in Claude Code. Anthropic patched the specific defect in Claude Code 1.0.111.

The patch closed *that* door. It did not close the *class* of door. The root cause was not a flaw in the model's reasoning; it was the **absence of a cryptographic authentication boundary between an AI instruction and its execution**. That boundary is missing almost everywhere autonomous AI is deployed:

- A config file carries instructions to a runtime — no signature.
- A tool/MCP call carries an action to an executor — no signature.
- A message queue carries a decision to a downstream worker — no signature.
- A log claims "the agent did X" — but the log is mutable and unprovable.

When anyone in the path can write to the channel, anyone can inject. Anthropic's own Frontier Safety roadmap names **"cryptographically verified short-lived identities"** as a priority. Protocol-C is one concrete, free, auditable way to build them.

> **Honest scope.** Protocol-C does **not** patch CVE-2025-59536 — Anthropic did, in 1.0.111. Protocol-C is **defense-in-depth** for the broader vulnerability class: it authenticates AI decisions *you* route through it, so that injected or unsigned instructions are rejected before execution. It protects the pipelines you wrap with it; it is not a drop-in shield for software you do not control.

## 2. Why the usual answers fall short

**Long-lived signing keys** move the risk rather than removing it. One key that signs everything becomes a single point of catastrophe: steal it once and every past and future record is forgeable. Kept alive on a server, it is a standing target.

**Application logs** are circumstantial. They can be edited, truncated, or rewritten, and they carry no proof they were not. "Trust our logs" is not an authentication model.

**Post-quantum signatures** (ML-DSA, SLH-DSA) raise the mathematical bar but still rest on a long-lived secret and a hardness assumption. They are valuable, but they are a different tool than *forward-secret, one-shot* authentication.

## 3. Design: commit, sign once, destroy

Protocol-C signs each decision with its own ephemeral key and destroys the private half immediately after a single signature.

```
 decision (dict)                                              anyone, anytime
      │                                                              │
      ▼                                                              ▼
┌───────────┐  CSPRNG   ┌──────────────┐   ECDSA    ┌──────────────────┐
│  get_seed │ ─ seed ─▶ │ ephemeral key│ ─ sign ──▶ │ signed commitment│ ─▶ verify ✓
└───────────┘           └──────┬───────┘            └────────┬─────────┘
                               │ zeroed                      │ append-only
                               ▼ after 1 use                 ▼ JSONL + SQLite
                         (key destroyed)                  (audit trail)
```

1. **Seed.** `secrets.token_bytes(32)` — 256 bits of OS-CSPRNG entropy. Only the SHA-256 hash of the seed is ever recorded; the raw seed is never stored.
2. **Key.** An secp256k1 private key is derived from the seed via HMAC-SHA256 and reduced mod the curve order. The implementation is **pure Python** (no third-party crypto dependency), so the entire signing path is auditable.
3. **Sign once.** The decision dict is canonicalized (`sort_keys`, compact separators), hashed with SHA-256, and signed with ECDSA using **RFC 6979 deterministic-k** (eliminates nonce-reuse key recovery) and low-`s` normalization (BIP 62).
4. **Destroy.** The private key integer is zeroed in place the instant the signature is produced. A second signing attempt raises. The window in which the key exists is measured in milliseconds.
5. **Record.** If enabled, the commitment is appended to an **append-only JSONL** log (the source of truth) with a companion SQLite index for O(1) lookups and rotation.
6. **Verify.** Verification needs only the public key embedded in the signature — no secret, no server, no trust in the storage layer. Changing a single byte of the committed data breaks verification.

For decide → act → settle workflows, Protocol-C provides a **three-phase chain**: `DECISION_COMMITMENT`, `EXECUTION_ATTESTATION`, `SETTLEMENT_FINALITY`, each independently keyed, so the whole chain is tamper-evident end to end.

## 4. Security properties

| | Property | What backs it |
|---|---|---|
| **P1** | Seed unpredictability | OS CSPRNG (`secrets`) entropy is computationally unpredictable |
| **P2** | Unforgeability | secp256k1 ECDSA; forging a signature means solving the ECDLP |
| **P3** | Temporal safety | key lifetime ≪ any near-term quantum attack window; the key is destroyed before an attack could complete |
| **P4** | Perfect forward secrecy | each decision/phase uses an independent seed + key pair |
| **P5** | Tamper detection | any change to the committed bytes invalidates the signature |

## 5. How this maps to the CVE

The CVE's root cause was unauthenticated instruction → execution. Protocol-C inserts a verifiable checkpoint:

- **Sign before dispatch.** The component that *decides* signs the decision with a one-shot key.
- **Verify before execute.** The component that *acts* checks the signature against the embedded public key and refuses unsigned or altered instructions.
- **Prove after the fact.** Every accepted decision is an independently verifiable record — not a log you have to trust.

An attacker who injects instructions into a config file, queue, or tool channel cannot produce a valid signature, because the signing key existed only inside the deciding component and was destroyed after use. The injected instruction fails verification and is dropped.

> Again, honestly: this works only for the boundaries you instrument. Protocol-C is a primitive for building authenticated AI pipelines, not a magic perimeter around software you do not control.

## 6. Economics: $0 entropy at scale

Quantum entropy is expensive — on the order of $100/minute of QPU time. For commitment workloads that do not require physical non-determinism, that cost is pure overhead. Protocol-C sources entropy from the OS kernel (CSPRNG): **same chain format, same verification path, zero QPU cost, zero mandatory dependencies.** Systems that later need quantum-sourced entropy can adopt the separate Protocol-L without changing the commitment/verification model.

## 7. Honest about "quantum-safe"

This matters enough to state plainly:

- secp256k1 ECDSA is **classical** and is **not** post-quantum. A large fault-tolerant quantum computer running Shor's algorithm could recover a private key from its public key.
- Protocol-C's mitigation is **temporal, not mathematical**: the private key is destroyed within ~1 hour (default, configurable) of creation — far inside any plausible attack window. Shor's algorithm needs the key to exist; a zeroed key cannot be recovered. The defense is the key's *absence*, not the algorithm's strength.
- If your threat model requires standardized post-quantum signatures, Protocol-C is **not** a drop-in for that. It is a forward-secret, tamper-evident commitment layer that ages its keys out faster than the attack.

No physical-unpredictability or quantum-hardware claims are made for Protocol-C. Hardware entropy sources are out of scope for this library.

## 8. Getting started

```bash
pip install aether-protocol-c     # zero mandatory dependencies
aether-protocol-c info            # version, Python, entropy source, key lifetime
aether-protocol-c demo            # sample commit -> verify, end to end
```

```python
from aether_protocol_c import commit, verify, get_seed

result = commit(
    get_seed(),
    order_id="decision_001",
    trade_details={"action": "deploy", "target": "prod"},
    account_state={"capital": 0, "equity": 0, "open_positions": [],
                   "risk_used": 0.0, "risk_limit": 1.0, "nonce": 1, "timestamp": 0},
    log_path="audit/audit.jsonl",
)
assert result["verified"]                                   # signed + verified
assert verify(result["commitment"], result["signature"])    # anyone can re-check
```

Audit a log at any time, with tamper detection:

```bash
aether-protocol-c logs --log audit/audit.jsonl --verify
```

## 9. Limitations

- **Scope:** authenticates only the boundaries you instrument; not a perimeter for third-party software.
- **Classical:** not post-quantum; quantum-safety is the temporal argument of §7.
- **Confidentiality:** commitments are signed, not encrypted — do not place secrets in the committed payload.
- **Timestamping:** the temporal window uses local system time by default; for third-party-verifiable time, use the optional RFC 3161 timestamp extra.

## 10. Conclusion

CVE-2025-59536 was patched, but the gap it exposed — unauthenticated instruction-to-execution — is structural and everywhere. Protocol-C is a small, auditable, dependency-free way to close that gap for the pipelines you control: sign each decision with a key that exists for one signature and then is gone, verify before execution, and keep a record nobody can forge. It is free at any scale, and it is honest about exactly what it does and does not guarantee.

---

## References

- Check Point Research — *RCE and API Token Exfiltration Through Claude Code Project Files (CVE-2025-59536 / CVE-2026-21852).* https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
- Tenable — *CVE-2025-59536.* https://www.tenable.com/cve/CVE-2025-59536
- Pornin, T. — *RFC 6979: Deterministic Usage of DSA and ECDSA.* IETF, 2013.
- Adams, C. et al. — *RFC 3161: Time-Stamp Protocol (TSP).* IETF, 2001.
- Certicom — *SEC 2: Recommended Elliptic Curve Domain Parameters (secp256k1).*

---

*Protocol-C is open source under Apache-2.0. Source, tests, and CLI: [github.com/AetherAI3/PROTOCOL-C](https://github.com/AetherAI3/PROTOCOL-C). This document applies black-box disclosure: architecture and guarantees are public; it makes no claims beyond what the published implementation does.*
