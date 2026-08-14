# Contributing to Aether Protocol-C

Thanks for considering a contribution. Protocol-C is a small, security-sensitive
library, so the bar is "boring and correct" over "clever." This guide keeps PRs
fast to review.

## Ground rules

- **Core stays dependency-free.** Anything in `aether_protocol_c/` that runs by
  default must use only the Python standard library. New third-party
  dependencies belong behind an optional extra in `pyproject.toml`
  (like `[server]` or `[quantum]`), never in the core path.
- **Don't touch the crypto casually.** Changes to `ephemeral_signer.py`,
  `crypto.py`, or anything that affects signing, key destruction, or
  verification get extra scrutiny and must come with tests. If you're not sure,
  open an issue first.
- **Public API is a contract.** The names in `aether_protocol_c/__init__.__all__`
  are what people import. Don't rename or remove them without a deprecation note
  in `CHANGELOG.md`.

## Development setup

```bash
git clone https://github.com/AetherAI3/PROTOCOL-C
cd AETHER-PROTOCOL-C
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

The full suite should pass before you start. If it doesn't on a clean checkout,
that's a bug — please report it.

## Making a change

1. **Branch** off `main` with a descriptive name (`fix/...`, `feat/...`, `docs/...`).
2. **Write the test first** when fixing a bug or adding behavior — it should fail
   before your change and pass after.
3. **Keep it focused.** One logical change per PR. Unrelated cleanups go in their
   own PR.
4. **Run the suite:** `pytest -q`. Add tests for new code; aim to keep coverage
   from regressing.
5. **Match the style.** PEP 8, type hints on function signatures, small focused
   functions. The codebase favors clarity over compression.

## Commit messages

Conventional-commit style, present tense:

```
feat: add tiered SQLite index for audit lookups
fix: zero key material even when sign() raises
docs: clarify the temporal-safety argument in the README
test: cover tamper detection through the CLI
```

## Pull requests

- Describe **what** changed and **why** — link any related issue.
- Note explicitly if the change touches signing, verification, key lifetime, or
  the audit-log format.
- CI (lint + tests across supported Python versions) must be green before review.

## Reporting security issues

**Do not** open a public issue for a vulnerability. Follow the private process in
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
