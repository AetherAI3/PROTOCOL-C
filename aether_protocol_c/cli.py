"""
aether_protocol_c/cli.py

Command-line interface for aether-protocol-c.

A thin, dependency-free wrapper over the high-level library functions
(`get_seed`, `commit`, `verify`).  Reads structured input as JSON from a
file or stdin and writes results as JSON to stdout, so the CLI composes
cleanly with shell pipelines and audit tooling.

Subcommands:
    seed     Generate a CSPRNG seed and print its provenance.
    commit   Create a signed commitment from a JSON payload.
    verify   Verify a {commitment, signature} JSON envelope.

Examples:
    aether-protocol-c seed
    aether-protocol-c commit --file order.json --log audit.jsonl
    echo '{"commitment": {...}, "signature": {...}}' | aether-protocol-c verify
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from typing import Any

from . import __version__, commit, get_seed, verify


# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "entropy": "CSPRNG",
    "key_lifetime_seconds": 3600,
    "audit_log": "audit/audit.jsonl",
}

# Maximum number of bytes accepted for a single JSON input (file or stdin).
# Guards against unbounded-memory DoS from a runaway pipe or malicious input.
MAX_JSON_INPUT_BYTES = 10 * 1024 * 1024  # 10 MiB


# ── IO helpers ────────────────────────────────────────────────────────────────

def _read_limited(fh, max_bytes: int) -> str:
    """Read at most `max_bytes` (+1 chunk) from a text file-like object.

    Raises ValueError if the stream contains more than `max_bytes` of data,
    instead of buffering an unbounded amount of input into memory.
    """
    chunks: list[str] = []
    total = 0
    # Read in bounded chunks rather than fh.read() so we never buffer more
    # than max_bytes + one chunk's worth of attacker-controlled data.
    chunk_size = 65536
    while total <= max_bytes:
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > max_bytes:
        raise ValueError(
            f"JSON input exceeds maximum allowed size of {max_bytes} bytes"
        )
    return "".join(chunks)


def _read_json(path: str | None) -> Any:
    """Read JSON from a file path, or from stdin when path is None or '-'."""
    if path in (None, "-"):
        raw = _read_limited(sys.stdin, MAX_JSON_INPUT_BYTES)
    else:
        with open(path, "r", encoding="utf-8") as fh:
            raw = _read_limited(fh, MAX_JSON_INPUT_BYTES)
    if not raw.strip():
        raise ValueError("no JSON input provided")
    return json.loads(raw)


def _emit(obj: Any, out) -> None:
    """Write a pretty JSON object followed by a newline."""
    json.dump(obj, out, indent=2, sort_keys=True)
    out.write("\n")


# ── Subcommand handlers ───────────────────────────────────────────────────────

def _cmd_seed(args: argparse.Namespace, out) -> int:
    """Generate a seed and print its provenance metadata."""
    seed = get_seed()
    _emit(seed.to_dict(), out)
    return 0


def _cmd_commit(args: argparse.Namespace, out) -> int:
    """Create a signed commitment from a JSON payload."""
    payload = _read_json(args.file)
    for key in ("order_id", "trade_details", "account_state"):
        if key not in payload:
            raise ValueError(f"payload missing required key: '{key}'")

    seed = get_seed()
    result = commit(
        seed,
        order_id=payload["order_id"],
        trade_details=payload["trade_details"],
        account_state=payload["account_state"],
        reasoning_text=payload.get("reasoning_text"),
        reasoning_model=payload.get("reasoning_model", "human"),
        log_path=args.log,
    )
    _emit(result, out)
    return 0 if result["verified"] else 1


def _cmd_verify(args: argparse.Namespace, out) -> int:
    """Verify a {commitment, signature} envelope. Exit 0 if valid, 1 if not."""
    envelope = _read_json(args.file)
    for key in ("commitment", "signature"):
        if key not in envelope:
            raise ValueError(f"envelope missing required key: '{key}'")

    ok = verify(envelope["commitment"], envelope["signature"])
    _emit({"verified": ok}, out)
    return 0 if ok else 1


def _cmd_init(args, out) -> int:
    """Scaffold aether.config.json + audit/ dir."""
    base = args.dir or "."
    cfg_path = os.path.join(base, "aether.config.json")
    if os.path.exists(cfg_path) and not args.force:
        print(f"error: {cfg_path} exists (use --force to overwrite)", file=sys.stderr)
        return 2
    os.makedirs(os.path.join(base, "audit"), exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG, fh, indent=2)
        fh.write("\n")
    _emit({"initialized": cfg_path,
           "next": ["aether-protocol-c info",
                    "aether-protocol-c demo"]}, out)
    return 0


def _cmd_info(args, out) -> int:
    """Print environment + protocol preflight info."""
    from . import __version__
    _emit({
        "tool": "aether-protocol-c",
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "entropy_source": "CSPRNG",
        "key_lifetime_seconds": 3600,
        "signature": "ecdsa-secp256k1-sha256 (RFC 6979)",
        "default_audit_log": "audit/audit.jsonl",
    }, out)
    return 0


def _cmd_demo(args, out) -> int:
    """Run a sample commit -> verify and print the receipt."""
    seed = get_seed()
    result = commit(
        seed,
        order_id="demo_001",
        trade_details={"symbol": "BTC", "qty": 1, "side": "long", "price": 50000},
        account_state={
            "capital": 100000, "equity": 100000, "open_positions": [],
            "risk_used": 0.0, "risk_limit": 1.0, "nonce": 1, "timestamp": 0,
        },
    )
    ok = verify(result["commitment"], result["signature"])
    result["independent_verify"] = ok
    _emit(result, out)
    return 0 if (result["verified"] and ok) else 1


def _cmd_logs(args, out) -> int:
    """List/tail audit entries; optionally re-verify each signature."""
    path = args.log or DEFAULT_CONFIG["audit_log"]
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
    except FileNotFoundError:
        print(f"error: audit log not found: {path}", file=sys.stderr)
        return 2

    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"_corrupt": True, "raw": line[:80]})

    if args.type:
        entries = [e for e in entries
                   if e.get("phase") == args.type or e.get("record_type") == args.type]
    if args.tail:
        entries = entries[-args.tail:]

    invalid = 0
    if args.verify:
        for e in entries:
            # Only true system markers (LOG_ROTATION) legitimately carry no
            # signature — skip those. Any OTHER entry missing a signature is
            # treated as tampering (e.g. a stripped signature) and counted invalid.
            if e.get("phase") == "LOG_ROTATION":
                e["_verified"] = "skipped"
                continue
            data = e.get("data", e.get("commitment", e))
            sig = e.get("signature")
            ok = bool(sig) and verify(data, sig)
            e["_verified"] = ok
            if not ok:
                invalid += 1

    _emit({"log": path, "count": len(entries), "invalid": invalid,
           "entries": entries}, out)
    return 1 if invalid else 0


# ── Parser ────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="aether-protocol-c",
        description=(
            "CSPRNG quantum-safe commitment protocol — sign, audit, and "
            "verify tamper-proof data commitments from the command line."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"aether-protocol-c {__version__}"
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_seed = sub.add_parser("seed", help="generate a CSPRNG seed and print provenance")
    p_seed.set_defaults(func=_cmd_seed)

    p_commit = sub.add_parser("commit", help="create a signed commitment from JSON")
    p_commit.add_argument(
        "-f", "--file", default=None,
        help="JSON payload file with order_id/trade_details/account_state "
             "(default: stdin)",
    )
    p_commit.add_argument(
        "-l", "--log", default=None,
        help="append the commitment to this JSONL audit log",
    )
    p_commit.set_defaults(func=_cmd_commit)

    p_verify = sub.add_parser("verify", help="verify a {commitment, signature} envelope")
    p_verify.add_argument(
        "-f", "--file", default=None,
        help="JSON envelope file with commitment + signature (default: stdin)",
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_init = sub.add_parser("init", help="scaffold config + audit dir")
    p_init.add_argument("--dir", default=".", help="target directory (default: .)")
    p_init.add_argument("--force", action="store_true", help="overwrite existing config")
    p_init.set_defaults(func=_cmd_init)

    p_info = sub.add_parser("info", help="print version/env/entropy preflight")
    p_info.set_defaults(func=_cmd_info)

    p_demo = sub.add_parser("demo", help="run a sample commit->verify end to end")
    p_demo.set_defaults(func=_cmd_demo)

    p_logs = sub.add_parser("logs", help="list/tail/verify audit-log entries")
    p_logs.add_argument("-l", "--log", default=None, help="audit JSONL path")
    p_logs.add_argument("--tail", type=int, default=None, help="show only last N")
    p_logs.add_argument("--type", default=None, help="filter by phase/record_type")
    p_logs.add_argument("--verify", action="store_true", help="re-check each signature")
    p_logs.set_defaults(func=_cmd_logs)

    return parser


def main(argv: list[str] | None = None, out=None) -> int:
    """
    CLI entry point.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).
        out: Output stream for JSON results (defaults to sys.stdout).

    Returns:
        Process exit code.
    """
    out = out or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return 2

    try:
        return args.func(args, out)
    except (ValueError, json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
