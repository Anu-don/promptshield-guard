"""Command line interface: ``promptshield scan <file|->``."""

from __future__ import annotations

import argparse
import json
import sys

from .detector import scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptshield",
                                description="Scan text for prompt-injection signals.")
    p.add_argument("path", help="File to scan, or '-' for stdin")
    p.add_argument("--json", action="store_true", help="Emit JSON")
    p.add_argument("--threshold", type=float, default=0.5)
    args = p.parse_args(argv)

    text = sys.stdin.read() if args.path == "-" else open(args.path, encoding="utf-8").read()
    result = scan(text, threshold=args.threshold)

    if args.json:
        print(json.dumps({
            "score": result.score,
            "suspicious": result.score >= args.threshold,
            "findings": [f.__dict__ for f in result.findings],
        }, indent=2))
    else:
        print(f"Result: {result.summary()}")
        for f in result.findings:
            print(f"  - {f.rule} ({f.weight}): {f.description}")
    return 1 if result.score >= args.threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
