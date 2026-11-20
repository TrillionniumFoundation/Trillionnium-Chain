#!/usr/bin/env python3
"""Build a HIA migration component with the exact pinned upstream compiler."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from toolchain import build_native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--kind", choices=("object", "shared"), default="object")
    parser.add_argument("--backend", choices=("direct", "selfhost"), required=True)
    parser.add_argument("--byte-export", action="append", default=[])
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--compiler-sha256")
    args = parser.parse_args()
    receipt, _ = build_native(args.source, args.output, byte_exports=args.byte_export,
        kind=args.kind, backend=args.backend, compiler=args.compiler,
        compiler_sha256=args.compiler_sha256)
    encoded = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    if args.receipt:
        with args.receipt.open("x") as stream:
            stream.write(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
