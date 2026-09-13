#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$repo_root/scripts/ci/check_poco_ai_native_v1_foundation_independent.py"

fail() {
  printf 'PoCO AI-native v1 independent foundation/order gate failed: %s\n' "$*" >&2
  exit 1
}

[[ -f "$checker" ]] || fail "missing ${checker#$repo_root/}"

# Keep this evidence implementation independent of the authoring checker and
# dependency-free beyond Python's standard library.  AST inspection prevents a
# future convenience import from silently collapsing the two implementations.
PYTHONDONTWRITEBYTECODE=1 python3 - "$checker" <<'PY'
from __future__ import annotations

import ast
import pathlib
import sys

checker = pathlib.Path(sys.argv[1])
tree = ast.parse(checker.read_text(encoding="utf-8"), filename=str(checker))
allowed = {
    "__future__",
    "argparse",
    "copy",
    "hashlib",
    "json",
    "pathlib",
    "sys",
    "typing",
}
imports: set[str] = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.update(alias.name.split(".", 1)[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom):
        imports.add((node.module or "").split(".", 1)[0])

unexpected = sorted(imports - allowed)
if unexpected:
    raise SystemExit(f"non-stdlib or unapproved imports: {unexpected}")

source = checker.read_text(encoding="utf-8")
for literal in (
    "STANDARD_LIBRARY_ONLY = True",
    "INDEPENDENT_IMPLEMENTATION = True",
):
    if literal not in source:
        raise SystemExit(f"missing independence boundary literal: {literal}")
PY

PYTHONDONTWRITEBYTECODE=1 \
  python3 "$checker" --self-test
