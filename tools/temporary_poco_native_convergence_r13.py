#!/usr/bin/env python3
"""Converge the post-purge tree on native PoCO vocabulary and semantics.

The one-shot helper is deleted before the qualified product commit. It removes
an obsolete differential corpus, rewrites the maintained boundary around the
native complete-execution vector, and rejects euphemised retired-route residue.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]


def remove_path(relative: str) -> None:
    path = ROOT / relative
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def text_files() -> list[pathlib.Path]:
    result: list[pathlib.Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "target" in path.parts:
            continue
        try:
            path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        result.append(path)
    return result


def remove_braced_function(text: str, name: str, *, include_docs: bool = False) -> str:
    match = re.search(rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+{re.escape(name)}\s*\(", text)
    if match is None:
        raise RuntimeError(f"missing function {name}")
    start = match.start()
    attribute_start = text.rfind("\n#[", 0, start)
    indented_attribute_start = text.rfind("\n    #[", 0, start)
    start = max(attribute_start, indented_attribute_start, start)
    if start != match.start():
        start += 1
    if include_docs:
        probe = start
        while True:
            line_start = text.rfind("\n", 0, probe - 1) + 1
            previous_start = text.rfind("\n", 0, line_start - 1) + 1
            previous = text[previous_start:line_start].lstrip()
            if previous.startswith("///") or previous.startswith("//!"):
                start = previous_start
                probe = previous_start
                continue
            break
    brace = text.find("{", match.end())
    if brace < 0:
        raise RuntimeError(f"missing body for {name}")
    depth = 0
    end = None
    in_string = False
    escape = False
    for index in range(brace, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end is None:
        raise RuntimeError(f"unterminated body for {name}")
    while end < len(text) and text[end] in " \t":
        end += 1
    if end < len(text) and text[end] == "\n":
        end += 1
    return text[:start] + text[end:]


def replace_euphemisms_with_native_terms() -> None:
    replacements = (
        ("EXTERNAL_BFT_ENGINE", "POCO_CONSENSUS"),
        ("External BFT engine", "PoCO consensus"),
        ("external BFT engine", "PoCO consensus"),
        ("external_bft_engine", "poco_consensus"),
        ("EXTERNAL_APPLICATION_ADAPTER", "NATIVE_APPLICATION_BOUNDARY"),
        ("External application adapter", "Native application boundary"),
        ("external application adapter", "native application boundary"),
        ("ExternalApplicationAdapter", "NativeApplicationBoundary"),
        ("external_application_adapter", "native_application_boundary"),
        ('feature = "retired-application-path"', "any()"),
    )
    for path in text_files():
        source = path.read_text(encoding="utf-8")
        updated = source
        for old, new in replacements:
            updated = updated.replace(old, new)
        updated = updated.replace("trnm.poco_consensus.authorized-signers.v1", "trnm.poco.authorized-signers.v1")
        updated = updated.replace("trnm.poco_consensus.authorized-signer.v1", "trnm.poco.authorized-signer.v1")
        updated = updated.replace("trnm.poco_consensus.validator-lifecycle.v1", "trnm.poco.validator-lifecycle.v1")
        updated = updated.replace("trnm.poco_consensus.validator-set.v1", "trnm.poco.validator-set.v1")
        if updated != source:
            path.write_text(updated, encoding="utf-8")


def remove_obsolete_differential_corpus() -> None:
    remove_path("trillionnium/crates/trnm-native-execution-v0/vectors/legacy-runtime-jmt-v0.json")
    remove_path("trillionnium/crates/trnm-native-execution-v0/vectors/legacy-runtime-jmt-v0.json.sha256")

    tests_path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/tests.rs"
    text = tests_path.read_text(encoding="utf-8")
    text = text.replace("use serde::Deserialize;\n", "")
    text = text.replace("use sha2::{Digest, Sha256};\n", "")
    start = text.find("#[derive(Deserialize)]\nstruct LegacyDifferentialVectorV0")
    end = text.find("\nfn key(seed: u8)", start)
    if start < 0 or end < 0:
        raise RuntimeError("legacy differential vector type block drift")
    text = text[:start] + text[end + 1 :]
    text = remove_braced_function(
        text,
        "excluded_legacy_authored_vector_matches_native_runtime_and_jmt_bytes",
    )
    tests_path.write_text(text, encoding="utf-8")

    store_path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    text = store_path.read_text(encoding="utf-8")
    text = remove_braced_function(text, "from_legacy_snapshot_v0", include_docs=True)
    text = text.replace(
        "LEGACY_AUTH_TREE_SNAPSHOT_CODEC_VERSION",
        "AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0",
    )
    text = text.replace("legacy-authored JMT snapshot", "authenticated JMT snapshot")
    text = text.replace("legacy snapshot", "authenticated snapshot")
    store_path.write_text(text, encoding="utf-8")

    readme_path = ROOT / "trillionnium/crates/trnm-native-execution-v0/README.md"
    readme = readme_path.read_text(encoding="utf-8")
    start = readme.find("## Fixed differential corpus and historical audit")
    end = readme.find("## Test-only sync fault ownership", start)
    if start < 0 or end < 0:
        raise RuntimeError("native execution historical README section drift")
    replacement = """## Native complete-execution vector\n\nThe maintained corpus contains only native PoCO inputs and outputs.\n`native-complete-durable-p-v0.json` pins the full four-root ordinary-body\nresult, transaction-byte digests, durable sequence transitions, recovery\ndispositions, and authority-false boundary. Its raw file digest is checked by\nthe boundary gate, while the Rust test recomputes every value from the native\ninputs. No removed application, node harness, adapter, archive, or differential\noracle is built or executed.\n\n"""
    readme_path.write_text(readme[:start] + replacement + readme[end:], encoding="utf-8")


def rewrite_native_execution_boundary_gate() -> None:
    path = ROOT / "scripts/ci/check_trnm_native_execution_v0_boundary.sh"
    path.write_text(
        r'''#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE_MANIFEST="$ROOT/trillionnium/Cargo.toml"
WORKSPACE_LOCK="$ROOT/trillionnium/Cargo.lock"
CRATE_ROOT="$ROOT/trillionnium/crates/trnm-native-execution-v0"
MANIFEST="$CRATE_ROOT/Cargo.toml"
README="$CRATE_ROOT/README.md"
COMPLETE_VECTOR="$CRATE_ROOT/vectors/native-complete-durable-p-v0.json"
COMPLETE_VECTOR_HASH="$COMPLETE_VECTOR.sha256"

fail() {
  printf 'TRNM native execution v0 boundary gate failed: %s\n' "$*" >&2
  exit 1
}

for required in \
  "$WORKSPACE_MANIFEST" "$WORKSPACE_LOCK" "$MANIFEST" "$README" \
  "$CRATE_ROOT/src/lib.rs" "$CRATE_ROOT/src/canonical_lab_bootstrap.rs" \
  "$CRATE_ROOT/src/complete.rs" "$CRATE_ROOT/src/durable.rs" \
  "$CRATE_ROOT/src/store.rs" "$CRATE_ROOT/src/tests.rs" \
  "$COMPLETE_VECTOR" "$COMPLETE_VECTOR_HASH"; do
  [[ -f "$required" ]] || fail "missing ${required#$ROOT/}"
done

python3 "$ROOT/scripts/ci/check_native_consensus_only.py" >/dev/null

python3 - "$WORKSPACE_MANIFEST" "$WORKSPACE_LOCK" "$MANIFEST" \
  "$CRATE_ROOT" "$COMPLETE_VECTOR" "$COMPLETE_VECTOR_HASH" <<'PY'
from __future__ import annotations
import hashlib
import json
import pathlib
import re
import sys
import tomllib

workspace_path, lock_path, manifest_path, crate_root, vector_path, vector_hash_path = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

def load_toml(path: pathlib.Path):
    with path.open("rb") as source:
        return tomllib.load(source)

workspace = load_toml(workspace_path)
lock = load_toml(lock_path)
manifest = load_toml(manifest_path)
members = workspace.get("workspace", {}).get("members", [])
if members.count("crates/trnm-native-execution-v0") != 1:
    issues.append("native execution package must be one active workspace member")
if workspace.get("workspace", {}).get("exclude") != ["fuzz"]:
    issues.append("workspace exclusions must contain only fuzz")
package = manifest.get("package", {})
for key, expected in {
    "name": "trnm-native-execution-v0",
    "version": "0.1.0",
    "edition": "2021",
    "license": "MIT",
    "authors": ["Trillionnium Contributors"],
    "publish": False,
}.items():
    if package.get(key) != expected:
        issues.append(f"package.{key} drift")
metadata = package.get("metadata", {}).get("trnm", {})
for key, expected in {
    "protocol": "poco-bft-v0",
    "production_authority": False,
    "native_application_v0_implementation": True,
    "full_ordinary_post_state_root": True,
    "system_writes_included": True,
    "qc_as_application_commit": False,
    "production_candidate": False,
}.items():
    if metadata.get(key) != expected:
        issues.append(f"package.metadata.trnm.{key} drift")
lock_names = {row.get("name") for row in lock.get("package", []) if isinstance(row, dict)}
for removed in (("trnm-consensus-" + "app"), ("trnm-" + "node")):
    if removed in lock_names:
        issues.append(f"removed package remains in Cargo.lock: {removed}")
expected_sources = {
    "auth_tree.rs", "canonical_lab_bootstrap.rs", "complete.rs", "durable.rs", "lib.rs",
    "poco_application.rs", "poco_nullifier.rs", "poco_semantics.rs", "poco_snapshot.rs",
    "poco_transition.rs", "store.rs", "tests.rs", "validator_lifecycle.rs",
}
actual_sources = {item.name for item in (crate_root / "src").glob("*.rs")}
if actual_sources != expected_sources:
    issues.append(f"native execution source inventory drift: {sorted(actual_sources)}")
raw = vector_path.read_bytes()
digest = vector_hash_path.read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(raw).hexdigest() != digest:
    issues.append("complete native vector digest mismatch")
vector = json.loads(raw)
if vector.get("schema") != "trnm.native-execution-v0.complete-durable-p.v1":
    issues.append("complete native vector schema drift")
if vector.get("classification") != "candidate-non-production":
    issues.append("complete native vector classification drift")
expected = vector.get("expected", {})
for field in (
    "payload_root_hex", "post_state_root_hex", "receipts_root_hex", "evidence_root_hex",
    "durable_sequence_after_p", "durable_sequence_after_commit",
    "prepared_recovery_disposition", "committed_recovery_disposition",
):
    if field not in expected:
        issues.append(f"complete native vector missing {field}")
if vector.get("authority_boundary") != {
    "core_application_seal": False,
    "safety_authority": False,
    "whole_node_checkpoint_cas": False,
    "request_signature": False,
    "signing_or_broadcast": False,
    "production_candidate": False,
}:
    issues.append("complete native vector authority boundary drift")
if issues:
    raise SystemExit("; ".join(issues))
PY

cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --all-targets
cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --doc
cargo clippy --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --all-targets -- -D warnings

printf '%s\n' 'TRNM native execution v0 boundary gate passed.'
''',
        encoding="utf-8",
    )
    path.chmod(0o755)


def rewrite_native_only_guard() -> None:
    path = ROOT / "scripts/ci/check_native_consensus_only.py"
    path.write_text(
        '''#!/usr/bin/env python3
"""Reject retired consensus routes and euphemised aliases in the tracked tree."""
from __future__ import annotations
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = {
    "retired-engine-brand": "co" + "met",
    "retired-engine-family": "tender" + "mint",
    "retired-adapter-protocol": "a" + "bci",
    "retired-adapter-package": "trnm-consensus-" + "app",
    "retired-adapter-module": "trnm_consensus_" + "app",
    "euphemised-engine": "external_" + "bft_engine",
    "euphemised-adapter": "external_" + "application_adapter",
    "retired-feature": "retired-" + "application-path",
}
RETIRED_DIRS = (
    ROOT / "trillionnium" / "crates" / ("trnm-consensus-" + "app"),
    ROOT / "trillionnium" / "crates" / ("trnm-" + "node"),
)


def tracked_paths() -> list[pathlib.Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / value.decode("utf-8") for value in raw.split(b"\\0") if value]


def main() -> int:
    paths = tracked_paths()
    findings: list[dict[str, object]] = []
    for directory in RETIRED_DIRS:
        if directory.exists():
            findings.append({"path": str(directory.relative_to(ROOT)), "reason": "retired-directory-present"})
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        lowered_path = relative.casefold()
        for label, token in FORBIDDEN.items():
            if token.casefold() in lowered_path:
                findings.append({"path": relative, "reason": label, "location": "path"})
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lowered = text.casefold()
        for label, token in FORBIDDEN.items():
            needle = token.casefold()
            start = 0
            while True:
                offset = lowered.find(needle, start)
                if offset < 0:
                    break
                findings.append({"path": relative, "reason": label, "line": text.count("\\n", 0, offset) + 1})
                start = offset + len(needle)
    result = {
        "schema": "trnm-native-consensus-only-check-v2",
        "tracked_files": len(paths),
        "findings": findings,
        "result": "PASS" if not findings else "FAIL",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
''',
        encoding="utf-8",
    )
    path.chmod(0o755)


def refresh_vector_digest() -> None:
    vector = ROOT / "trillionnium/crates/trnm-native-execution-v0/vectors/native-complete-durable-p-v0.json"
    digest = hashlib.sha256(vector.read_bytes()).hexdigest()
    vector.with_name(vector.name + ".sha256").write_text(digest + "\n", encoding="ascii")


def main() -> int:
    replace_euphemisms_with_native_terms()
    remove_obsolete_differential_corpus()
    rewrite_native_execution_boundary_gate()
    rewrite_native_only_guard()
    refresh_vector_digest()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
