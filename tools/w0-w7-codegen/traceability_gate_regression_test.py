#!/usr/bin/env python3
"""Small, dependency-free regression checks for the G2.0 fail-closed gate."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import traceability_gate as gate  # noqa: E402


def expect_reject(label: str, fn) -> None:
    try:
        fn()
    except (gate.GateError, TypeError, ValueError):
        return
    raise AssertionError(f"negative case unexpectedly accepted: {label}")


def test_strict_json() -> None:
    expect_reject("duplicate key", lambda: gate.strict_loads(b'{"a":1,"a":2}'))
    expect_reject("trailing bytes", lambda: gate.strict_loads(b'{"a":1} trailing'))
    expect_reject("nonfinite", lambda: gate.strict_loads(b'{"a":NaN}'))
    expect_reject("boolean integer", lambda: gate.exact_int(True, "mutant"))


def test_dynamic_disabled_slots() -> None:
    operations = []
    for kind in range(30):
        disabled = kind in {20, 27}
        operations.append(
            {
                "kind": kind,
                "name": f"Operation{kind}",
                "body_type": f"Operation{kind}V1",
                "plane": "order-coordination-settlement" if kind == 27 else "agent",
                "status": "disabled" if disabled else "candidate-assigned",
                "enabled": False,
                "authority": "candidate-authority",
                "nonce_lane": "candidate-lane",
                **({"canonical_error": "ERR_OPERATION_DISABLED"} if disabled else {}),
            }
        )
    context = gate.Context(Path.cwd(), operations=operations, limits={
        "max_transaction_bytes": 1,
        "max_cev1_nesting": 1,
        "max_signature_work_per_transaction": 1,
        "max_operation_scopes": 1,
        "max_nonce_lanes_per_agent": 1,
        "max_protocol_objects_per_block": 1,
    }, domains=set(gate.DOMAIN_BY_PLANE.values()), trace_schema={"raw_sha256": "0" * 64})
    gate.build_rows(context)
    assert len(context.rows) == 30
    assert context.rows[20]["required_links"] == ["W0"]
    assert context.rows[27]["required_links"] == ["W0"]
    assert context.rows[29]["status"] == "candidate-assigned"


def test_real_a09_cli() -> None:
    """Ensure the corrected A09 CLI is source-pinned, not legacy --registry-dir."""
    manifest = gate.load_manifest(gate.ROOT / "docs/evidence/g2.0/g20-source-manifest-v1.json")
    a08_doc = manifest["a08"]
    a08 = gate.Source(
        "a08",
        a08_doc["ref"],
        a08_doc["commit"],
        a08_doc["tree"],
    )
    parser = gate.ROOT / gate.A09_PARSER_REL
    with tempfile.TemporaryDirectory(prefix="trnm-g20-cli-") as directory:
        evidence = Path(directory) / "evidence.json"
        command = gate.parser_command(
            parser,
            gate.ROOT,
            evidence,
            a08,
            gate.ROOT / gate.A08_CHECKER_REL,
        )
        help_text = subprocess.run(
            [sys.executable, str(parser), "--help"],
            cwd=gate.ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ).stdout
        if "--root" in help_text:
            assert "--root" in command
            assert "--a08-source-commit" in command
            assert "--a08-source-tree" in command
            assert "--require-a08-pin" in command
            assert "--a08-checker" in command
            assert "--registry-dir" not in command
            result = subprocess.run(command, cwd=gate.ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert result.returncode == 0, result.stderr or result.stdout
            value = gate.strict_loads(evidence.read_bytes(), "A09 CLI evidence")
            assert isinstance(value, dict) and gate.EVIDENCE_ID.fullmatch(value.get("evidence_id", ""))
        else:
            # A stale base is a supported diagnostic fixture, but it must be
            # explicit rather than silently treated as the corrected parser.
            assert "--registry-dir" in command


def test_manifest_rejects_weak_tuple(tmp: Path) -> None:
    value = {
        "schema": gate.MANIFEST_SCHEMA,
        "status": "upstream-pending",
        "a08": {"role": "a08", "ref": "x", "commit": "0" * 40, "tree": "1" * 40, "files": {}},
        "a09": {"role": "a09", "ref": "x", "commit": "0" * 40, "tree": "1" * 40, "files": {}},
        "traceability_schema": {"path": str(gate.TRACE_SCHEMA_REL), "sha256": "0" * 64},
        "artifacts": {"closure": "docs/evidence/g2.0/a.json", "evidence_index": "docs/evidence/g2.0/b.json"},
        "policy": {"required_registry_files": [], "required_a08_files": [], "required_a09_files": []},
    }
    path = tmp / "manifest.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    expect_reject("empty pinned file sets", lambda: gate.load_manifest(path))


def main() -> int:
    test_strict_json()
    test_dynamic_disabled_slots()
    test_real_a09_cli()
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix="trnm-g20-regression-") as value:
        test_manifest_rejects_weak_tuple(Path(value))
    print("g2.0 traceability gate regression: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
