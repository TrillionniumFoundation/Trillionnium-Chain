#!/usr/bin/env python3
"""Build fail-closed candidate dispositions from one exact-source Rust CodeQL SARIF.

The output is review input only. It never marks a finding accepted or dismissed.
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import functools
import gzip
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

SOURCE_SHA = "ded43a0704b455cd4bef724cb3ca40fb6db9465d"
SOURCE_TREE = "c0791ffb57e05fde43f87bfed1a3b4656c09efc0"
PROSPECTIVE_MERGE = "0549e088e5a1108363e542bf02d6afc2c11ffed2"
WORKFLOW_RUN = 34298452515
ARTIFACT_ID = 10084352708
ARTIFACT_DIGEST = "sha256:f07a9cf0ccc003102a704190c2d16102eebe688874b43f8644a95fa440647d3d"
CODEQL_ACTION_SHA = "d1ba80a13dd99fba24a470575428917156a28b43"
ALLOWED_RULES = {
    "rust/hard-coded-cryptographic-value",
    "rust/cleartext-logging",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class Classifier:
    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root

    @functools.lru_cache(maxsize=None)
    def lines(self, path: str) -> list[str]:
        candidate = (self.source_root / path).resolve()
        root = self.source_root.resolve()
        if root not in candidate.parents:
            raise ValueError(f"path escapes source root: {path}")
        return candidate.read_text(encoding="utf-8", errors="replace").splitlines()

    @functools.lru_cache(maxsize=None)
    def source_sha256(self, path: str) -> str:
        candidate = (self.source_root / path).resolve()
        return sha256(candidate.read_bytes())

    def excerpt(self, path: str, line: int, context: int = 2) -> list[dict[str, Any]]:
        lines = self.lines(path)
        start = max(1, line - context)
        end = min(len(lines), line + context)
        return [{"line": index, "text": lines[index - 1]} for index in range(start, end + 1)]

    @staticmethod
    def dedicated_context(path: str) -> str | None:
        low = path.lower()
        name = Path(low).name
        if "/tests/" in low or name in {"tests.rs", "test.rs"} or name.endswith(("_test.rs", "_tests.rs")):
            return "dedicated-test"
        if "/fuzz/" in low or "/fuzz_targets/" in low:
            return "fuzz-target"
        if "/vectors/" in low:
            return "vector"
        if "fixture" in name or "/fixtures/" in low:
            return "fixture"
        if "/examples/" in low:
            return "example"
        if "simulator" in low or "/trnm-consensus-sim/" in low:
            return "simulator"
        if "lab-validator" in low or "/lab/" in low:
            return "lab"
        return None

    @functools.lru_cache(maxsize=None)
    def test_ranges(self, path: str) -> tuple[tuple[int, int, str], ...]:
        lines = self.lines(path)
        ranges: list[tuple[int, int, str]] = []

        def block(index: int, cap: int) -> tuple[int, int] | None:
            depth = 0
            started = False
            end = min(len(lines), index + cap)
            for cursor in range(index, min(len(lines), index + cap)):
                text = lines[cursor].split("//", 1)[0]
                text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
                for char in text:
                    if char == "{":
                        depth += 1
                        started = True
                    elif char == "}" and started:
                        depth -= 1
                        if depth == 0:
                            return index + 1, cursor + 1
            return (index + 1, end) if started else None

        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#[") and (
                re.search(r"\btest\b", stripped)
                or re.search(r'feature\s*=\s*"[^"]*(?:test|fixture|lab)[^"]*"', stripped)
            ):
                found = block(index, 4000)
                if found:
                    ranges.append((*found, "cfg-test-or-test-feature"))
            if re.search(r"#\s*\[\s*(?:(?:tokio|rstest)::)?test(?:\s*\([^\]]*\))?\s*\]", line):
                found = block(index, 500)
                if found:
                    ranges.append((*found, "test-function"))
        return tuple(ranges)

    def context(self, path: str, line: int) -> str:
        direct = self.dedicated_context(path)
        if direct:
            return direct
        for start, end, kind in self.test_ranges(path):
            if start <= line <= end:
                return kind
        lines = self.lines(path)
        nearby = "\n".join(lines[max(0, line - 30) : min(len(lines), line + 5)]).lower()
        if (
            re.search(r"\b(test|fixture|mock|mutant|scenario|sample|harness)[a-z0-9_]*\s*\(", nearby)
            or "test-only" in nearby
            or "fixture" in nearby
        ):
            return "test-helper-heuristic"
        return "runtime-or-unknown"

    @staticmethod
    def compact_location(location: dict[str, Any]) -> dict[str, Any]:
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        region = physical.get("region") or {}
        return {
            "path": artifact.get("uri"),
            "start_line": region.get("startLine"),
            "start_column": region.get("startColumn"),
            "end_line": region.get("endLine"),
            "end_column": region.get("endColumn"),
            "message": (location.get("message") or {}).get("text"),
        }

    def classify(self, result: dict[str, Any], ordinal: int) -> dict[str, Any]:
        rule = result.get("ruleId") or "<missing>"
        if rule not in ALLOWED_RULES:
            raise ValueError(f"unexpected rule: {rule}")
        primary = (result.get("locations") or [{}])[0].get("physicalLocation") or {}
        artifact = primary.get("artifactLocation") or {}
        region = primary.get("region") or {}
        path = artifact.get("uri")
        line = region.get("startLine")
        if not isinstance(path, str) or not isinstance(line, int):
            raise ValueError(f"missing primary location at ordinal {ordinal}")

        lines = self.lines(path)
        source_line = lines[line - 1].strip()
        context = self.context(path, line)
        related = [self.compact_location(item) for item in result.get("relatedLocations", [])]
        thread_flows: list[list[dict[str, Any]]] = []
        for code_flow in result.get("codeFlows", []):
            for thread_flow in code_flow.get("threadFlows", []):
                thread_flows.append(
                    [
                        self.compact_location(item.get("location") or {})
                        for item in thread_flow.get("locations", [])
                    ]
                )
        flattened = [item for flow in thread_flows for item in flow]
        terminal = flattened[-1] if flattened else None
        terminal_line = ""
        if terminal and isinstance(terminal.get("path"), str) and isinstance(terminal.get("start_line"), int):
            terminal_lines = self.lines(terminal["path"])
            terminal_line = terminal_lines[terminal["start_line"] - 1].strip()

        if rule == "rust/hard-coded-cryptographic-value":
            combined = (
                " ".join(str(item.get("message") or "") for item in related)
                + (result.get("message") or {}).get("text", "")
            ).lower()
            semantic = "nonce" if "nonce" in combined else "salt" if "salt" in combined else "unknown"
            literal = bool(
                re.search(r"\b(?:0x[0-9a-fA-F_]+|\d[\d_]*|u\d+::MAX|i\d+::MAX)\b", source_line)
            )
            if not literal and context == "runtime-or-unknown":
                candidate_class = "query-dataflow-false-positive"
                confidence = "medium"
                reachability = "no-literal-at-primary-location"
                rationale = (
                    "Primary location has no literal cryptographic value; the query appears to project "
                    "a deterministic state/revision flow onto a nonce sink. Specialist trace review is required."
                )
            else:
                candidate_class = "public-deterministic-protocol-test-value"
                confidence = "high" if context != "runtime-or-unknown" else "medium"
                reachability = (
                    "non-production-or-test"
                    if context != "runtime-or-unknown"
                    else "runtime-public-deterministic-value"
                )
                rationale = (
                    f"Candidate deterministic {semantic} is in {context} context and is not demonstrated "
                    "to be signing randomness, AEAD nonce material, or a secret. Preserve frozen bytes "
                    "until a specialist verifies the complete trace."
                )
            classifier_evidence = {
                "semantic_label": semantic,
                "literal_detected_at_primary": literal,
            }
        else:
            combined = (
                source_line + " " + terminal_line + " " + str((terminal or {}).get("message") or "")
            ).lower()
            actual_log = bool(
                re.search(r"\b(?:e?println!|tracing::|log::|error!|warn!|info!|debug!|trace!)", combined)
            )
            panic_or_assert = bool(
                re.search(r"\b(?:panic!|assert(?:_eq|_ne)?!|expect\s*\(|unwrap_or_else)", combined)
            )
            collection = bool(
                re.search(r"\.(?:insert|remove|push|push_front|push_back|extend|entry)\b", combined)
            )
            if actual_log and context == "runtime-or-unknown":
                candidate_class = "actionable-production-finding"
                confidence = "medium"
                reachability = "potential-production-log"
                rationale = (
                    "Trace reaches a process-visible runtime logging macro. Redact values or replace them "
                    "with bounded event codes and rerun exact-source CodeQL."
                )
            elif panic_or_assert or context != "runtime-or-unknown":
                candidate_class = "test-fixture-issue"
                confidence = "high" if panic_or_assert and context != "runtime-or-unknown" else "medium"
                reachability = "non-production-test-diagnostic"
                rationale = (
                    "Trace terminates in a test/assertion diagnostic or test/fixture context, not an "
                    "operational production logger. Confirm exclusion from production closures."
                )
            else:
                candidate_class = "query-dataflow-false-positive"
                confidence = "high" if collection else "medium"
                reachability = "not-a-log-sink" if collection else "no-visible-log-sink-observed"
                rationale = (
                    "No process-visible logging macro exists at the primary or terminal location; "
                    "the trace ends in state/collection code. Specialist confirmation remains required."
                )
            classifier_evidence = {
                "actual_log_macro_observed": actual_log,
                "panic_or_assert_observed": panic_or_assert,
                "collection_mutation_observed": collection,
            }

        message = (result.get("message") or {}).get("text") or ""
        result_hash = sha256(canonical(result))
        flow_hash = sha256(canonical(thread_flows))
        related_hash = sha256(canonical(related))
        partial = result.get("partialFingerprints") or {}
        partial_string = "|".join(f"{key}={partial[key]}" for key in sorted(partial))

        return {
            "ordinal": ordinal,
            "finding_id": f"{ordinal:04d}:{rule}:{result_hash[:20]}",
            "sarif_result_sha256": result_hash,
            "partial_fingerprint": partial_string,
            "rule_id": rule,
            "level": result.get("level"),
            "message_summary": {
                "sha256": sha256(message.encode("utf-8")),
                "bytes": len(message.encode("utf-8")),
                "prefix": message[:500],
            },
            "primary": {
                "path": path,
                "line": line,
                "column": region.get("startColumn"),
                "end_line": region.get("endLine"),
                "end_column": region.get("endColumn"),
                "source_file_sha256": self.source_sha256(path),
                "source_line": source_line,
                "excerpt": self.excerpt(path, line),
            },
            "trace_summary": {
                "thread_flow_count": len(thread_flows),
                "location_count": len(flattened),
                "sha256": flow_hash,
                "first": flattened[0] if flattened else None,
                "last": terminal,
            },
            "related_locations_summary": {
                "count": len(related),
                "sha256": related_hash,
                "items": related[:8],
                "truncated": len(related) > 8,
            },
            "terminal_source_line": terminal_line,
            "context_classification": context,
            "candidate_disposition_class": candidate_class,
            "candidate_confidence": confidence,
            "candidate_rationale": rationale,
            "production_reachability_candidate": reachability,
            "classifier_evidence": classifier_evidence,
            "acceptance_state": "candidate-unreviewed",
            "accepted": False,
            "independent_security_review_required": True,
            "exact_source_sha": SOURCE_SHA,
            "exact_source_tree": SOURCE_TREE,
        }


def write_package(sarif_path: Path, source_root: Path, output: Path) -> None:
    document = json.loads(sarif_path.read_text(encoding="utf-8"))
    runs = document.get("runs") or []
    if len(runs) != 1:
        raise ValueError(f"expected one SARIF run, found {len(runs)}")
    results = runs[0].get("results") or []
    if len(results) != 703:
        raise ValueError(f"expected 703 exact-source results, found {len(results)}")

    classifier = Classifier(source_root)
    records = [classifier.classify(item, index) for index, item in enumerate(results, start=1)]
    if len({item["finding_id"] for item in records}) != len(records):
        raise ValueError("duplicate finding_id")
    if len({item["sarif_result_sha256"] for item in records}) != len(records):
        raise ValueError("duplicate complete SARIF result hash")

    output.mkdir(parents=True, exist_ok=False)
    chunks_dir = output / "chunks"
    chunks_dir.mkdir()

    by_rule = collections.Counter(item["rule_id"] for item in records)
    by_class = collections.Counter(item["candidate_disposition_class"] for item in records)
    by_confidence = collections.Counter(item["candidate_confidence"] for item in records)
    by_context = collections.Counter(item["context_classification"] for item in records)

    chunks = []
    width = 176
    for start in range(0, len(records), width):
        part = records[start : start + width]
        payload = {
            "schema": "trnm-codeql-candidate-dispositions-v1",
            "repository": "TrillionniumFoundation/Trillionnium-Chain",
            "source_commit": SOURCE_SHA,
            "source_tree": SOURCE_TREE,
            "workflow_run": WORKFLOW_RUN,
            "artifact_id": ARTIFACT_ID,
            "artifact_digest": ARTIFACT_DIGEST,
            "range": {
                "first_ordinal": start + 1,
                "last_ordinal": start + len(part),
                "count": len(part),
            },
            "accepted": False,
            "independent_security_review_required": True,
            "findings": part,
        }
        raw = canonical(payload)
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        encoded = base64.b64encode(compressed) + b"\n"
        name = f"findings-{start + 1:04d}-{start + len(part):04d}.json.gz.b64"
        path = chunks_dir / name
        path.write_bytes(encoded)
        chunks.append(
            {
                "path": f"chunks/{name}",
                "first_ordinal": start + 1,
                "last_ordinal": start + len(part),
                "count": len(part),
                "base64_sha256": sha256(encoded),
                "gzip_sha256": sha256(compressed),
                "json_sha256": sha256(raw),
                "gzip_bytes": len(compressed),
                "json_bytes": len(raw),
            }
        )

    manifest = {
        "schema": "trnm-codeql-candidate-disposition-package-v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": "TrillionniumFoundation/Trillionnium-Chain",
        "source_commit": SOURCE_SHA,
        "source_tree": SOURCE_TREE,
        "prospective_merge": PROSPECTIVE_MERGE,
        "codeql_workflow_run": WORKFLOW_RUN,
        "codeql_artifact_id": ARTIFACT_ID,
        "codeql_artifact_digest": ARTIFACT_DIGEST,
        "codeql_action_sha": CODEQL_ACTION_SHA,
        "codeql_cli_version": "2.26.4",
        "language": "rust",
        "build_mode": "none",
        "query_suite": "security-extended",
        "result_count": len(records),
        "counts_by_rule": dict(sorted(by_rule.items())),
        "counts_by_candidate_class": dict(sorted(by_class.items())),
        "counts_by_confidence": dict(sorted(by_confidence.items())),
        "counts_by_context": dict(sorted(by_context.items())),
        "chunks": chunks,
        "candidate_only": True,
        "accepted": False,
        "independent_security_review_required": True,
        "official_codeql_gate_success": False,
        "production_candidate": False,
        "public_testnet_ready": False,
        "release_ready": False,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    readme = f"""# Rust CodeQL candidate disposition packet

Status: **candidate-unreviewed / accepted=false**

Exact source: `{SOURCE_SHA}` / `{SOURCE_TREE}`  
Prospective merge: `{PROSPECTIVE_MERGE}`  
CodeQL run/artifact: `{WORKFLOW_RUN}` / `{ARTIFACT_ID}`  
Artifact digest: `{ARTIFACT_DIGEST}`

The package contains {len(records)} per-result candidate records. Candidate totals:

```json
{json.dumps(dict(sorted(by_class.items())), indent=2, sort_keys=True)}
```

No finding is accepted, dismissed or suppressed. The complete original SARIF remains
in immutable Actions artifact `{ARTIFACT_ID}`. Each record binds its complete SARIF
result and trace by SHA-256 and retains bounded source/trace endpoints.

Run `python3 verify.py` inside this directory. Any source, tree, query suite, result
count or artifact change invalidates the packet. A non-author security specialist
must inspect the medium-confidence records and sample every high-confidence cluster
before an alert disposition or release decision.
"""
    (output / "README.md").write_text(readme, encoding="utf-8")
    verifier = Path(__file__).with_name("verify_codeql_candidate_dispositions.py")
    shutil.copy2(verifier, output / "verify.py")
    files = sorted(path for path in output.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256(path.read_bytes())}  {path.relative_to(output)}\n" for path in files),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_package(args.sarif.resolve(), args.source_root.resolve(), args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
