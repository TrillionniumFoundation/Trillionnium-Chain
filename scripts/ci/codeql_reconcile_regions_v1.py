#!/usr/bin/env python3
"""M17 candidate evidence only: match complete SARIF regions to GHAS alerts.

This is not a security disposition, independent review, or live GitHub check.
The normalized candidate records are authenticated by the replay driver before
calling this function. Source paths are compared exactly, without case folding,
prefix matching, or basename-only matching.
"""
from __future__ import annotations

import collections
import re
from typing import Any


def reconcile_regions(
    records: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    expected_source_sha: str,
    expected_source_tree: str,
    *,
    expected_ref: str,
) -> tuple[list[dict[str, Any]], set[str], collections.Counter[str]]:
    """Return (rows, mapped inventory IDs, status counts); never mutate inputs.

    Missing startColumn and endLine in a SARIF-derived candidate record have
    the SARIF 2.1.0 defaults of 1 and startLine. GHAS coordinates must be explicit.
    An absent endColumn cannot be reconstructed without source, so is rejected.
    Duplicate full regions remain ambiguous; message prefixes never break ties.
    """
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def digest(value, size):
        return (isinstance(value, str) and len(value) == size
                and all(c in "0123456789abcdef" for c in value))

    def integer(value):
        return type(value) is int and value > 0

    def region_key(rule, path, start_line, end_line, start_column, end_column):
        require(isinstance(rule, str) and rule.startswith("rust/"),
                "missing or unexpected Rust rule ID")
        require(isinstance(path, str) and path and not path.startswith("/")
                and "\\" not in path and ":" not in path
                and all(p not in ("", ".", "..") for p in path.split("/")),
                "invalid exact repository-relative source path")
        require(all(integer(v) for v in
                    (start_line, end_line, start_column, end_column)),
                "region coordinates must be positive integers")
        require(end_line >= start_line, "reversed line range")
        require(end_line != start_line or end_column >= start_column,
                "reversed column range")
        return (rule, path, start_line, end_line, start_column, end_column)

    require(digest(expected_source_sha, 40) and digest(expected_source_tree, 40),
            "expected commit/tree must be explicit SHA-1 identifiers")
    require(isinstance(records, list) and isinstance(alerts, list)
            and records and len(records) == len(alerts),
            "non-empty equal-cardinality inventories required")
    require(isinstance(expected_ref, str)
            and re.fullmatch(r"refs/pull/[1-9][0-9]*/head", expected_ref) is not None,
            "explicit pull-request head ref required")
    by_key = collections.defaultdict(list)
    inventory_ids = set()
    for record in records:
        require(isinstance(record, dict), "candidate record must be an object")
        require(record.get("exact_source_sha") == expected_source_sha
                and record.get("exact_source_tree") == expected_source_tree,
                "candidate source tuple drift")
        require(record.get("accepted") is False
                and record.get("acceptance_state") == "candidate-unreviewed"
                and record.get("independent_security_review_required") is True,
                "candidate acceptance semantics drift")
        inventory_id = record.get("inventory_id")
        require(digest(inventory_id, 64), "invalid immutable inventory ID")
        require(inventory_id not in inventory_ids, "duplicate immutable inventory ID")
        inventory_ids.add(inventory_id)
        primary = record.get("primary")
        require(isinstance(primary, dict), "candidate primary location missing")
        start_line = primary.get("line")
        end_line = primary.get("end_line")
        start_column = primary.get("column")
        key = region_key(record.get("rule_id"), primary.get("path"), start_line,
                         start_line if end_line is None else end_line,
                         1 if start_column is None else start_column,
                         primary.get("end_column"))
        by_key[key].append(record)

    reconciliation = []
    mapped_ids = set()
    alert_numbers = set()
    status_counts = collections.Counter()
    for alert in alerts:
        require(isinstance(alert, dict), "GHAS alert must be an object")
        number = alert.get("alert_number")
        require(integer(number) and number not in alert_numbers,
                "invalid or duplicate GHAS alert number")
        alert_numbers.add(number)
        require(alert.get("tool_name") == "CodeQL" and alert.get("state") == "open",
                "unexpected GHAS producer/state")
        instance = alert.get("most_recent_instance")
        require(isinstance(instance, dict), "GHAS instance missing")
        require(instance.get("commit_sha") == expected_source_sha,
                "GHAS source commit drift")
        require(instance.get("category") == "/language:rust"
                and instance.get("analysis_key") == "dynamic/github-code-scanning/codeql:analyze"
                and instance.get("ref") == expected_ref
                and instance.get("state") == "open",
                "GHAS analysis category/ref/state drift")
        loc = instance.get("location")
        require(isinstance(loc, dict), "GHAS full location missing")
        key = region_key(alert.get("rule_id"), loc.get("path"),
                         loc.get("start_line"), loc.get("end_line"),
                         loc.get("start_column"), loc.get("end_column"))
        candidates = by_key.get(key, [])
        inventory_id = None
        finding_id = None
        if len(candidates) == 1:
            status = "unique-rule-path-region"
            record = candidates[0]
            inventory_id = record["inventory_id"]
            finding_id = record.get("finding_id")
            require(inventory_id not in mapped_ids,
                    "multiple GHAS alerts map to the same immutable result")
            mapped_ids.add(inventory_id)
        elif not candidates:
            status = "unmapped"
        else:
            status = "ambiguous"
        status_counts[status] += 1
        reconciliation.append({
            "alert_number": number,
            "rule_id": alert.get("rule_id"),
            "path": loc.get("path"),
            "start_line": loc.get("start_line"),
            "end_line": loc.get("end_line"),
            "start_column": loc.get("start_column"),
            "end_column": loc.get("end_column"),
            "status": status,
            "inventory_id": inventory_id,
            "finding_id": finding_id,
            "candidate_inventory_ids": [r["inventory_id"] for r in candidates]
                                       if status != "unique-rule-path-region" else [],
        })
    return reconciliation, mapped_ids, status_counts
