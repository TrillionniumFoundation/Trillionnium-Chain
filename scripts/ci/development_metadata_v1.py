#!/usr/bin/env python3
"""Non-authoritative development metadata, distinct from runtime acceptance."""
from __future__ import annotations

import re
from typing import Any


class MetadataError(ValueError):
    pass


def staffing_observation(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Staff estimates are advisory; neither 48 nor any other total is a gate."""
    total = 0
    warnings = []
    for row in rows:
        value = next((row[key] for key in
                      ("staff", "staff_target", "target_staff", "recommended_staff")
                      if key in row), None)
        if type(value) is int and value > 0:
            total += value
        else:
            warnings.append(f"{row.get('id', '?')}: staffing estimate unspecified or invalid")
    return {"staff_target": total, "warnings": warnings, "authority": "planning-only"}


def valid_successor(value: Any) -> bool:
    """None means no currently selected PR. Zero and booleans are not PR IDs."""
    return value is None or (type(value) is int and 0 < value <= 2**31 - 1)


def validate_observed_stack(observation: dict[str, Any]) -> None:
    """Validate connected lineage, not particular PR numbers or branch names.

    This is a source observation, never proof of review, merge or acceptance.
    Actual CI source/head/base/merge identities are checked by runtime binding.
    """
    selected = observation.get("selected_successor_pr")
    stack = observation.get("stack")
    if not valid_successor(selected) or not isinstance(stack, list) or len(stack) > 32:
        raise MetadataError("invalid selected successor or bounded stack")
    if selected is None:
        if stack:
            raise MetadataError("unselected successor must have an empty current stack")
        return
    if not stack or not isinstance(stack[0], dict) or stack[0].get("pr") != selected:
        raise MetadataError("selected successor is not the root PR")
    previous = "main"
    seen_prs: set[int] = set()
    seen_heads = {"main"}
    for row in stack:
        if not isinstance(row, dict) or set(row) != {"pr", "base_ref", "head_ref"}:
            raise MetadataError("invalid stack entry")
        number, base, head = row["pr"], row["base_ref"], row["head_ref"]
        if number is None or not valid_successor(number) or number in seen_prs:
            raise MetadataError("invalid or duplicate stack PR")
        if base != previous or not isinstance(head, str) or head in seen_heads:
            raise MetadataError("disconnected or cyclic observed stack")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", head):
            raise MetadataError("invalid observed branch")
        if any(part in {"", ".", ".."} or part.endswith(".lock")
               for part in head.split("/")) or ".." in head or head.endswith("."):
            raise MetadataError("invalid observed branch")
        seen_prs.add(number)
        seen_heads.add(head)
        previous = head


def require_same_successor(*values: Any) -> None:
    if not values or any(not valid_successor(value) for value in values):
        raise MetadataError("invalid selected successor")
    if any(value != values[0] for value in values):
        raise MetadataError("selected successor observations disagree")
