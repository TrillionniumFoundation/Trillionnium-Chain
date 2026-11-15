#!/usr/bin/env python3
"""Pure retained-log observations; no scanner, toolchain or security verdict.

This selected component accepts explicit bounded byte streams and a declared
source inventory. It never starts CodeQL, reads a live process, infers active
modules, authorizes a result, or changes the current security gate.
"""
from __future__ import annotations

import collections
import hashlib
from pathlib import PurePosixPath
import re
from urllib.parse import unquote, urlsplit

LOG_LIMIT = 32 * 1024 * 1024
SEMANTIC_DIAGNOSTIC_LIMIT = 10000
SEMANTIC_MARKERS = (b"semantic analyzer unavailable", b"failed to load workspace",
                    b"macro expansion will be skipped")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def source_uri(uri, root):
    require(type(uri) is str, "diagnostic source URI type")
    url = urlsplit(uri)
    require(url.scheme in ("", "file") and not url.netloc and not url.query and not url.fragment,
            "diagnostic source URI scheme")
    path = PurePosixPath(unquote(url.path))
    require(".." not in path.parts, "diagnostic source traversal")
    if path.is_absolute():
        try:
            return str(path.relative_to(PurePosixPath(str(root))))
        except ValueError:
            return None
    return str(path)


def semantic_extraction_observations(streams, tracked, source_root):
    """Locate retained semantic failures, including informational diagnostics.

    Extraction success only establishes that a file entered the database. The
    extractor can emit INFO-level semantic failures that SARIF does not retain
    as warnings. This inventory never infers an active module from its path or
    excuses archived, platform-specific or include!-composed source files.
    """
    require(set(streams) == {"stdout", "stderr"}, "both retained creation streams required")
    require(all(type(raw) is bytes and len(raw) <= LOG_LIMIT for raw in streams.values()),
            "creation stream bound")
    tracked = set(tracked)
    rows, reasons, markers, unlocated = [], collections.Counter(), collections.Counter(), 0
    count = 0
    ansi = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
    location = re.compile(r"(?P<path>[^\s\x00]+\.rs):(?P<line>[0-9]+):(?P<column>[0-9]+): "
                          r"semantic analyzer unavailable \((?P<reason>[^\r\n]+)\):")
    for stream, raw in streams.items():
        for line_number, original in enumerate(raw.splitlines(), 1):
            clean = ansi.sub(b"", original)
            present = [marker for marker in SEMANTIC_MARKERS if marker in clean.lower()]
            if not present:
                continue
            count += 1
            markers.update(marker.decode("ascii") for marker in present)
            text = clean.decode("utf-8", errors="replace")
            match = location.search(text)
            relative = None
            if match:
                try:
                    relative = source_uri(match["path"], source_root)
                except ValueError:
                    pass
                reasons[match["reason"]] += 1
            if relative is None:
                unlocated += 1
            if len(rows) < SEMANTIC_DIAGNOSTIC_LIMIT:
                rows.append({"stream": stream, "retained_log_line": line_number,
                             "raw_line_sha256": hashlib.sha256(original).hexdigest(),
                             "source_path": relative, "tracked_source": relative in tracked,
                             "source_line": int(match["line"]) if match else None,
                             "source_column": int(match["column"]) if match else None,
                             "reason": match["reason"] if match else None,
                             "failure_markers": [marker.decode("ascii") for marker in present]})
    return {"schema": "pon-pinned-codeql-semantic-extraction-v1",
            "scope": "Retained creation-log observations only; no active-module, feature, platform, semantic-success or security qualification is inferred.",
            "retained_logs": {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                              for name, raw in streams.items()},
            "diagnostic_line_count": count, "retained_diagnostic_count": len(rows),
            "diagnostic_inventory_complete": count == len(rows), "diagnostic_limit": SEMANTIC_DIAGNOSTIC_LIMIT,
            "failure_markers": sorted(markers), "marker_line_counts": dict(sorted(markers.items())),
            "reason_counts": dict(sorted(reasons.items())), "unlocated_diagnostic_count": unlocated,
            "affected_tracked_files": sorted({row["source_path"] for row in rows if row["tracked_source"]}),
            "diagnostics": rows, "semantic_coverage_qualified": False,
            "official_security_gate_qualified": False}
