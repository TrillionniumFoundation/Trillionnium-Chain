from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
import sys

MAX_PART_BYTES = 60_000
MAX_BLOCK_BYTES = 32_000
NESTED_PART_BYTES = 28_000

@dataclass
class Target:
    impl_signature: str
    label: str


def line_depths(text: str) -> list[int]:
    """Return brace depth at start of every line, ignoring comments/strings."""
    depths: list[int] = []
    depth = 0
    i = 0
    n = len(text)
    state = "normal"
    block_depth = 0
    raw_hashes = 0
    at_line_start = True
    while i < n:
        if at_line_start:
            depths.append(depth)
            at_line_start = False
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "line_comment":
            if c == "\n":
                state = "normal"
                at_line_start = True
            i += 1
            continue
        if state == "block_comment":
            if c == "/" and nxt == "*":
                block_depth += 1
                i += 2
                continue
            if c == "*" and nxt == "/":
                block_depth -= 1
                i += 2
                if block_depth == 0:
                    state = "normal"
                continue
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if state == "string":
            if c == "\\":
                if nxt == "\n":
                    at_line_start = True
                i += 2
                continue
            if c == '"':
                state = "normal"
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if state == "char":
            if c == "\\":
                if nxt == "\n":
                    at_line_start = True
                i += 2
                continue
            if c == "'":
                state = "normal"
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if state == "raw":
            if c == '"' and text.startswith("#" * raw_hashes, i + 1):
                i += 1 + raw_hashes
                state = "normal"
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if c == "/" and nxt == "/":
            state = "line_comment"
            i += 2
            continue
        if c == "/" and nxt == "*":
            state = "block_comment"
            block_depth = 1
            i += 2
            continue
        raw_start = None
        if c == "r":
            raw_start = i
            j = i + 1
        elif c == "b" and nxt == "r":
            raw_start = i
            j = i + 2
        else:
            j = i
        if raw_start is not None:
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                state = "raw"
                raw_hashes = hashes
                i = j + 1
                continue
        if c == '"' or (c == "b" and nxt == '"'):
            state = "string"
            i += 2 if c == "b" else 1
            continue
        if c == "'":
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
            else:
                j += 1
            if j < n and text[j] == "'":
                state = "char"
                i += 1
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                raise SystemExit("negative brace depth")
        if c == "\n":
            at_line_start = True
        i += 1
    if state == "block_comment":
        raise SystemExit("unterminated block comment")
    if depth != 0:
        raise SystemExit(f"unbalanced braces: {depth}")
    return depths[:len(text.splitlines())]


def find_block(lines: list[str], depths: list[int], signature: str, start_at: int = 0) -> tuple[int, int]:
    matches = [i for i in range(start_at, len(lines)) if depths[i] == 0 and lines[i].strip() == signature]
    if not matches:
        raise SystemExit(f"missing top-level block signature {signature!r}")
    start = matches[0]
    for i in range(start + 1, len(lines)):
        if depths[i] == 1 and lines[i].strip() == "}":
            return start, i
    raise SystemExit(f"unclosed block {signature!r}")


def member_starts(lines: list[str], depths: list[int], start: int, end: int) -> list[int]:
    starts: list[int] = []
    pending: int | None = None
    prefixes = (
        "pub fn ", "pub(crate) fn ", "pub(super) fn ", "fn ",
        "pub async fn ", "pub(crate) async fn ", "async fn ",
        "pub const ", "const ", "pub type ", "type ",
    )
    for i in range(start + 1, end):
        if depths[i] != 1:
            continue
        stripped = lines[i].lstrip()
        if not stripped:
            continue
        if stripped.startswith(("///", "#[")):
            if pending is None:
                pending = i
            continue
        if stripped.startswith("//"):
            if pending is None:
                pending = i
            continue
        if stripped.startswith(prefixes):
            starts.append(pending if pending is not None else i)
            pending = None
        else:
            pending = None
    if not starts:
        raise SystemExit(f"no splittable members in {lines[start].strip()!r}")
    return sorted(set(starts))


def split_impl_blocks(text: str, signatures: list[str], max_bytes: int) -> str:
    for signature in signatures:
        lines = text.splitlines(keepends=True)
        depths = line_depths(text)
        start, end = find_block(lines, depths, signature)
        block = "".join(lines[start:end + 1])
        if len(block.encode()) <= max_bytes:
            continue
        starts = member_starts(lines, depths, start, end)
        prefix = "".join(lines[start + 1:starts[0]])
        items: list[str] = []
        for idx, item_start in enumerate(starts):
            item_end = starts[idx + 1] if idx + 1 < len(starts) else end
            items.append("".join(lines[item_start:item_end]))
        chunks: list[str] = []
        current = prefix
        for item in items:
            prospective = f"{signature}\n{current}{item}}}\n"
            if current.strip() and len(prospective.encode()) > max_bytes:
                chunks.append(f"{signature}\n{current}}}\n\n")
                current = item
            else:
                current += item
        chunks.append(f"{signature}\n{current}}}\n")
        if len(chunks) == 1:
            raise SystemExit(f"cannot split oversized block {signature!r}")
        text = "".join(lines[:start]) + "".join(chunks) + "".join(lines[end + 1:])
        lines2 = text.splitlines(keepends=True)
        depths2 = line_depths(text)
        indices = [i for i, line in enumerate(lines2) if depths2[i] == 0 and line.strip() == signature]
        for idx in indices:
            for j in range(idx + 1, len(lines2)):
                if depths2[j] == 1 and lines2[j].strip() == "}":
                    size = len("".join(lines2[idx:j+1]).encode())
                    if size > max_bytes:
                        raise SystemExit(f"generated {signature!r} block remains {size} bytes")
                    break
    return text


def item_starts(lines: list[str], depths: list[int], body_start: int) -> list[int]:
    starts: list[int] = []
    pending: int | None = None
    prefixes = (
        "pub ", "fn ", "const ", "static ", "impl ", "mod ", "use ",
        "struct ", "enum ", "trait ", "type ", "macro_rules!", "unsafe ", "extern ",
    )
    for i in range(body_start, len(lines)):
        if depths[i] != 0:
            continue
        stripped = lines[i].lstrip()
        if not stripped:
            continue
        if stripped.startswith(("///", "#[")):
            if pending is None:
                pending = i
            continue
        if stripped.startswith("//"):
            if pending is None:
                pending = i
            continue
        if stripped.startswith(prefixes):
            starts.append(pending if pending is not None else i)
            pending = None
        else:
            pending = None
    return sorted(set(starts))


def split_test_module(text: str, prefix: str) -> tuple[str, dict[str, str]]:
    lines = text.splitlines(keepends=True)
    depths = line_depths(text)
    matches = [i for i, line in enumerate(lines) if depths[i] == 0 and line.strip() == "mod tests {"]
    if not matches:
        return text, {}
    start = matches[0]
    end = None
    for i in range(start + 1, len(lines)):
        if depths[i] == 1 and lines[i].strip() == "}":
            end = i
            break
    if end is None:
        raise SystemExit("unclosed top-level tests module")
    starts = member_starts(lines, depths, start, end)
    prefix_text = "".join(lines[start + 1:starts[0]])
    items = []
    for idx, item_start in enumerate(starts):
        item_end = starts[idx + 1] if idx + 1 < len(starts) else end
        items.append("".join(lines[item_start:item_end]))
    chunks = []
    current = ""
    for item in items:
        if current and len((current + item).encode()) > NESTED_PART_BYTES:
            chunks.append(current)
            current = item
        else:
            current += item
    if current:
        chunks.append(current)
    nested: dict[str, str] = {}
    include_lines = []
    for idx, chunk in enumerate(chunks, 1):
        relative = f"tests/{prefix}_tests_{idx:02d}.rs"
        nested[relative] = chunk
        include_lines.append(f'    include!("{relative}");\n')
    replacement = "mod tests {\n" + prefix_text + "".join(include_lines) + "}\n"
    return "".join(lines[:start]) + replacement + "".join(lines[end + 1:]), nested


def partition(path: Path, header_marker: str, impl_signatures: list[str], prefix: str) -> None:
    transformed = split_impl_blocks(path.read_text(encoding="utf-8"), impl_signatures, MAX_BLOCK_BYTES)
    transformed, nested_parts = split_test_module(transformed, prefix)
    lines = transformed.splitlines(keepends=True)
    depths = line_depths(transformed)
    marker_indices = [i for i, line in enumerate(lines) if depths[i] == 0 and line.startswith(header_marker)]
    if len(marker_indices) != 1:
        raise SystemExit(f"expected one header marker {header_marker!r}, got {len(marker_indices)}")
    body_start = marker_indices[0]
    header = "".join(lines[:body_start]).rstrip() + "\n\n"
    starts = item_starts(lines, depths, body_start)
    if not starts or starts[0] != body_start:
        raise SystemExit("first item start does not match body marker")
    items: list[str] = []
    for idx, start in enumerate(starts):
        end = starts[idx+1] if idx + 1 < len(starts) else len(lines)
        items.append("".join(lines[start:end]))
    parts_dir = path.parent / "lib_parts"
    parts_dir.mkdir(exist_ok=True)
    for old in parts_dir.glob("*.rs"):
        old.unlink()
    tests_dir = parts_dir / "tests"
    if tests_dir.exists():
        for old in tests_dir.glob("*.rs"):
            old.unlink()
    tests_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in nested_parts.items():
        destination = parts_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    chunks: list[str] = []
    current = ""
    for item in items:
        if current and len((current + item).encode()) > MAX_PART_BYTES:
            chunks.append(current)
            current = item
        else:
            current += item
    if current:
        chunks.append(current)
    if max(len(chunk.encode()) for chunk in chunks) > MAX_PART_BYTES * 2:
        raise SystemExit("oversized unsplittable top-level item remains")
    records = []
    includes = []
    for idx, chunk in enumerate(chunks, 1):
        filename = f"{prefix}_{idx:02d}.rs"
        (parts_dir / filename).write_text(chunk, encoding="utf-8")
        raw = chunk.encode()
        records.append({"path": f"lib_parts/{filename}", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        includes.append(f'include!("lib_parts/{filename}");')
    path.write_text(
        header
        + "// Directly reviewed source partition. Every included file is tracked in Git;\n"
          "// no build script or generated runtime source participates in compilation.\n\n"
        + "\n".join(includes)
        + "\n",
        encoding="utf-8",
    )
    nested_records = []
    for relative, content in sorted(nested_parts.items()):
        raw = content.encode("utf-8")
        nested_records.append({"path": f"lib_parts/{relative}", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    manifest = {
        "schema": "trnm_direct_rust_source_partition_v1",
        "crate": path.parent.parent.name,
        "semantic_generation": False,
        "max_part_bytes": MAX_PART_BYTES,
        "parts": records,
        "nested_test_parts": nested_records,
    }
    (parts_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    reconstructed = "".join((parts_dir / Path(record["path"]).name).read_text(encoding="utf-8") for record in records)
    if reconstructed != "".join(lines[body_start:]):
        raise SystemExit("partition body mismatch")
    print(json.dumps({"path": str(path), "parts": len(records), "max_bytes": max(record["bytes"] for record in records)}, sort_keys=True))


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: partition-large-rust.py <world-root> <game-server|campaign|rts>")
    root = Path(sys.argv[1])
    mode = sys.argv[2]
    if mode == "game-server":
        partition(root / "trillionnium/crates/trnm-game-server/src/lib.rs", "use axum::extract::DefaultBodyLimit;", [], "game_server")
    elif mode == "campaign":
        partition(root / "trillionnium/crates/trnm-campaign-core/src/lib.rs", "pub const CAMPAIGN_SAVE_CONTRACT", ["impl CampaignSaveV1 {"], "campaign")
    elif mode == "rts":
        partition(root / "trillionnium/crates/trnm-rts-sim/src/lib.rs", "pub const RTS_SIM_CONTRACT", ["impl MissionSimV1 {"], "rts")
    else:
        raise SystemExit(f"unknown mode {mode!r}")

if __name__ == "__main__":
    main()
