#!/usr/bin/env python3
"""Check repository-style inline Markdown links plus reference definitions.

The repository gate checks inline links after removing fenced code. This audit
uses the same inline syntax and also checks reference definitions, including
unused definitions. It checks local file membership in Git's tracked set;
directory links require a tracked descendant because Git does not track dirs.
This is not a general CommonMark parser or an anchor/HTML-link validator.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit


SKIP = {".git", "target", "__pycache__", ".pytest_cache", "node_modules"}


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def state(root):
    return {
        "head": git(root, "rev-parse", "HEAD").decode().strip(),
        "tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
        "status_porcelain": git(root, "status", "--porcelain=v1", "--untracked-files=all").decode(),
    }


def markdown_files(root):
    result = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in SKIP)
        for name in sorted(names):
            path = Path(current) / name
            if path.suffix == ".md" and path.is_file():
                result.append(path)
    return sorted(result)


def save(directory, name, value):
    with (directory / name).open("x") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output_directory.resolve()
    output.mkdir()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    then = time.monotonic()
    before = state(root)
    save(output, "state-before.json", before)
    if before["head"] != args.expected_head or before["status_porcelain"]:
        raise ValueError("exact clean expected source required")
    tracked_raw = git(root, "ls-files", "-z")
    tracked = {os.fsdecode(name) for name in tracked_raw.split(b"\0") if name}
    tracked_dirs = {"."}
    for name in tracked:
        tracked_dirs.update(str(parent) for parent in Path(name).parents)

    links, failures, file_hashes = [], [], {}
    ignored_external_or_fragment = 0
    inline_count, definition_count = 0, 0
    files = markdown_files(root)
    for path in files:
        source = str(path.relative_to(root))
        data = path.read_bytes()
        file_hashes[source] = hashlib.sha256(data).hexdigest()
        # Match the repository gate's fencing and inline-link scope exactly.
        prose = re.sub(r"^```[^\n]*\n.*?^```[^\n]*$", "", data.decode(), flags=re.M | re.S)
        occurrences = [("inline", target) for target in re.findall(r"\[[^\]]*\]\(([^\s)]+)\)", prose)]
        occurrences += [("reference_definition", target) for target in re.findall(
            r"^[ ]{0,3}\[[^\]\n]+\]:[ \t]*(<[^>\n]+>|[^\s]+)", prose, flags=re.M
        )]
        for kind, target in occurrences:
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or parsed.netloc or not parsed.path:
                ignored_external_or_fragment += 1
                continue
            resolved = (path.parent / unquote(parsed.path)).resolve()
            contained = resolved.is_relative_to(root)
            relative = str(resolved.relative_to(root)) if contained else None
            is_file = contained and resolved.is_file()
            is_directory = contained and resolved.is_dir()
            tracked_file = bool(is_file and relative in tracked)
            tracked_directory = bool(is_directory and relative in tracked_dirs)
            row = {
                "source": source,
                "source_is_tracked": source in tracked,
                "kind": kind,
                "target": target,
                "resolved_target": relative,
                "contained": contained,
                "file": is_file,
                "directory": is_directory,
                "tracked_file": tracked_file,
                "directory_has_tracked_descendants": tracked_directory,
            }
            links.append(row)
            inline_count += kind == "inline"
            definition_count += kind == "reference_definition"
            if not (tracked_file or tracked_directory):
                failures.append(row)
    after_hashes = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in markdown_files(root)
    }
    after = state(root)
    save(output, "state-after.json", after)
    save(output, "markdown-sha256-before.json", file_hashes)
    save(output, "markdown-sha256-after.json", after_hashes)
    save(output, "local-link-targets.json", links)
    save(output, "failures.json", failures)
    stable = before == after and file_hashes == after_hashes
    summary = {
        "schema": "tracked-markdown-target-audit-v1",
        "result": "PASS" if not failures and stable else "FAIL",
        "root": str(root),
        "expected_head": args.expected_head,
        "head": before["head"],
        "tree": before["tree"],
        "clean_before": not before["status_porcelain"],
        "clean_after": not after["status_porcelain"],
        "source_state_and_markdown_hashes_equal_at_endpoints": stable,
        "markdown_files_physically_read": len(files),
        "untracked_markdown_sources": sorted(set(file_hashes) - tracked),
        "local_inline_link_occurrences": inline_count,
        "local_reference_definition_occurrences": definition_count,
        "local_target_occurrences": len(links),
        "unique_local_targets": len({row["resolved_target"] for row in links}),
        "file_target_occurrences": sum(row["file"] for row in links),
        "directory_target_occurrences": sum(row["directory"] for row in links),
        "ignored_external_or_fragment_occurrences": ignored_external_or_fragment,
        "invalid_or_untracked_target_occurrences": len(failures),
        "git_tracked_set_sha256": hashlib.sha256(tracked_raw).hexdigest(),
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "syntax_scope": "Repository inline-link syntax after fenced-code removal, plus all reference definitions; not a CommonMark/HTML/anchor validator.",
        "directory_rule": "A contained local directory must have at least one tracked descendant.",
        "started_at_utc": started,
        "elapsed_seconds": time.monotonic() - then,
        "production_qualified": False,
    }
    save(output, "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
