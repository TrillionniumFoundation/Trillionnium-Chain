#!/usr/bin/env python3
"""Data-only SARIF publication packaging; no GitHub write/API capability.

This is a separate observation namespace. It does not change queries, findings,
coverage policy, the original runner result, or the official export predicate.
"""
import argparse
import copy
from decimal import Decimal
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
from urllib.parse import quote, unquote, urlsplit

SCHEMA = "pon-codeql-publication-bundle-v1"
LANGUAGES = {"actions", "python", "rust", "cpp"}
QUERY_COUNTS = {"actions": 18, "python": 45, "rust": 37, "cpp": 61}
LIMIT = 16 * 1024 * 1024
TOTAL = 64 * 1024 * 1024
BASE_FILES = ("analysis.sarif", "result.json", "source-before.json", "source-after.json")
CPP_FILES = ("cpp-source-copy-before.json", "cpp-source-copy-after.json",
             "cpp-scope/build/context.json", "cpp-scope/build/kernel-owned-original.c")
DEADLINE = 0.0

def require(ok, message):
    if not ok:
        raise ValueError(message)

def check_time():
    require(time.monotonic() < DEADLINE, "publication data verification deadline")

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def loads(raw, *, parse_float=float):
    require(len(raw) <= LIMIT, "publication JSON byte cap")
    return json.loads(raw, object_pairs_hook=pairs, parse_float=parse_float,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON")))

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()

def serialized(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                      allow_nan=False).encode() + b"\n"

def digest(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def relative(value):
    require(type(value) is str and value and "\\" not in value and "\0" not in value,
            "relative path type")
    p = PurePosixPath(value)
    require(not p.is_absolute() and all(x not in ("", ".", "..") for x in value.split("/"))
            and str(p) == value, "noncanonical relative path")
    return value

def read(root, name):
    check_time()
    parts = relative(name).split("/")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            before = os.fstat(child)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= LIMIT, "regular bounded data file required")
            chunks, size = [], 0
            while True:
                check_time()
                block = os.read(child, min(1024 * 1024, LIMIT + 1 - size))
                if not block:
                    break
                size += len(block)
                require(size <= LIMIT, "publication data byte cap")
                chunks.append(block)
            after = os.fstat(child)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            require(identity(before) == identity(after) and size == before.st_size, "data changed during read")
            return b"".join(chunks)
        finally:
            os.close(child)
    finally:
        os.close(fd)

class GitBlobs:
    def __init__(self, root, head):
        self.root, self.head, self.cache, self.total = str(root), head, {}, 0
        require(re.fullmatch(r"[0-9a-f]{40}", head), "exact SHA required")
        require(self.command("rev-parse", "HEAD").decode().strip() == head, "publisher checkout is not exact analyzed head")
        self.tree = self.command("rev-parse", head + "^{tree}").decode().strip()
        self.entries = {}
        for item in self.command("ls-tree", "-rz", "--full-tree", head).split(b"\0"):
            if item:
                meta, raw_path = item.split(b"\t", 1)
                mode, kind, oid = meta.decode().split()
                path = raw_path.decode()
                relative(path)
                require(path not in self.entries, "duplicate Git tree path")
                self.entries[path] = (mode, kind, oid)

    def command(self, *args):
        check_time()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
        process = subprocess.run(["git", "-C", self.root, *args], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                 timeout=min(15, max(0.001, DEADLINE - time.monotonic())))
        require(process.returncode == 0, "read-only exact Git object command failed")
        require(len(process.stdout) <= LIMIT and len(process.stderr) <= 65536, "Git command output cap")
        return process.stdout

    def blob(self, path):
        relative(path)
        if path not in self.cache:
            require(path in self.entries, "source URI is not a tracked path: " + path)
            mode, kind, oid = self.entries[path]
            require(kind == "blob" and mode in ("100644", "100755"), "source must be a regular Git blob")
            size_text = self.command("cat-file", "-s", oid).decode().strip()
            require(size_text.isdigit(), "Git blob size type")
            size = int(size_text)
            require(size <= LIMIT and self.total + size <= TOTAL, "source verification byte cap")
            raw = self.command("cat-file", "blob", oid)
            require(len(raw) == size and hashlib.sha1(b"blob " + str(size).encode() + b"\0" + raw).hexdigest() == oid,
                    "Git blob identity mismatch")
            self.total += size
            self.cache[path] = raw
        return self.cache[path]

    def binding(self, path):
        raw = self.blob(path)
        mode, _, oid = self.entries[path]
        return {"path": path, "git_blob": oid, "git_mode": mode, **digest(raw)}

def locations(document):
    """Yield only SARIF artifact locations, never prose/message/help URI strings."""
    found = []
    def walk(value, pointer):
        if type(value) is dict:
            for key, child in value.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                child_pointer = pointer + "/" + escaped
                # Tool taxonomy/model metadata can also use artifactLocation;
                # those are query-pack locations, not repository locations.
                # Preserve that entire metadata unchanged. Physical locations
                # and result fix targets are the source paths being mapped.
                source_location = pointer.endswith("/physicalLocation") or re.search(
                    r"/fixes/[0-9]+/artifactChanges/[0-9]+$", pointer)
                if key == "artifactLocation" and source_location:
                    require(type(child) is dict, "artifactLocation type")
                    found.append((child_pointer, child))
                else:
                    walk(child, child_pointer)
        elif type(value) is list:
            for index, child in enumerate(value):
                walk(child, pointer + "/" + str(index))
    walk(document, "")
    for i, artifact in enumerate(document["runs"][0].get("artifacts", [])):
        require(type(artifact) is dict and type(artifact.get("location")) is dict, "artifact location missing")
        found.append(("/runs/0/artifacts/" + str(i) + "/location", artifact["location"]))
    require(len(found) <= 50000, "artifact location count cap")
    return found

def rewrite(document, language, bindings, generated_uri):
    result, edits = copy.deepcopy(document), []
    artifacts = document["runs"][0].get("artifacts", [])
    for pointer, location in locations(result):
        original = copy.deepcopy(location)
        index = location.get("index")
        if index is not None:
            require(type(index) is int and 0 <= index < len(artifacts), "artifact index")
            indexed = artifacts[index]["location"]
            if "uri" in location:
                require(location["uri"] == indexed.get("uri")
                        and location.get("uriBaseId") == indexed.get("uriBaseId"), "inline/index URI disagreement")
        if "uri" not in location:
            require(index is not None, "artifact has neither URI nor index")
            continue
        uri = location["uri"]
        require(type(uri) is str and location.get("uriBaseId") in (None, "%SRCROOT%"), "unexpected URI base")
        split = urlsplit(uri)
        require(not split.scheme and not split.netloc and not split.query and not split.fragment, "unexpected source URI")
        decoded = relative(unquote(uri))
        require(quote(decoded, safe="/-._~") == uri, "noncanonical encoded source URI")
        if language == "cpp":
            if decoded.startswith("project/"):
                path = decoded[len("project/"):]
                require(path in bindings, "unbound project source")
                location["uri"] = quote(path, safe="/-._~")
            else:
                require(decoded == "build/kernel-owned-original.c" and generated_uri, "unbound C++ generated/external source")
                location["uri"] = generated_uri
                location.pop("uriBaseId", None)
        else:
            require(decoded in bindings, "unbound repository source")
        if canonical(location) != canonical(original):
            edits.append({"pointer": pointer, "before": original, "after": copy.deepcopy(location)})
    # This is a typed JSON equality proof, not an equal-count heuristic.
    restored = copy.deepcopy(result)
    for edit in edits:
        target = restored
        components = edit["pointer"].split("/")[1:]
        for component in components[:-1]:
            component = component.replace("~1", "/").replace("~0", "~")
            target = target[int(component)] if type(target) is list else target[component]
        last = components[-1].replace("~1", "/").replace("~0", "~")
        target[int(last) if type(target) is list else last] = copy.deepcopy(edit["before"])
    require(canonical(restored) == canonical(document), "non-location SARIF mutation")
    return result, edits

def derive(raws, git, head, language, run_id, attempt):
    require(language in LANGUAGES, "unknown language")
    require(type(run_id) is str and run_id.isdigit() and int(run_id) > 0
            and type(attempt) is str and attempt.isdigit() and int(attempt) > 0, "workflow identity")
    names = BASE_FILES + (CPP_FILES if language == "cpp" else ())
    require(set(raws) == set(names) and sum(map(len, raws.values())) <= TOTAL, "fixed original file set/budget")
    before, after = loads(raws["source-before.json"]), loads(raws["source-after.json"])
    require(canonical(before) == canonical(after), "source observation changed")
    require(before.get("schema") == "trnm-ci-source-v1" and before.get("kind") == "head"
            and before.get("tested_commit") == head and before.get("candidate") == head
            and before.get("tested_tree") == git.tree
            and before.get("tracked_worktree_verified") is True
            and type(before.get("tracked_entries")) is int
            and before["tracked_entries"] == len(git.entries), "source observation/Git binding")
    status = loads(raws["result.json"])
    require(status.get("schema") == "pon-pinned-codeql-analysis-v1"
            and status.get("expected_head") == head and status.get("language") == language, "analysis identity")
    # A completed scan with failed coverage must still publish its original
    # diagnostics and findings. Publication never turns that failure green.
    for key in ("analysis_execution_complete", "source_stable"):
        require(status.get(key) is True, "original analysis is incomplete: " + key)
    for key in ("passed", "extraction_coverage_complete"):
        require(type(status.get(key)) is bool, "original analysis verdict missing: " + key)
    for key in ("official_security_gate_qualified", "production_qualified", "query_or_model_changes"):
        require(status.get(key) is False, "original authority/scope contradiction")
    require(status.get("selected_query_count") == QUERY_COUNTS[language]
            and type(status.get("selected_query_count")) is int, "original query count")
    raw = raws["analysis.sarif"]
    require(status.get("sarif") == digest(raw), "original SARIF digest mismatch")
    doc = loads(raw)
    require(doc.get("version") == "2.1.0" and type(doc.get("runs")) is list and len(doc["runs"]) == 1, "one original SARIF run")
    run = doc["runs"][0]
    require(run.get("tool", {}).get("driver", {}).get("name") == "CodeQL"
            and run["tool"]["driver"].get("semanticVersion") == "2.27.3", "original tool")
    require(run.get("automationDetails", {}).get("id") == f"independent-artifact/{head}/{language}/code-scanning/",
            "original category must be retained")
    require(not run.get("originalUriBaseIds"), "unexpected original URI base table")
    require(type(run.get("results")) is list and type(status.get("finding_count")) is int
            and len(run["results"]) == status["finding_count"], "original results count")
    require(type(run.get("invocations")) is list and run["invocations"]
            and all(x.get("executionSuccessful") is True for x in run["invocations"]), "original invocation incomplete")
    paths = set()
    for _, loc in locations(doc):
        if "uri" in loc:
            value = unquote(loc["uri"])
            if language == "cpp":
                if value.startswith("project/"):
                    paths.add(relative(value[8:]))
                else:
                    require(value == "build/kernel-owned-original.c", "unexpected C++ source")
            else:
                paths.add(relative(value))
    bindings = {path: git.binding(path) for path in sorted(paths)}
    generated = None
    if language == "cpp":
        left, right = loads(raws["cpp-source-copy-before.json"]), loads(raws["cpp-source-copy-after.json"])
        require(canonical(left) == canonical(right) and status.get("cpp_source_copy_stable") is True, "C++ copy changed")
        rows = left.get("files")
        require(type(rows) is list and len(rows) == len(git.entries), "C++ copy inventory count")
        indexed = {r["path"]: r for r in rows}
        require(len(indexed) == len(rows) and set(indexed) == set(git.entries), "C++ copy path coverage")
        for path, binding in bindings.items():
            row = indexed[path]
            require(type(row.get("bytes")) is int and row["bytes"] == binding["bytes"]
                    and row.get("sha256") == binding["sha256"]
                    and row.get("mode") == int(binding["git_mode"], 8) & 0o777, "C++ copy/blob mismatch")
        context = loads(raws["cpp-scope/build/context.json"])
        require(context.get("schema") == "pon-pinned-codeql-cpp-context-v1"
                and context.get("complete") is True and context.get("runtime_build_qualified") is False
                and context.get("native_code_executed") is False, "C++ context scope")
        require(context.get("inputs_before") == context.get("inputs_after"), "C++ inputs changed")
        for path, expected in context["inputs_before"].items():
            require(digest(git.blob(path)) == expected, "C++ input/Git mismatch")
        root = Path(status["analysis_root"])
        require(root.is_absolute() and str(root / "project") == status["tracked_project_root"]
                and context["source_root"] == str(root / "project")
                and context["output"] == str(root / "build")
                and left["analysis_project"] == str(root / "project"), "C++ analysis root binding")
        generated_raw = raws["cpp-scope/build/kernel-owned-original.c"]
        require(digest(generated_raw) == context["generated"], "generated TU raw identity")
        components, offset, joined = context["components"], 0, b""
        require(type(components) is list and len(components) == 2, "original generated component count")
        for i, component in enumerate(components):
            raw_component = git.blob(component["source"])
            if i:
                joined += b"\n"
                offset += 1
            require(component["byte_start"] == offset
                    and component["byte_end_exclusive"] == offset + len(raw_component)
                    and component["line_start"] == joined.count(b"\n") + 1, "component original range")
            joined += raw_component
            offset += len(raw_component)
        require(joined == generated_raw, "generated TU does not equal original byte-bound components")
        generated = {"original_uri": (root / "build/kernel-owned-original.c").as_uri(),
                     **digest(generated_raw), "components": components, "tracked_git_file": False,
                     "github_repository_source_annotation_qualified": False}
    derived, edits = rewrite(doc, language, bindings, None if generated is None else generated["original_uri"])
    publication = serialized(derived) if language == "cpp" else raw
    require(len(publication) <= LIMIT and len(gzip.compress(publication, mtime=0)) <= 10 * 1024 * 1024, "SARIF upload byte bound")
    manifest = {"schema": SCHEMA, "repository": "TrillionniumFoundation/Trillionnium-Chain",
                "expected_head": head, "tested_tree": git.tree, "language": language,
                "workflow_run_id": run_id, "workflow_run_attempt": attempt,
                "original_files": {name: digest(raws[name]) for name in names},
                "original_sarif": digest(raw), "publication_sarif": digest(publication),
                "original_category": run["automationDetails"]["id"],
                "finding_count": len(run["results"]), "locations": edits,
                "original_analysis_passed": status["passed"],
                "original_extraction_coverage_complete": status["extraction_coverage_complete"],
                "git_blob_bindings": list(bindings.values()), "generated_source": generated,
                "all_other_typed_json_fields_identical": True,
                "original_bytes_preserved": True, "query_or_model_changes": False,
                "official_security_gate_qualified": False, "production_qualified": False,
                "physical_authentication": False}
    return publication, manifest

def exact_json_equal(left, right):
    """Compare a second Decimal parse without binary-float value collapse."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (left.keys() == right.keys()
                and all(exact_json_equal(value, right[key]) for key, value in left.items()))
    if type(left) is list:
        return (len(left) == len(right)
                and all(exact_json_equal(a, b) for a, b in zip(left, right)))
    if type(left) is Decimal:
        return left.is_finite() and right.is_finite() and left == right
    return left == right


def restore_metric_integer_spellings(left, right, exact_left, exact_right):
    """Allow only exact safe-integer serialization at SARIF metric value paths.

    The official JavaScript action serializes, for example, 100.0 as 100.
    Decimal is required: binary float can round a non-integer token to an
    integer before this check. No other numeric field receives this exception.
    Only comparison copies are restored; both original byte streams stay intact.
    """
    changes = []
    for ri, (old_run, new_run) in enumerate(zip(left["runs"], right["runs"])):
        old_properties, new_properties = old_run.get("properties", {}), new_run.get("properties", {})
        if type(old_properties) is not dict or type(new_properties) is not dict:
            continue
        old_metrics, new_metrics = old_properties.get("metricResults"), new_properties.get("metricResults")
        if type(old_metrics) is not list or type(new_metrics) is not list:
            continue
        require(len(old_metrics) == len(new_metrics), "metric result count changed")
        for mi, (old_metric, new_metric) in enumerate(zip(old_metrics, new_metrics)):
            require(type(old_metric) is dict and type(new_metric) is dict, "metric result type changed")
            old_value, new_value = old_metric.get("value"), new_metric.get("value")
            if type(old_value) is not float or type(new_value) is not int:
                continue
            precise_old = exact_left["runs"][ri]["properties"]["metricResults"][mi]["value"]
            precise_new = exact_right["runs"][ri]["properties"]["metricResults"][mi]["value"]
            require(type(precise_old) is Decimal and type(precise_new) is int
                    and math.isfinite(old_value) and precise_old.is_finite()
                    and -(2**53 - 1) <= new_value <= 2**53 - 1
                    and precise_old == precise_new,
                    "metric number is not an exact finite safe-integer serialization")
            changes.append({"pointer": f"/runs/{ri}/properties/metricResults/{mi}/value",
                            "original_decimal": str(precise_old),
                            "processed_integer": new_value})
            new_metric["value"] = old_value
            exact_right["runs"][ri]["properties"]["metricResults"][mi]["value"] = precise_old
    return changes


def compare_postprocessed(publication, processed):
    left, right = loads(publication), loads(processed)
    exact_left, exact_right = loads(publication, parse_float=Decimal), loads(processed, parse_float=Decimal)
    require(type(right.get("runs")) is list and len(right["runs"]) == len(left["runs"]), "upload run count changed")
    additions = []
    for ri, (old_run, new_run) in enumerate(zip(left["runs"], right["runs"])):
        require(len(old_run["results"]) == len(new_run.get("results", [])), "upload filtered/reordered results")
        for i, (old, new) in enumerate(zip(old_run["results"], new_run["results"])):
            before, after = old.get("partialFingerprints", {}), new.get("partialFingerprints", {})
            require(type(before) is dict and type(after) is dict, "fingerprint type")
            require(all(k in after and after[k] == v for k, v in before.items()), "existing fingerprint changed")
            precise_before = exact_left["runs"][ri]["results"][i].get("partialFingerprints", {})
            precise_after = exact_right["runs"][ri]["results"][i].get("partialFingerprints", {})
            require(all(k in precise_after and exact_json_equal(v, precise_after[k])
                        for k, v in precise_before.items()), "existing fingerprint changed")
            extra = set(after) - set(before)
            require(extra <= {"primaryLocationLineHash"}
                    and all(type(after[k]) is str and re.fullmatch(r"[0-9a-f]+:[1-9][0-9]*", after[k]) for k in extra),
                    "unexpected upload fingerprint change")
            if extra:
                additions.append({"run": ri, "result": i, "added": {k: after[k] for k in extra}})
            if "partialFingerprints" in old:
                new["partialFingerprints"] = copy.deepcopy(before)
                exact_right["runs"][ri]["results"][i]["partialFingerprints"] = copy.deepcopy(
                    exact_left["runs"][ri]["results"][i]["partialFingerprints"])
            else:
                new.pop("partialFingerprints", None)
                exact_right["runs"][ri]["results"][i].pop("partialFingerprints", None)
    number_changes = restore_metric_integer_spellings(left, right, exact_left, exact_right)
    require(exact_json_equal(exact_left, exact_right) and canonical(left) == canonical(right),
            "official postprocessing changed more than additive fingerprints and exact metric number serialization")
    return {"schema": "pon-codeql-publication-postprocessing-v1", "publication_sarif": digest(publication),
            "official_postprocessed_sarif": digest(processed), "additive_fingerprints": additions,
            "metric_number_serializations": number_changes,
            "all_results_rules_diagnostics_and_invocations_preserved": True,
            "official_security_gate_qualified": False, "production_qualified": False}

def main():
    global DEADLINE
    DEADLINE = time.monotonic() + 120
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "verify", "postprocessed"))
    parser.add_argument("--analysis", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--head")
    parser.add_argument("--language", choices=sorted(LANGUAGES))
    parser.add_argument("--run-id")
    parser.add_argument("--attempt")
    parser.add_argument("--processed", type=Path)
    args = parser.parse_args()
    if args.mode == "postprocessed":
        require(args.processed is not None, "processed SARIF required")
        value = compare_postprocessed(read(args.bundle, "publication.sarif"), read(args.processed.parent, args.processed.name))
        print(serialized(value).decode(), end="")
        return
    require(args.repo is not None and args.head and args.language and args.run_id and args.attempt, "source/workflow arguments required")
    git = GitBlobs(args.repo, args.head)
    names = BASE_FILES + (CPP_FILES if args.language == "cpp" else ())
    original_root = args.analysis if args.mode == "prepare" else args.bundle / "original"
    require(original_root is not None, "original analysis directory required")
    raws = {name: read(original_root, name) for name in names}
    publication, manifest = derive(raws, git, args.head, args.language, args.run_id, args.attempt)
    if args.mode == "prepare":
        args.bundle.mkdir()
        for name, raw in [("publication.sarif", publication), ("manifest.json", serialized(manifest))] + [
                ("original/" + name, raw) for name, raw in raws.items()]:
            path = args.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
    else:
        require(read(args.bundle, "publication.sarif") == publication, "derived publication bytes changed")
        require(canonical(loads(read(args.bundle, "manifest.json"))) == canonical(manifest), "publication manifest changed")
    print(serialized({"schema": "pon-codeql-publication-preflight-v1", "mode": args.mode,
                      "input_consistent": True, "expected_head": args.head, "language": args.language,
                      "manifest": digest(serialized(manifest)), "finding_count": manifest["finding_count"],
                      "official_security_gate_qualified": False, "production_qualified": False}).decode(), end="")

if __name__ == "__main__":
    main()
