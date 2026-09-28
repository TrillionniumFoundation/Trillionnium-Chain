# Cargo metadata consumer for the existing build-closure validator.
# Module quotient cycles are NOT actual normal Cargo dependency cycles.
from __future__ import annotations
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


class GraphError(RuntimeError):
    pass


def components(vertices: set[str], edges: list[dict]) -> list[list[str]]:
    if len(vertices) > 4096 or len(edges) > 65536:
        raise GraphError("graph exceeds the analysis bound")
    graph = {v: set() for v in vertices}
    for edge in edges:
        a, b = edge["source"], edge["target"]
        if a not in graph or b not in graph:
            raise GraphError("edge references an unknown vertex")
        graph[a].add(b)
    # Bounded iterative traversal avoids recursion exhaustion on a hostile graph.
    reachable = {}
    for root in sorted(vertices):
        seen, pending = set(), [root]
        while pending:
            v = pending.pop()
            if v not in seen:
                seen.add(v)
                pending.extend(graph[v] - seen)
        reachable[root] = seen
    unused, result = set(vertices), []
    while unused:
        root = min(unused)
        group = {v for v in unused if v in reachable[root] and root in reachable[v]}
        unused -= group
        if len(group) > 1 or root in graph[root]:
            result.append(sorted(group))
    return result


def analyze(metadata: dict, coverage: dict, registry: dict) -> dict:
    ids = metadata.get("workspace_members", [])
    packages = metadata.get("packages", [])
    if not ids or len(ids) != len(set(ids)):
        raise GraphError("missing or duplicate workspace member")
    package_by_id = {p["id"]: p for p in packages}
    if len(package_by_id) != len(packages) or set(ids) - package_by_id.keys():
        raise GraphError("ambiguous or absent workspace package")
    members = {pid: package_by_id[pid] for pid in ids}
    names = {p["name"] for p in members.values()}
    if len(names) != len(members):
        raise GraphError("ambiguous workspace package name")
    module_rows = registry.get("modules", [])
    allowed = {r["id"]: set(r["allowed_module_dependencies"]) for r in module_rows}
    if len(allowed) != len(module_rows) or not allowed:
        raise GraphError("duplicate or absent module registry")
    if any(deps - allowed.keys() for deps in allowed.values()):
        raise GraphError("registry contains unknown module dependencies")
    mapping = {}
    for row in coverage.get("module_coverage", []):
        if row["id"] not in allowed:
            raise GraphError("coverage refers to unknown module")
        for name in row.get("primary_crates", []):
            if name in mapping:
                raise GraphError("ambiguous crate module membership")
            mapping[name] = row["id"]
    if set(mapping) != names:
        raise GraphError(f"module coverage mismatch: missing={sorted(names-set(mapping))} extra={sorted(set(mapping)-names)}")
    declarations = []
    declaration_index = defaultdict(list)
    for package in members.values():
        for dep in package.get("dependencies", []):
            if dep["name"] not in names:
                continue
            kind = dep.get("kind") or "normal"
            if kind not in {"normal", "dev", "build"}:
                raise GraphError("unknown Cargo dependency kind")
            row = {"source": package["name"], "target": dep["name"],
                   "alias": dep.get("rename") or dep["name"], "kind": kind,
                   "optional": bool(dep.get("optional", False)),
                   "target_predicate": dep.get("target")}
            declarations.append(row)
            declaration_index[(row["source"], row["target"], kind)].append(row)
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise GraphError("full Cargo resolution is required; --no-deps is insufficient")
    nodes = resolve["nodes"]
    node_by_id = {n["id"]: n for n in nodes}
    if len(node_by_id) != len(nodes) or set(ids) - node_by_id.keys():
        raise GraphError("duplicate or missing resolved workspace node")
    edges = []
    for pid, package in members.items():
        for dep in node_by_id[pid].get("deps", []):
            target_id = dep["pkg"]
            if target_id not in package_by_id:
                raise GraphError("resolved edge references unknown package")
            if target_id not in members:
                continue
            target_name = members[target_id]["name"]
            kinds = dep.get("dep_kinds")
            if not kinds:
                raise GraphError("resolved dependency kind is missing")
            for item in kinds:
                kind = item.get("kind") or "normal"
                matches = [d for d in declaration_index[(package["name"], target_name, kind)]
                           if d["alias"].replace("-", "_") == dep["name"].replace("-", "_")
                           and d["target_predicate"] == item.get("target")]
                if len(matches) != 1:
                    raise GraphError("resolved edge lacks one exact manifest declaration")
                edges.append(dict(matches[0]))
    normal = [e for e in edges if e["kind"] == "normal"]
    module_edges = defaultdict(list)
    for edge in normal:
        a, b = mapping[edge["source"]], mapping[edge["target"]]
        if a != b:
            module_edges[(a, b)].append(edge)
    quotient = [{"source": a, "target": b, "witnesses": witnesses}
                for (a, b), witnesses in sorted(module_edges.items())]
    undeclared = [edge for edge in quotient if edge["target"] not in allowed[edge["source"]]]
    crate_cycles = components(names, normal)
    quotient_cycles = components(set(allowed), quotient)
    return {"workspace_package_count": len(members),
            "scope": "host-filtered-workspace-unified-features-not-individual-product",
            "declared_edges": declarations, "resolved_edges": edges,
            "resolved_features": {p["name"]: sorted(node_by_id[pid].get("features", []))
                                  for pid, p in members.items()},
            "normal_crate_cycles": crate_cycles, "module_quotient_cycles": quotient_cycles,
            "module_edges": quotient, "undeclared_normal_module_edges": undeclared,
            "module_architecture_satisfied": not (crate_cycles or quotient_cycles or undeclared),
            "production_acceptance": False}


def collect(root: Path) -> dict:
    def command(args):
        try:
            completed = subprocess.run(args, cwd=root, text=True, capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            raise GraphError(f"metadata infrastructure failure: {error}") from error
        if completed.returncode:
            raise GraphError(f"command exited {completed.returncode}: {completed.stderr[-4000:]}")
        return completed.stdout
    coverage_path = root / "config/module-coverage-v1.toml"
    registry_path = root / "docs/development/module-registry-v1.toml"
    tracked = [root / "trillionnium/Cargo.toml", root / "trillionnium/Cargo.lock",
               coverage_path, registry_path]
    tracked += sorted((root / "trillionnium/crates").glob("*/Cargo.toml"))
    def hashes():
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
    before = hashes()
    host_lines = command(["rustc", "-vV"]).splitlines()
    hosts = [line.split(": ", 1)[1] for line in host_lines if line.startswith("host: ")]
    if len(hosts) != 1:
        raise GraphError("one compiler host triple required")
    argv = ["cargo", "metadata", "--manifest-path", "trillionnium/Cargo.toml",
            "--format-version", "1", "--locked", "--offline", "--filter-platform", hosts[0]]
    raw = command(argv)
    report = analyze(json.loads(raw), tomllib.loads(coverage_path.read_text()),
                     tomllib.loads(registry_path.read_text()))
    if hashes() != before:
        raise GraphError("manifest/lock/registry changed during Cargo resolution")
    report.update(command=argv, input_sha256=before, metadata_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                  source=command(["git", "rev-parse", "HEAD"]).strip(),
                  tree=command(["git", "rev-parse", "HEAD^{tree}"]).strip(),
                  worktree_clean=not command(["git", "status", "--porcelain=v1"]).strip())
    return report
