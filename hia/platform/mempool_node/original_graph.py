"""Complete literal include graph for actual original Node compilation."""
import re,tomllib
from hia.platform.execution_state.rust_oracle import need,canonical_root,canonical_path as canonical_file
SKIP=frozenset(("target","__pycache__",".pytest_cache"))

def include_graph(repository):
    """Resolve literal source/data includes in the complete local Node graph."""
    repository = canonical_root(repository)
    workspace = tomllib.loads(canonical_file(repository, "trillionnium/Cargo.toml").read_text())
    inherited = workspace.get("workspace", {}).get("dependencies", {})
    pending = ["trillionnium/crates/trnm-pon-node"]; visited = set(); includes = {}
    literal = re.compile(rb'\b(include|include_str|include_bytes)!\s*\(\s*"([^"\\\r\n]*)"\s*,?\s*\)')
    occurrence = re.compile(rb"\b(?:include|include_str|include_bytes)!\s*\(")
    manifest_literal = re.compile(
        rb'\b(include_str|include_bytes)!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"(/[^"\\\r\n]*)"\s*,?\s*\)\s*,?\s*\)')
    def relative(base, value):
        need(type(value) is str and value and not value.startswith("/") and "\\" not in value and "\0" not in value,
             "Noncanonical local Cargo/include path")
        parts = base.split("/")
        for part in value.split("/"):
            need(part != "", "Empty original path component")
            if part == ".": continue
            if part == "..":
                need(bool(parts), "Original path escaped repository"); parts.pop()
            else: parts.append(part)
        need(bool(parts), "Original include resolves to repository")
        return "/".join(parts)
    while pending:
        package = pending.pop()
        if package in visited: continue
        visited.add(package)
        manifest = tomllib.loads(canonical_file(repository, package + "/Cargo.toml").read_text())
        tables = [manifest, *manifest.get("target", {}).values()]
        for table in tables:
            need(type(table) is dict, "Malformed original Cargo target table")
            for category in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, value in table.get(category, {}).items():
                    if type(value) is str: continue
                    need(type(value) is dict, "Malformed original Cargo dependency")
                    base = package
                    if value.get("workspace") is True:
                        need(name in inherited, "Missing inherited original dependency")
                        value = inherited[name]; base = "trillionnium"
                        if type(value) is str: continue
                    if "path" in value:
                        target = relative(base, value["path"])
                        canonical_file(repository, target + "/Cargo.toml"); pending.append(target)
        for path in sorted((repository / package).rglob("*.rs")):
            if any(p in SKIP for p in path.relative_to(repository).parts): continue
            source = path.relative_to(repository).as_posix()
            raw = canonical_file(repository, source).read_bytes()
            found = list(literal.finditer(raw))
            bound_manifest = list(manifest_literal.finditer(raw))
            need(len(found) + len(bound_manifest) == len(occurrence.findall(raw)),
                 "Unsupported original include expression: " + source)
            for match, base, value, form in [
                    *[(m, path.parent.relative_to(repository).as_posix(), m[2].decode(), "file-relative")
                      for m in found],
                    *[(m, package, m[2].decode()[1:], "bound-CARGO_MANIFEST_DIR")
                      for m in bound_manifest]]:
                target = relative(base, value)
                canonical_file(repository, target)
                includes.setdefault(target, []).append({"source": source, "kind": match[1].decode(),
                                                         "literal": match[2].decode(), "form": form})
    return {"local_packages": sorted(visited), "includes": dict(sorted(includes.items()))}
