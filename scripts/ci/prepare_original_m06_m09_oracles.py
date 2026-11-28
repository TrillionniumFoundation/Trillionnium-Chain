"""Provision exact original M06/M09 dependencies before native General discovery."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
LOCK = ROOT/"trillionnium/Cargo.lock"
M06 = {
    "serde_json": ("1.0.149", ("default", "std")),
    "hex": ("0.4.3", ("alloc", "default", "std")),
    "serde_core": ("1.0.229", ("result", "std")),
    "itoa": ("1.0.18", ()),
    "memchr": ("2.8.0", ("alloc", "std")),
    "zmij": ("1.0.21", ()),
}
# Actual ordinary Rust module edges. The original lock may cover optional
# features not active in this General artifact.
M06_LINKS = {
    "serde_json": {"memchr", "itoa", "serde_core", "zmij", "build_script_build"},
    "serde_core": {"build_script_build"},
    "hex": set(), "itoa": set(), "memchr": set(), "zmij": {"build_script_build"},
}
# Edges exactly match the ordinary profile's active dependencies. Retain the
# locked cross-target libc edge of cpufeatures, not the optional ASM profile.
SHA_LOCK = {
    "sha2": ("0.10.9", ("cfg-if", "cpufeatures", "digest")),
    "cfg-if": ("1.0.4", ()),
    "cpufeatures": ("0.2.17", ("libc",)),
    "digest": ("0.10.7", ("block-buffer", "crypto-common")),
    "block-buffer": ("0.10.4", ("generic-array",)),
    "crypto-common": ("0.1.7", ("generic-array", "typenum")),
    "generic-array": ("0.14.7", ("typenum", "version_check")),
    "typenum": ("1.20.1", ()),
    "version_check": ("0.9.5", ()),
    "libc": ("0.2.184", ()),
}
SHA_BUILD = {
    "sha2": ("default", "std"),
    "cfg-if": (),
    "cpufeatures": (),
    "digest": ("alloc", "block-buffer", "core-api", "default", "std"),
    "block-buffer": (),
    "crypto-common": ("std",),
    "generic-array": ("more_lengths",),
    "typenum": (),
    "version_check": (),
}
SHA_PROJECT = "trnm-ci-original-sha2"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    need(path.is_absolute() and path.resolve(strict=True)==path and path.is_file(),
         "expected a direct regular file: "+str(path))
    return path.read_bytes()


def toolchain():
    expected=tomllib.loads(LOCK.parent.parent.joinpath("rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rust=subprocess.check_output(["rustc","-vV"],cwd=ROOT,text=True,timeout=10)
    cargo=subprocess.check_output(["cargo","-V"],cwd=ROOT,text=True,timeout=10)
    need(rust.split()[:2]==["rustc",expected] and cargo.split()[:2]==["cargo",expected]
         and "\nhost: x86_64-unknown-linux-gnu\n" in rust,
         "expected the pinned General Linux x86-64 toolchain")
    return rust


def lock_entry(rows,name,version):
    [entry]=[p for p in rows if (p["name"],p["version"])==(name,version)]
    need(entry.get("source")==REGISTRY and re.fullmatch(r"[a-f0-9]{64}",entry.get("checksum","")),
         "expected original public lock identity: "+name)
    return entry


def locked_projection(rows):
    projection={}
    for name,(version,edges) in SHA_LOCK.items():
        entry=lock_entry(rows,name,version)
        raw=entry.get("dependencies",[])
        keep=set(edges)
        extras={"sha2-asm"} if name=="sha2" else set()
        need({e.split()[0] for e in raw}==keep|extras,"changed original ordinary lock edges: "+name)
        for e in raw:
            part=e.split()
            if part[0] in keep and len(part)>1:
                need(part[1]==SHA_LOCK[part[0]][0],"changed exact child lock version: "+e)
        projection[name]={k:entry[k] for k in ("name","version","source","checksum")}
        projection[name]["dependencies"]=list(edges)
    members=[p for p in rows if p["name"]=="trnm-data-availability"]
    need(len(members)==1 and "sha2 0.10.9" in members[0].get("dependencies",[]),
         "the original M09 crate does not use exact SHA2")
    projection[SHA_PROJECT]={"name":SHA_PROJECT,"version":"0.0.0","dependencies":["sha2"]}
    lines=["version = 4",""]
    for name in sorted(projection):
        p=projection[name]
        lines+=["[[package]]",*(k+" = "+json.dumps(p[k]) for k in
                                 ("name","version","source","checksum") if k in p)]
        if p["dependencies"]:
            lines+=["dependencies = [",*(f' "{e}",' for e in p["dependencies"]),"]"]
        lines+=[""]
    return "\n".join(lines).encode()


def cargo_artifacts(data):
    events=[json.loads(line) for line in data.splitlines() if line.strip()]
    terminal=[row for row in events if row.get("reason")=="build-finished"]
    need(len(terminal)==1 and terminal[0].get("success") is True and events[-1]==terminal[0],
         "one successful terminal Cargo build event required")
    return [row for row in events if row.get("reason")=="compiler-artifact"]


def exact_artifacts(data, target, roster, lock, rust):
    events=cargo_artifacts(data)
    target=target.absolute()
    need(target.resolve(strict=True)==target and target.is_dir(),"expected direct original Cargo target")
    outputs=json.loads(regular(target/".rustc_info.json"))["outputs"]
    need(any(x.get("stdout")==rust and x.get("success") is True for x in outputs.values()),
         "original target did not use the exact pinned rustc")
    deps=target/"debug/deps"
    observed={}
    paths={}
    for name,(version,features) in roster.items():
        library=name.replace("-","_")
        lock_row=lock_entry(lock,name,version)
        package=f"{REGISTRY}#{name}@{version}"
        entries=[x for x in events if x.get("package_id")==package and x.get("target",{}).get("name")==library]
        need(len(entries)==1,"expected one exact successful Cargo artifact for "+name)
        [entry]=entries
        need(tuple(sorted(entry["features"]))==features and entry["target"]["kind"]==["lib"],
             "changed reference feature/target profile: "+name)
        [artifact]=[Path(p) for p in entry["filenames"] if p.endswith(".rlib")]
        want=rf"lib{library}-[0-9a-f]{{16}}\.rlib"
        need(artifact.parent==deps and re.fullmatch(want,artifact.name),"wrong original Cargo output path: "+name)
        need(list(deps.glob(f"lib{library}-*.rlib")).count(artifact)==1,"missing exact original artifact: "+name)
        if name in M06:
            need(list(deps.glob(f"lib{library}-*.rlib"))==[artifact],"ambiguous prebuilt M06 artifact: "+name)
        stem=artifact.stem[3:]
        suffix=stem.rsplit("-",1)[-1]
        dep=deps/(stem+".d")
        fp=target/f"debug/.fingerprint/{name}-{suffix}/lib-{library}.json"
        src=Path(entry["target"]["src_path"])
        need(src.is_absolute() and src.parents[1].name==f"{name}-{version}"
             and src.parent.name=="src" and src.name=="lib.rs" and src.parents[3].name=="src"
             and src.parents[4].name=="registry","wrong original registry source path: "+name)
        archive=src.parents[4]/"cache"/src.parents[2].name/f"{name}-{version}.crate"
        info=regular(dep); fingerprint=regular(fp)
        fp_value=json.loads(fingerprint)
        need(str(src) in info.decode().splitlines()[0] and not fp_value["rustflags"]
             and fp_value["compile_kind"]==0 and tuple(sorted(json.loads(fp_value["features"])))==features,
             "wrong original source, target, flags or Cargo fingerprint: "+name)
        need(digest(regular(archive))==lock_row["checksum"],"original locked crate archive changed: "+name)
        observed[name]={"package_id":package,"features":list(features),"registry_checksum":lock_row["checksum"],
                        "artifact_sha256":digest(regular(artifact)),"dep_info_sha256":digest(info),
                        "fingerprint_sha256":digest(fingerprint),"registry_lib_sha256":digest(regular(src)),
                        "rlib":str(artifact)}
        paths[name]=artifact
    return paths,observed


def m06_fingerprints(paths):
    """Link the exact selected prebuilt artifacts through Cargo's markers."""
    need(set(paths)==set(M06_LINKS),"wrong compiled M06 fingerprint roster")
    target=paths["serde_json"].parent.parent/".fingerprint"
    dirs={name:target/path.stem[3:] for name,path in paths.items()}
    observed={}
    for name,directory in dirs.items():
        content=json.loads(regular(directory/f"lib-{name}.json"))
        deps=content["deps"]
        need(len(deps)==len(M06_LINKS[name]) and {d[1] for d in deps}==M06_LINKS[name],
             "M06 link graph differs: "+name)
        fixed=[]
        for _,edge,host,code in deps:
            need(host is False and type(code) is int and 0<=code<2**64,"changed M06 host edge")
            expected=code.to_bytes(8,"little").hex().encode()
            if edge=="build_script_build":
                [marker]=[m for m in target.glob(name+"-*/run-build-script-build-script-build")
                          if regular(m).strip()==expected]
                fixed.append({"edge":edge,"marker_sha256":digest(regular(marker)),
                              "fingerprint_sha256":digest(regular(marker.with_suffix(".json")))})
            else:
                marker=dirs[edge]/f"lib-{edge}"
                need(regular(marker).strip()==expected,"M06 linking names a different artifact: "+edge)
                fixed.append({"edge":edge,"marker_sha256":digest(regular(marker))})
        observed[name]=fixed
    return observed


def prepare_sha2(output,lock,rust):
    from hia.tests.cell_manifest_original import dependency_graph

    directory=output/"m09-ordinary-sha2"
    directory.mkdir(mode=0o700)
    manifest=(f'[package]\nname = "{SHA_PROJECT}"\nversion = "0.0.0"\nedition = "2024"\n'
              'publish = false\n\n[dependencies]\nsha2 = "=0.10.9"\n')
    (directory/"Cargo.toml").write_text(manifest)
    exact=locked_projection(lock)
    (directory/"Cargo.lock").write_bytes(exact)
    (directory/"src").mkdir()
    (directory/"src/lib.rs").write_text("pub use sha2 as original_sha2;\n")
    target=directory/"target"
    raw=output/"m09-cargo.stdout.jsonl"
    err=output/"m09-cargo.stderr"
    env={**os.environ,"CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0","CARGO_BUILD_JOBS":"1"}
    with raw.open("xb") as stdout,err.open("xb") as stderr:
        subprocess.run(["cargo","build","--offline","--locked","--manifest-path",str(directory/"Cargo.toml"),
                        "--target-dir",str(target),"--message-format=json"],cwd=ROOT,env=env,timeout=120,
                       check=True,stdout=stdout,stderr=stderr)
    need(regular(directory/"Cargo.lock")==exact,"ordinary SHA2 Cargo lock was rewritten")
    roster={name:(SHA_LOCK[name][0],features) for name,features in SHA_BUILD.items()}
    paths,observed=exact_artifacts(regular(raw),target,roster,lock,rust)
    SHA=paths["sha2"]
    actual,graph,_=dependency_graph(SHA)
    expected={k for k in SHA_BUILD if k!="version_check"}
    need(actual==rust and {v["package"] for v in graph.values()}==expected,
         "ordinary SHA2 linked dependency graph differs")
    return SHA,{"actual_artifacts":observed,"actual_link_graph":graph,
                "projected_lock_sha256":digest(exact),"cargo_events_sha256":digest(regular(raw))}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for path in ("general-cargo-events","general-target","output","github-env"):
        parser.add_argument("--"+path,type=Path,required=True)
    args=parser.parse_args()
    output=args.output.absolute()
    out_env=args.github_env.absolute()
    need(output.parent.resolve(strict=True)==output.parent,"expected direct proof parent directory")
    output.mkdir(mode=0o700)
    lock_bytes=regular(LOCK)
    rows=tomllib.loads(lock_bytes.decode())["package"]
    rust=toolchain()
    need(os.environ.get("HIA_M06_LOCKED_CARGO_ORACLE")!="1", "conflicting M06 oracle mode")
    events=regular(args.general_cargo_events.absolute())
    paths,m06=exact_artifacts(events,args.general_target,M06,rows,rust)
    m06_links=m06_fingerprints(paths)
    sha2,m09=prepare_sha2(output,rows,rust)
    need(regular(LOCK)==lock_bytes,"original workspace lock changed")
    need(not any(line.startswith((b"HIA_M06_ORACLE_PREBUILT=",b"HIA_M09_SHA2_RLIB="))
                 for line in regular(out_env).splitlines()),"original oracle environment is already assigned")
    updates=f"HIA_M06_ORACLE_PREBUILT={args.general_target.absolute()}\nHIA_M09_SHA2_RLIB={sha2}\n"
    need("\r" not in updates and updates.count("\n")==2,"unsafe environment path")
    proof={"schema":"trnm.ci.original-m06-m09-oracles.v1","status":"PASS","rustc":rust,
           "prep_source_sha256":digest(regular(Path(__file__).resolve())),
           "workspace_lock_sha256":digest(lock_bytes),"general_cargo_events_sha256":digest(events),
           "m06_actual_artifacts":m06,"m06_link_graph":m06_links,"m09":m09}
    receipt=output/"report.json"
    receipt.write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    with out_env.open("a",encoding="utf-8") as out:
        out.write(updates)
    print(json.dumps({"status":"PASS","report_sha256":digest(regular(receipt))},sort_keys=True))


if __name__=="__main__":
    main()
