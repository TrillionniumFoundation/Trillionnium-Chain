"""Bind the actual original std compiler, source, and host dynamic dependencies."""
from __future__ import annotations
import os
from pathlib import Path
import struct
import subprocess
from .build import HERE, read_json, identity, digest, need

FORBIDDEN=(
 "LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT",
 "RUSTC","RUSTDOC","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","RUSTFLAGS","RUSTDOCFLAGS",
 "CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","RUSTC_BOOTSTRAP","CARGO",
 "CARGO_BUILD_RUSTC","CARGO_BUILD_RUSTDOC","CARGO_BUILD_RUSTC_WRAPPER",
 "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTFLAGS","CARGO_BUILD_RUSTDOCFLAGS",
 "CARGO_BUILD_TARGET","CARGO_BUILD_BUILD_DIR","CARGO_BUILD_TARGET_DIR","CARGO_TARGET_DIR")
def forbidden_override(key):
 return key in FORBIDDEN or key.startswith("CARGO_PROFILE_") or (
  key.startswith("CARGO_TARGET_") and key.endswith(("_RUSTFLAGS","_RUSTDOCFLAGS","_LINKER","_RUNNER")))
def environment():
 for key,value in os.environ.items():
  need(not value or not forbidden_override(key),"Unbound original compilation/runtime override: "+key)
 value=dict(os.environ)
 value["PYTHONDONTWRITEBYTECODE"]="1";value.pop("PYTHONOPTIMIZE",None)
 value["RUSTUP_TOOLCHAIN"]=read_json(HERE/"abi.json")["standard_library"]["toolchain"]
 return value

def captured_std():
 env=environment();contract=read_json(HERE/"abi.json")["standard_library"]
 version=subprocess.run(["rustc","-Vv"],capture_output=True,env=env,timeout=15,check=True)
 need(not version.stderr and digest(version.stdout)==contract["rustc_version_sha256"],
      "Original compiler/std contract differs from the explicitly qualified Rust toolchain")
 printed=subprocess.run(["rustc","--print","sysroot"],capture_output=True,env=env,timeout=15,check=True)
 need(not printed.stderr,"Unexpected sysroot discovery diagnostic")
 sysroot=Path(printed.stdout.decode().strip()).resolve(strict=True)
 compiler=(sysroot/"bin/rustc").resolve(strict=True)
 exact=subprocess.run([str(compiler),"-Vv"],capture_output=True,env=env,timeout=15,check=True)
 need(not exact.stderr and exact.stdout==version.stdout,"Selected actual compiler differs from the pinned toolchain")
 cargo=(sysroot/"bin/cargo").resolve(strict=True)
 sources={}
 for relative,expected in contract["sources"].items():
  actual=identity(sysroot/"lib/rustlib/src/rust"/relative)
  need(actual==expected,"Original rust-src differs or is missing: "+relative)
  sources[relative]=actual
 library=sysroot/"lib/rustlib/x86_64-unknown-linux-gnu/lib"
 binaries={}
 for name,expected in contract["binaries"].items():
  path=library/name;actual=identity(path)
  need(actual==expected,"Actual original compiled std differs: "+name)
  binaries[name]={"path":str(path),**actual}
 dynamic={}
 for line in Path("/proc/self/maps").read_text().splitlines():
  pieces=line.split(maxsplit=5)
  if len(pieces)!=6 or not pieces[5].startswith("/"):continue
  path=Path(pieces[5]).resolve()
  if path.name=="libc.so.6" or path.name.startswith("ld-linux"):dynamic[str(path)]=identity(path)
 need(len([p for p in dynamic if Path(p).name=="libc.so.6"])==1
      and any(Path(p).name.startswith("ld-linux") for p in dynamic),"Actual glibc/loader identity unavailable")
 return {"schema":"trnm.hia.paid-cpu-original-std-dependency.v1","compiler":version.stdout.decode(),
  "sysroot":str(sysroot),"commit":contract["commit"],"sources":sources,"binaries":binaries,
  "compiler_executable":{"path":str(compiler),**identity(compiler)},
  "cargo_executable":{"path":str(cargo),**identity(cargo)},
  "actual_host_dynamic_libraries":dynamic,"normal_vdso_error_or_timing_behavior_claimed":False}


def bound_build_environment(dependency):
 value=environment()
 for name in ("compiler_executable","cargo_executable"):
  row=dependency[name]
  need(identity(Path(row["path"]))=={key:row[key] for key in ("bytes","sha256")},
       "Bound actual compiler/Cargo changed: "+name)
 value["RUSTC"]=dependency["compiler_executable"]["path"]
 value["CARGO"]=dependency["cargo_executable"]["path"]
 value["RUSTC_WRAPPER"]="";value["RUSTC_WORKSPACE_WRAPPER"]=""
 return value

def executable_interpreter(binary,dependency):
 with Path(binary).open("rb") as stream:
  header=stream.read(64);need(header[:7]==b"\x7fELF\x02\x01\x01","Original executable is not ELF64LE")
  values=struct.unpack("<16sHHIQQQIHHHHHH",header)
  need(values[2]==62 and values[8]==64 and values[9]==56,"Original ELF machine or table entry size differs")
  stream.seek(values[5]);table=stream.read(values[9]*values[10])
  rows=[struct.unpack_from("<IIQQQQQQ",table,i*56) for i in range(values[10])]
  interpreters=[row for row in rows if row[0]==3]
  need(len(interpreters)==1 and 1<interpreters[0][5]<=4096,"No unique bounded original ELF interpreter")
  row=interpreters[0];stream.seek(row[2]);raw=stream.read(row[5])
 need(raw.endswith(b"\0") and b"\0" not in raw[:-1],"Malformed original ELF interpreter")
 path=Path(raw[:-1].decode()).resolve(strict=True)
 need(str(path) in dependency["actual_host_dynamic_libraries"]
      and identity(path)==dependency["actual_host_dynamic_libraries"][str(path)],
      "Original ELF uses another dynamic loader than the bound host runtime")
 return {"path":str(path),**identity(path)}
