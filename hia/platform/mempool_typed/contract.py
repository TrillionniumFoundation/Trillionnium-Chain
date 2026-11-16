"""Fail-closed byte/source contracts. No admission decisions are executed here."""
from __future__ import annotations
import ast,hashlib,json,os,stat,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
OWNED="hia/platform/mempool_typed"
ORIGINAL="trillionnium/crates/trnm-mempool"
REQUIRED=frozenset({"README.md","abi.json","build.py","contract.py","cases.py","native_io.py",
    "runtime.py","physical.py","guarded.py","rust_oracle.py","rust_reference.rs",
    "qualify.py","test_integrity.py","typed_fixture.hepta","linux_emitter.hepta"})
SKIP_ORIGINAL=frozenset({"target",".git","__pycache__",".pytest_cache"})
COMPILER_SHA="87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
TOOLCHAIN_REVISION="f33d8da316de8fdf27b504371f1a5310997ff548"

def need(condition,message):
    if not condition:raise ValueError(message)

def identity(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def unique_keys(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,"Duplicate JSON key: "+key);result[key]=value
    return result

def load_json(raw):
    return json.loads(raw,object_pairs_hook=unique_keys)

def canonical_root(path):
    path=Path(path).absolute()
    need(path==path.resolve(strict=True),"Repository path is not canonical")
    need(path.is_dir(),"Repository is not a directory")
    return path

def canonical_path(root,relative,*,directory=False):
    root=canonical_root(root)
    need(isinstance(relative,str) and relative and "\x00" not in relative,"Invalid relative path")
    fragment=Path(relative)
    need(not fragment.is_absolute() and fragment.as_posix()==relative
        and all(p not in (".","..") for p in fragment.parts),"Noncanonical relative path")
    path=root/fragment
    for ancestor in (path,*path.parents):
        if ancestor==root.parent:break
        st=ancestor.lstat()
        need(not stat.S_ISLNK(st.st_mode),"Symbolic source path: "+relative)
        if ancestor!=path:need(stat.S_ISDIR(st.st_mode),"Nondirectory source ancestor")
    st=path.stat()
    if directory:need(stat.S_ISDIR(st.st_mode),"Nondirectory source")
    else:need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,"Nonregular or hard-linked source: "+relative)
    return path

def file_bytes(path):
    path=Path(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,"Nonregular byte source")
    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW
    fd=os.open(path,flags)
    try:
        opened=os.fstat(fd)
        need((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),"Source changed before open")
        pieces=[]
        while True:
            b=os.read(fd,1<<20)
            if not b:break
            pieces.append(b)
        raw=b"".join(pieces);after=os.fstat(fd)
    finally:os.close(fd)
    final=path.lstat()
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
    need(fields(before)==fields(opened)==fields(after)==fields(final),"Source changed during read")
    need(len(raw)==before.st_size,"Short source capture")
    return raw

def file_identity(path):
    path=Path(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,"Nonregular byte source")
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    digest=hashlib.sha256();size=0
    try:
        opened=os.fstat(fd)
        need((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),"Source changed before open")
        while True:
            block=os.read(fd,1<<20)
            if not block:break
            digest.update(block);size+=len(block)
        after=os.fstat(fd)
    finally:os.close(fd)
    final=path.lstat()
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
    need(fields(before)==fields(opened)==fields(after)==fields(final),"Source changed during hash")
    need(size==before.st_size,"Short source hash")
    return {"bytes":size,"sha256":digest.hexdigest()}

def source_manifest(repository=ROOT):
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    root=canonical_root(repository);directory=canonical_path(root,OWNED,directory=True)
    names={p.name for p in directory.iterdir()}
    need(names==REQUIRED,"Owner source set differs: missing="+repr(sorted(REQUIRED-names))+
         " extra="+repr(sorted(names-REQUIRED)))
    captured={}
    def capture(name):
        raw=file_bytes(canonical_path(root,name))
        need(name not in captured or captured[name]==raw,"Source changed during closure discovery")
        captured[name]=raw
        return raw
    for name in sorted(REQUIRED):capture(OWNED+"/"+name)
    platform=capture("hia/platform/build.py")
    tree=ast.parse(platform)
    definitions=[n for n in tree.body if isinstance(n,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=="INPUTS" for t in n.targets)]
    need(len(definitions)==1,"Ambiguous pinned INPUTS")
    pinned=ast.literal_eval(definitions[0].value)
    need(isinstance(pinned,tuple) and pinned and len(pinned)==len(set(pinned))
         and all(isinstance(n,str) for n in pinned),"Invalid pinned INPUTS")
    for name in pinned:capture("hia/"+name)
    for name,raw in captured.items():
        need(file_bytes(canonical_path(root,name))==raw,"Source changed during discovery: "+name)
    return {name:identity(raw) for name,raw in sorted(captured.items())}

def original_manifest(repository=ROOT):
    root=canonical_root(repository);directory=canonical_path(root,ORIGINAL,directory=True);result={}
    for current,children,files in os.walk(directory,followlinks=False):
        children[:]=sorted(n for n in children if n not in SKIP_ORIGINAL)
        for name in children:canonical_path(root,(Path(current)/name).relative_to(root).as_posix(),directory=True)
        for name in sorted(files):
            if name in SKIP_ORIGINAL:continue
            relative=(Path(current)/name).relative_to(root).as_posix()
            result[relative]=file_identity(canonical_path(root,relative))
    for name in ("trillionnium/Cargo.toml","trillionnium/Cargo.lock"):
        result[name]=file_identity(canonical_path(root,name))
    need({ORIGINAL+"/Cargo.toml",ORIGINAL+"/src/lib.rs",ORIGINAL+"/src/typed_admission.rs"}<=set(result),
        "Complete original mempool package is absent")
    return dict(sorted(result.items()))

def manifest_sha(manifest):
    return identity(json.dumps(manifest,sort_keys=True,separators=(",",":")).encode())["sha256"]

def write_json(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    path=Path(path)
    with path.open("xb") as stream:stream.write(raw)
    return identity(raw)

def fresh_output(path,repository=ROOT):
    root=canonical_root(repository);path=Path(path).absolute()
    parent=path.parent.resolve(strict=True)
    need(path==parent/path.name and path.name not in ("",".",".."),"Noncanonical output")
    need(path!=root and root not in path.parents,"Output must be outside the source repository")
    need(not path.exists() and not path.is_symlink(),"Output already exists")
    path.mkdir(mode=0o700)
    return path

def preflight(repository,output):
    result=subprocess.run(["bash","scripts/project-preflight.sh"],cwd=repository,
        capture_output=True,timeout=60)
    (output/"preflight.stdout").write_bytes(result.stdout)
    (output/"preflight.stderr").write_bytes(result.stderr)
    need(result.returncode==0,"Project preflight failed")
    return {"exit_code":result.returncode,"stdout":identity(result.stdout),"stderr":identity(result.stderr)}
