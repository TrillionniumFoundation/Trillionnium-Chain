"""Descriptor-relative, strict evidence/source reads. No runtime authority is imported."""
from pathlib import Path
import os,stat,json,hashlib,re
def need(value,message):
    if not value:raise ValueError(message)
def same(a,b):
    if type(a) is not type(b):return False
    if isinstance(a,dict):return set(a)==set(b) and all(same(a[k],b[k]) for k in a)
    if isinstance(a,list):return len(a)==len(b) and all(same(x,y) for x,y in zip(a,b))
    return a==b
def identity(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def unique(pairs):
    value={}
    for key,item in pairs:
        need(key not in value,"Duplicate JSON field");value[key]=item
    return value
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(ValueError("Nonfinite JSON number")))
def relative(name):
    need(type(name) is str and name and "\\" not in name and "\0" not in name,"Invalid relative file")
    p=Path(name);need(not p.is_absolute() and p.as_posix()==name and all(x not in (".","..","") for x in p.parts),"Escaping/noncanonical path")
    return p
def _directory(path):
    path=Path(path).absolute();need(path.as_posix()==str(path) and ".." not in path.parts,"Noncanonical root")
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
        return fd
    except BaseException:os.close(fd);raise
def read(root,name,limit=1<<30):
    parts=relative(name).parts;fd=_directory(root);opened=None
    try:
        for part in parts[:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
        opened=os.open(parts[-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        before=os.fstat(opened);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,"Nonregular/multiple-link/oversized input")
        data=bytearray()
        while len(data)<=limit:
            chunk=os.read(opened,min(1<<20,limit+1-len(data)))
            if not chunk:break
            data.extend(chunk)
        after=os.fstat(opened)
        fields=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        need(fields(before)==fields(after) and len(data)==before.st_size,"Input changed or grew")
        return bytes(data)
    finally:
        if opened is not None:os.close(opened)
        os.close(fd)
def read_json(root,name):return parse(read(root,name))
def file_identity(path):
    path=Path(path).absolute();return identity(read(path.parent,path.name))
def write_json(path,value):Path(path).write_bytes(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False).encode()+b"\n")
def new_output(path,repository):
    p=Path(path).absolute();root=Path(repository).absolute()
    need(p!=root and root not in p.parents and p not in root.parents,"Output overlaps source")
    need(not p.exists() and not p.is_symlink(),"Fresh output required")
    fd=_directory(p.parent);os.close(fd);p.mkdir(mode=0o700);return p
