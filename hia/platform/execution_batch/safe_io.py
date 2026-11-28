"""Descriptor-bound regular-file evidence reads. No special fixture is opened."""
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path
def need(c,m):
    if not c:raise ValueError(m)
def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def unique(pairs):
    result={}
    for name,value in pairs:
        need(name not in result,'Duplicate JSON key: '+name);result[name]=value
    return result
def json_load(raw):return json.loads(raw,object_pairs_hook=unique)
def same(a,b):return json.dumps(a,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(b,sort_keys=True,separators=(',',':'),allow_nan=False)
def _parts(name):
    need(isinstance(name,str) and name and not name.startswith('/') and '\\' not in name and '\0' not in name,'Relative evidence path required')
    parts=name.split('/');need(all(part not in ('','.','..') for part in parts),'Evidence path traversal')
    return parts
def _directory(root):
    # Anchor every ancestor to its already-held parent descriptor. O_NOFOLLOW
    # on only the final absolute path would leave an earlier check/open window.
    root=Path(root).absolute()
    need(root.parts and root.parts[0]=='/' and all(part not in ('.','..') for part in root.parts[1:]),'Canonical absolute evidence root required')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
    fd=os.open('/',flags)
    try:
        need(stat.S_ISDIR(os.fstat(fd).st_mode),'Evidence anchor is not a directory')
        for part in root.parts[1:]:
            next_fd=os.open(part,flags,dir_fd=fd)
            try:need(stat.S_ISDIR(os.fstat(next_fd).st_mode),'Evidence ancestor is not a directory')
            except BaseException:
                os.close(next_fd)
                raise
            previous=fd;fd=next_fd;os.close(previous)
        return fd
    except BaseException:
        os.close(fd)
        raise
def _stamp(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_uid,st.st_gid)
def read(root,name,maximum=None):
    parts=_parts(name);fd=_directory(root);opened=[fd]
    try:
        for part in parts[:-1]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd);opened.append(fd)
            need(stat.S_ISDIR(os.fstat(fd).st_mode),'Nondirectory evidence ancestor')
        need(hasattr(os,'O_PATH'),'Linux descriptor metadata admission is required')
        path_fd=os.open(parts[-1],os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);opened.append(path_fd)
        admitted=os.fstat(path_fd)
        need(stat.S_ISREG(admitted.st_mode) and admitted.st_nlink==1,'Regular, single-link evidence required')
        file_fd=os.open('/proc/self/fd/'+str(path_fd),os.O_RDONLY|os.O_CLOEXEC|os.O_NONBLOCK);opened.append(file_fd)
        before=os.fstat(file_fd)
        need(_stamp(before)==_stamp(admitted),'Evidence metadata changed before regular-file read')
        need(maximum is None or type(maximum) is int and maximum>=0 and before.st_size<=maximum,'Evidence extent exceeds bound')
        remaining=before.st_size;chunks=[]
        while remaining:
            chunk=os.read(file_fd,min(remaining,1024*1024));need(chunk,'Truncated evidence file')
            chunks.append(chunk);remaining-=len(chunk)
        need(os.read(file_fd,1)==b'' and _stamp(os.fstat(file_fd))==_stamp(before),'Evidence changed during descriptor read')
        return b''.join(chunks)
    finally:
        for item in reversed(opened):os.close(item)
def load(root,name,maximum=None):return json_load(read(root,name,maximum))
def roster(root):
    fd=_directory(root);files=set()
    def visit(directory,prefix):
        before=os.fstat(directory)
        with os.scandir(directory) as entries:
            names=sorted(e.name for e in entries)
        for name in names:
            _parts(name);child=os.stat(name,dir_fd=directory,follow_symlinks=False);relative=prefix+name
            if stat.S_ISDIR(child.st_mode):
                sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
                try:
                    need(os.fstat(sub).st_dev==child.st_dev and os.fstat(sub).st_ino==child.st_ino,'Directory substitution')
                    visit(sub,relative+'/')
                finally:os.close(sub)
            else:
                need(stat.S_ISREG(child.st_mode) and child.st_nlink==1,'Special or linked evidence object')
                files.add(relative)
        after=os.fstat(directory)
        need((before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns),'Evidence directory changed')
    try:visit(fd,'')
    finally:os.close(fd)
    return files
def write_json(path,value):
    with Path(path).open('x') as out:json.dump(value,out,sort_keys=True,indent=2,allow_nan=False);out.write('\n')
