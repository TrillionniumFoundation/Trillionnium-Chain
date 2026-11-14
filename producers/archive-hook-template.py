#!/opt/homebrew/bin/python3
"""Owned one-tag pre-push guard. Prepared template; no installed hook is replaced."""
import concurrent.futures, datetime, hashlib, json, math, os, pathlib, re, stat, subprocess, sys
ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
URL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"
HEAD = "2a86462a1ab20c68151719ba4635e3c294391e64"
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
CANDIDATE = "fix/chain-hepta-closure-candidate-20261109-481716"
TAG = "refs/tags/archive/post-publication-diagnostics-20261114-2a86462a1ab2-v1"
ZERO = "0" * 40
EXPECTED_SHA = "__EXPECTED_SHA256__"
EXPECTED_BYTES = 0  # __EXPECTED_BYTES__
HERE = pathlib.Path(__file__).parent

def need(ok, why):
    if not ok:
        raise ValueError(why)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def unique(items):
    out = {}
    for k,v in items:
        need(k not in out, "duplicate JSON key")
        out[k] = v
    return out

def parse(raw):
    def no_constant(value):
        raise ValueError("nonfinite JSON")
    def finite(value):
        n = float(value)
        need(math.isfinite(n), "nonfinite JSON")
        return n
    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant, parse_float=finite)

def fp(s):
    return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns

def fixed(p, limit):
    need(p.resolve(strict=True) == p, "noncanonical hook input")
    s = p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= limit, "unsafe hook input")
    fd = os.open(p, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(fp(os.fstat(fd)) == fp(s), "hook input replaced")
        chunks = []; count = 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            count += len(b); need(count <= limit, "hook input cap"); chunks.append(b)
        need(fp(os.fstat(fd)) == fp(s), "hook input changed")
    finally:
        os.close(fd)
    need(fp(p.lstat()) == fp(s) and count == s.st_size, "hook path changed")
    return b"".join(chunks)

def refs(raw, prefix=None, allowed=None):
    out = {}
    for line in raw.decode("ascii").splitlines():
        p = line.split()
        need(len(p) == 2 and re.fullmatch(r"[0-9a-f]{40}", p[0]) and p[1] not in out, "advertisement")
        need(prefix is None or p[1].startswith(prefix), "ref namespace")
        need(allowed is None or p[1] in allowed, "unexpected tag")
        out[p[1]] = p[0]
    return out

def capture(argv):
    try:
        return subprocess.run(argv, cwd=SOURCE, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(argv,124,e.stdout or b"",e.stderr or b"")
    except OSError as e:
        return subprocess.CompletedProcess(argv,127,b"",str(e).encode())

def main():
    need(not sys.flags.optimize, "optimized Python forbidden")
    need(HERE.parent.parent == ROOT and re.fullmatch(
        r"postpublication-diagnostics-publish-v1-[a-z0-9-]+", HERE.parent.name)
        and HERE.name == "hooks" and HERE.resolve(strict=True) == HERE, "owned hook directory")
    receipt = {"schema":"trnm-postpublication-one-tag-prepush-v1","status":"HOLD",
               "started_at":stamp(),"argv":list(sys.argv),"commands":[],"updates":None,"errors":[]}
    def save(first=False):
        p = HERE/("receipt.json" if first else "receipt.next")
        with p.open("xb") as f:
            f.write((json.dumps(receipt,indent=2,sort_keys=True)+"\n").encode()); f.flush(); os.fsync(f.fileno())
        if not first:
            os.replace(p,HERE/"receipt.json")
    save(True)
    def record(label,argv,q,must=True):
        need(len(q.stdout)+len(q.stderr) <= 2*1024*1024, "hook command output bound")
        row = {"label":label,"argv":argv,"exit":q.returncode,"timeout_seconds":90}
        for channel in ("stdout","stderr"):
            b = getattr(q,channel); p=HERE/(label+"."+channel)
            with p.open("xb") as f:
                f.write(b); f.flush(); os.fsync(f.fileno())
            row[channel+"_path"]=str(p); row[channel+"_bytes"]=len(b); row[channel+"_sha256"]=sha(b)
        receipt["commands"].append(row); save()
        if must:
            need(q.returncode == 0, "hook command failed: "+label)
        return q.stdout
    try:
        need(pathlib.Path.cwd().resolve(strict=True) == SOURCE, "hook cwd")
        raw = fixed(HERE/"expected.json",256*1024)
        need(type(EXPECTED_BYTES) is int and len(raw)==EXPECTED_BYTES and sha(raw)==EXPECTED_SHA,
             "fixed hook expectation")
        spec = parse(raw)
        need(type(spec) is dict and set(spec)=={"origin","remote_heads","old_archive_tags","new_tag_ref","updates"},
             "expectation fields")
        need(spec["origin"]==URL and spec["new_tag_ref"]==TAG, "fixed remote/tag")
        need(type(spec["remote_heads"]) is dict and len(spec["remote_heads"])==908
             and spec["remote_heads"].get("main")==BASE and spec["remote_heads"].get(CANDIDATE)==HEAD,
             "fixed heads")
        need(type(spec["old_archive_tags"]) is dict and len(spec["old_archive_tags"])==4
             and TAG not in spec["old_archive_tags"], "two previous annotated archives")
        need(type(spec["updates"]) is dict and set(spec["updates"])=={TAG}, "one ref scope")
        update=spec["updates"][TAG]
        need(type(update) is dict and set(update)=={"local_ref","new","old"}
             and update["local_ref"]==TAG and update["old"]==ZERO
             and type(update["new"]) is str and re.fullmatch(r"[0-9a-f]{40}",update["new"])
             and update["new"]!=ZERO, "one new annotated tag")
        need(len(sys.argv)==3 and sys.argv[1:]==["origin",URL], "hook actual remote argv")
        incoming=sys.stdin.buffer.read(65537)
        need(len(incoming)<=65536, "prepush input cap")
        lines=incoming.decode("ascii").splitlines()
        need(len(lines)==1, "exact complete EOF one-ref input")
        cells=lines[0].split()
        need(len(cells)==4, "prepush tuple")
        local,new,remote,old=cells
        seen={remote:{"local_ref":local,"new":new,"old":old}}
        receipt["updates"]=seen
        need(seen==spec["updates"], "actual remote-advertised old/new/local tuple differs")
        self_raw=fixed(pathlib.Path(__file__),64*1024)
        receipt["hook_sha256"]=sha(self_raw); receipt["expected_sha256"]=sha(raw)
        pu=["git","remote","get-url","--push","--all","origin"]
        fu=["git","remote","get-url","--all","origin"]
        need(record("push-url",pu,capture(pu)).decode().splitlines()==[URL], "unique push URL")
        need(record("fetch-url",fu,capture(fu)).decode().splitlines()==[URL], "unique fetch URL")
        ha=["git","ls-remote","--heads","origin"]
        ta=["git","ls-remote","origin",*sorted(spec["old_archive_tags"]),TAG,TAG+"^{}"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            h=pool.submit(capture,ha); t=pool.submit(capture,ta)
            hq=h.result(); tq=t.result()
        hr=record("heads",ha,hq,must=False); tr=record("tags",ta,tq,must=False)
        need(hq.returncode == 0 and tq.returncode == 0, "hook heads/tags command failed")
        need(refs(hr,prefix="refs/heads/")=={"refs/heads/"+n:o for n,o in spec["remote_heads"].items()},
             "complete remote heads changed")
        need(refs(tr,allowed=set(spec["old_archive_tags"])|{TAG,TAG+"^{}"})==spec["old_archive_tags"],
             "old archive moved or new tag appeared")
        need(fixed(HERE/"expected.json",256*1024)==raw
             and fixed(pathlib.Path(__file__),64*1024)==self_raw, "hook inputs changed")
        receipt["status"]="passed"
    except Exception as e:
        receipt["errors"].append({"type":type(e).__name__,"message":str(e)})
    finally:
        receipt["finished_at"]=stamp(); save()
    sys.stderr.write("archive-only-prepush-"+receipt["status"]+"\n"); sys.stderr.flush()
    return 0 if receipt["status"]=="passed" else 1

if __name__=="__main__":
    sys.exit(main())
