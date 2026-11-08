#!/usr/bin/env python3
"""Verify the exact archived public evidence; optionally extract to a new directory."""
import argparse, hashlib, io, json, pathlib, tarfile, tempfile
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--directory", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent)
    p.add_argument("--extract", type=pathlib.Path)
    a=p.parse_args(); base=a.directory.resolve()
    index=json.loads((base/"raw-index.json").read_bytes())
    manifest_bytes=(base/"raw-manifest.json").read_bytes()
    if sha(manifest_bytes)!=index["manifest_sha256"]: raise ValueError("manifest hash mismatch")
    manifest=json.loads(manifest_bytes)
    expected={x["archive_path"]:x for x in manifest["files"]}
    if len(expected)!=len(manifest["files"]): raise ValueError("duplicate manifest member")
    def safe(name):
        q=pathlib.PurePosixPath(name)
        if q.is_absolute() or any(x in ("..",".","") for x in q.parts) or str(q)!=name: raise ValueError("unsafe path")
        return q
    with tempfile.TemporaryFile() as archive:
        digest=hashlib.sha256(); total=0
        for row in index["parts"]:
            safe(row["path"]); data=(base/row["path"]).read_bytes()
            if len(data)!=row["size_bytes"] or sha(data)!=row["sha256"]: raise ValueError("part identity mismatch")
            archive.write(data); digest.update(data); total+=len(data)
        if total!=index["archive_size_bytes"] or digest.hexdigest()!=index["archive_sha256"]: raise ValueError("archive identity mismatch")
        archive.seek(0); seen=set(); count=0; byte_count=0
        with tarfile.open(fileobj=archive,mode="r:gz") as t:
            for member in t:
                safe(member.name)
                if not member.isfile() or member.name in seen: raise ValueError("nonregular or duplicate archive member")
                seen.add(member.name); f=t.extractfile(member)
                if f is None: raise ValueError("missing member bytes")
                data=f.read()
                if member.name=="MANIFEST.json":
                    if data!=manifest_bytes: raise ValueError("embedded manifest mismatch")
                    continue
                row=expected.get(member.name)
                if row is None or member.size!=row["size_bytes"] or len(data)!=row["size_bytes"] or sha(data)!=row["sha256"]: raise ValueError("member identity mismatch")
                count+=1; byte_count+=len(data)
        if seen!=set(expected)|{"MANIFEST.json"}: raise ValueError("incomplete member set")
        if count!=index["regular_file_count"] or byte_count!=index["uncompressed_file_bytes"]: raise ValueError("inventory totals mismatch")
        if a.extract:
            dest=a.extract.absolute()
            if dest.exists(): raise ValueError("extraction destination already exists")
            dest.mkdir(parents=True)
            archive.seek(0)
            with tarfile.open(fileobj=archive,mode="r:gz") as t:
                for member in t:
                    q=safe(member.name); output=dest.joinpath(*q.parts)
                    output.parent.mkdir(parents=True,exist_ok=True)
                    with output.open("xb") as out: out.write(t.extractfile(member).read())
        print(json.dumps({"status":"PASS","source_head":index["source_head"],"archive_sha256":index["archive_sha256"],"regular_files":count,"uncompressed_file_bytes":byte_count,"extracted_to":str(a.extract.absolute()) if a.extract else None},sort_keys=True))
if __name__=="__main__": main()
