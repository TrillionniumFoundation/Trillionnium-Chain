from pathlib import Path
import gzip, hashlib, json, shutil, zipfile

BASE = Path(__file__).resolve().parent
INPUT = BASE / 'resume-ci-artifacts'
OUT = BASE / 'chain-pq/evidence/pq-cell-retained-key-20261110'
OUT.mkdir(parents=True, exist_ok=False)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')
def retain(path, raw, compress=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if compress:
        path.write_bytes(gzip.compress(raw, mtime=0))
        return {'path':str(path.relative_to(OUT)), 'original_bytes':len(raw),
                'original_sha256':sha(raw), 'gzip_bytes':path.stat().st_size,
                'gzip_sha256':sha(path.read_bytes())}
    path.write_bytes(raw)
    return {'path':str(path.relative_to(OUT)), 'bytes':len(raw), 'sha256':sha(raw)}

archives=[]
retained=[]
for archive in sorted(INPUT.glob('*.zip')):
    raw=archive.read_bytes()
    with zipfile.ZipFile(archive) as z:
        members=[]
        for info in z.infolist():
            if info.is_dir(): continue
            data=z.read(info.filename)
            members.append({'name':info.filename,'bytes':len(data),'sha256':sha(data)})
            if archive.name == '13735114981.zip':
                selected=info.filename in ('workspace-tests.log','pq-provider/provider.json','pq-provider/build-and-smoke.log')
            else:
                selected=True
            if selected:
                relative=Path(archive.stem)/info.filename
                compressed=relative.suffix=='.log'
                target=OUT/'hosted'/relative
                if compressed:target=target.with_name(target.name+'.gz')
                retained.append(retain(target,data,compressed))
        archives.append({'download_name':archive.name,'bytes':len(raw),'sha256':sha(raw),
                         'members':members,'full_zip_republished':False})

retained.append(retain(OUT/'hosted/quality-head-job.log.gz',
                       (INPUT/'quality-head-job.log').read_bytes(),True))
for name in ('baseline-artifact-index.json','hosted-overview.json'):
    if (INPUT/name).exists():retained.append(retain(OUT/'hosted'/name,(INPUT/name).read_bytes()))
for file in sorted((BASE/'lifetime-rebind-validation').iterdir()):
    if file.is_file():
        target=OUT/'staged-lifetime-review'/file.name
        retained.append(retain(target,file.read_bytes()))

write_json(OUT/'archive-index.json',{'archives':archives,'selected_retained_members':retained,
    'scope':'Exact downloaded source-81f89 head/merge artifacts; ZIPs checked by the reader against GitHub artifact digests. Selected complete members are retained, including complete source refusal and doctest-reader failure logs. Archive member hashes do not constitute independent execution authentication.'})
shutil.copy2(Path(__file__),OUT/'assemble_hosted_evidence.py')
print(json.dumps({'output':str(OUT),'retained_files':len(list(OUT.rglob('*'))),
                  'source':'81f89b01b1fe0bb23cb8b885a30bb8fcb11a8455'}))
