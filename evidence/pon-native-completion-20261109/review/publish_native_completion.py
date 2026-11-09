"""Publish qualified native code/evidence only through h main ProfHepta."""
import base64,datetime,gzip,hashlib,json,re,subprocess,sys,time
if sys.flags.optimize != 0: raise RuntimeError("Optimized Python is not permitted for this publisher")
from pathlib import Path,PurePosixPath
transfer=json.load(sys.stdin)
packed=b''.join(base64.b64decode(x) for x in transfer['chunks'])
assert hashlib.sha256(packed).hexdigest()==transfer['sha256']
payload=json.loads(gzip.decompress(packed))
assert payload['schema']=='native-completion-frozen-publication-v1'
repo=payload['repository'];assert repo=='TrillionniumFoundation/Trillionnium-Chain'
assert payload['base_head']=='e798d7125724d4b9f98c24d00cc80031f2eab4a9'
assert payload['base_tree']=='f77b6240b845425e0fc75e88abb09e6cfa3a71c0'
assert payload['base_branch']=='fix/chain-six-full-d9fb-20261108'
assert payload['branch']=='fix/chain-native-completion-20261108-70ae'
assert payload['code_source']=='ef025cbea963e3dee54ec4a17e3db7336c11409b'
q=payload['qualification']
for key in ['complete_source_verified','strict_clippy_passed','repository_gate_passed','push_preflight_passed']:assert q[key] is True,key
assert q['actual_distinct_native_passes']==89 and q['ignored_native_tests']==2
assert q['finite_model_tests']==255 and q['source_negative_tests']==43 and q['pq_source_negative_tests']==57
assert q['new_execution_claim_on_evidence_head'] is False and q['production_acceptance'] is False
assert q['ag_joint_acceptance']=='HOLD_NO_GO'
commits=payload['commits'];assert len(commits)==4
assert commits[0]['head']=='29ac3c8e86ebc59462da45d10fced1ca020e02c9'
assert commits[1]['head']=='843d7c3c0b58b5b0491f686df6a7fd3c26991d6c'
assert commits[2]['head']==payload['code_source'] and commits[-1]['head']==payload['delivery_head']
assert q['execution_source_commit']==payload['code_source'] and q['execution_source_tree']==commits[2]['tree']
parent=payload['base_head'];tree=payload['base_tree']
for ci,c in enumerate(commits):
 assert c['parent']==parent and c['base_tree']==tree
 raw=base64.b64decode(c['raw_commit_base64'])
 assert hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==c['head']
 headers,message=raw.split(b'\n\n',1);lines=headers.decode('utf-8').splitlines()
 assert len(lines)==4 and message.decode('utf-8')==c['message']
 assert lines[0]=='tree '+c['tree'] and lines[1]=='parent '+c['parent']
 for role,line in zip(['author','committer'],lines[2:]):
  m=re.fullmatch(role+r' (.+) <([^<>]+)> ([0-9]+) ([+-][0-9]{4})',line);assert m
  assert m[1]==c[role]['name'] and m[2]==c[role]['email'] and m[4]=='+0000'
  expected_date=datetime.datetime.fromtimestamp(int(m[3]),datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
  assert expected_date==c[role]['date']

 for role in ['author','committer']:
  assert c[role]['name']=='ProfHepta' and c[role]['email']=='102159240+ProfHepta@users.noreply.github.com' and c[role]['date'].endswith('Z')
 paths=[]
 for e in c['files']:
  p=PurePosixPath(e['path']);assert not p.is_absolute() and '..' not in p.parts and e['mode'] in ('100644','100755')
  raw=base64.b64decode(e['content_base64']);raw.decode('utf-8')
  assert len(raw)==e['bytes'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==e['blob']
  assert e['change'] in ('A','M');paths.append(e['path'])
 assert len(paths)==len(set(paths))
 if ci==3:assert all(p.startswith('evidence/pon-native-completion-20261109/') for p in paths)
 parent=c['head'];tree=c['tree']
root=Path('/Users/qianqi/work/chain-native-completion-70ae-20261109-publication');root.mkdir(mode=0o700,exist_ok=False)
(root/'frozen-publication.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
gh='/opt/homebrew/bin/gh'

def call(label, arguments, request=None):
    argv = [gh, *arguments]
    if request is not None:
        request_path = root / (label + '.request.json')
        request_path.write_text(json.dumps(request, ensure_ascii=False) + '\n')
        argv += ['--input', str(request_path)]
    started = time.monotonic_ns()
    with (root / (label + '.stdout')).open('wb') as out, (root / (label + '.stderr')).open('wb') as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err)
        try:
            code = process.wait(timeout=75)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            code = 124
    stdout = (root / (label + '.stdout')).read_bytes()
    stderr = (root / (label + '.stderr')).read_bytes()
    record = dict(argv=argv, exit_code=code, duration_ns=time.monotonic_ns() - started,
                  stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                  stderr_sha256=hashlib.sha256(stderr).hexdigest())
    (root / (label + '.command.json')).write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(label=label, exit_code=code)), flush=True)
    if code:
        # An uncertain write is reconciled by reading its exact expected object/ref.
        # This publisher never retries a write under a fresh operation identity.
        raise RuntimeError('gh failed or is uncertain: ' + label + ': ' + stderr.decode(errors='replace'))
    return stdout


def api(label, endpoint, request=None):
    args = ['api', endpoint]
    if request is not None:
        args += ['--method', 'POST']
    return json.loads(call(label, args, request))


user=json.loads(call('current-publisher',['api','user','--jq','{login,id}']))
assert user['login']=='ProfHepta' and user['id']==102159240
base=api('current-base','repos/'+repo+'/git/ref/heads/'+payload['base_branch']);assert base['object']['sha']==payload['base_head']
refs=api('existing-continuation-refs','repos/'+repo+'/git/matching-refs/heads/'+payload['branch'])
assert all(r['ref']!='refs/heads/'+payload['branch'] for r in refs)
for number,c in enumerate(commits,1):
 batches=[];batch=[];batch_bytes=0
 for e in sorted(c['files'],key=lambda e:e['path']):
  row=dict(path=e['path'],mode=e['mode'],type='blob',content=base64.b64decode(e['content_base64']).decode('utf-8'))
  size=len(json.dumps(row,ensure_ascii=False).encode('utf-8'))
  if batch and batch_bytes+size>1500000:batches.append(batch);batch=[];batch_bytes=0
  batch.append(row);batch_bytes+=size
 if batch:batches.append(batch)
 tree=c['base_tree']
 for index,entries in enumerate(batches,1):
  result=api(f'commit-{number}-tree-{index}','repos/'+repo+'/git/trees',dict(base_tree=tree,tree=entries));tree=result['sha']
 assert tree==c['tree'],(number,tree,c['tree'])
 result=api(f'commit-{number}-object','repos/'+repo+'/git/commits',dict(message=c['message'],tree=tree,parents=[c['parent']],author=c['author'],committer=c['committer']))
 assert result['sha']==c['head']
created=api('create-continuation-ref','repos/'+repo+'/git/refs',dict(ref='refs/heads/'+payload['branch'],sha=payload['delivery_head']))
assert created['object']['sha']==payload['delivery_head']
readback=api('readback-continuation-ref','repos/'+repo+'/git/ref/heads/'+payload['branch']);assert readback['object']['sha']==payload['delivery_head']
body=root/'pull-request-body.md';body.write_text(payload['pr_body'])
created_pr=call('create-draft-pull-request',['pr','create','--repo',repo,'--draft','--base',payload['base_branch'],'--head',payload['branch'],'--title',payload['pr_title'],'--body-file',str(body)]).decode().strip()
pr=json.loads(call('readback-draft-pull-request',['pr','view',payload['branch'],'--repo',repo,'--json','url,number,title,headRefOid,baseRefName,isDraft,state,statusCheckRollup']))
assert pr['isDraft'] is True and pr['headRefOid']==payload['delivery_head'] and pr['baseRefName']==payload['base_branch'] and pr['state']=='OPEN' and pr['url'] in created_pr
result=dict(repository=repo,code_source=payload['code_source'],delivery_head=payload['delivery_head'],delivery_tree=commits[-1]['tree'],publisher=user['login'],production_acceptance=False,pull_request=pr)
(root/'publication.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
