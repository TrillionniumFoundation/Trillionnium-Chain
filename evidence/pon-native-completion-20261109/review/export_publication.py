"""Export committed source/evidence through read-only Git queries for h main publication."""
import base64,datetime,gzip,hashlib,json,os,pathlib,re,subprocess,sys
if sys.flags.optimize: raise RuntimeError('Optimized Python is forbidden')
BASE=pathlib.Path('/data/chain-abg-70ae-20261108');ROOT=BASE/'source'
OUT=BASE/'inputs/frozen-publication';OUT.mkdir(exist_ok=False)
CODE='ef025cbea963e3dee54ec4a17e3db7336c11409b';TREE='8de2f7b477aa41b75e9818634fc3aaf04f12f4df'
FIRST='e798d7125724d4b9f98c24d00cc80031f2eab4a9'
ENV={**os.environ,'GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1','PYTHONDONTWRITEBYTECODE':'1'}
def rawgit(*args):return subprocess.check_output(['git',*args],cwd=ROOT,env=ENV)
def git(*args):return rawgit(*args).decode('utf-8').strip()
def read(rel):return json.loads((BASE/rel).read_text())
assert git('status','--porcelain')==''
head=git('rev-parse','HEAD');assert git('rev-parse','HEAD^')==CODE
assert git('rev-parse',CODE+'^{tree}')==TREE
chain=git('rev-list','--reverse',FIRST+'..'+head).splitlines()
assert chain==['29ac3c8e86ebc59462da45d10fced1ca020e02c9','843d7c3c0b58b5b0491f686df6a7fd3c26991d6c',CODE,head]
delivery=read('evidence/delivery-preparation/delivery.json')
assert delivery['code_source']==CODE and delivery['code_tree']==TREE
assert delivery['delivery_head']==head and delivery['delivery_tree']==git('rev-parse',head+'^{tree}')
assert delivery['push_preflight_passed'] is True
native=read('evidence/r3-native-and-clippy/summary.json')
static=read('evidence/r3-contract-gates/summary.json')
finite=read('evidence/r3-def-finite/summary.json')
assert native['source_head']==CODE and native['source_tree']==TREE
assert native['retained_all_pass'] and native['strict_clippy_pass'] and native['actual_distinct_native_passes']==89 and native['ignored_tests']==2
assert static['expected_head']==CODE and static['expected_tree']==TREE and static['all_recorded_gates_pass'] is True
assert len(static['gates'])==13 and all(g['passed'] and g['exit_code']==0 for g in static['gates'])
assert finite['expected_source_commit']==CODE and finite['expected_source_tree']==TREE and finite['all_finite_suites_pass'] is True and finite['actual_tests']==255
byname={g['label']:g for g in static['gates']}
for label,count in [('source-integrity-negative-43',43),('pq-research-negative-57',57)]:
 assert byname[label]['tests_run']==count and byname[label]['skipped']==0
components={}
for path in ['trillionnium','scripts','config','docs','.github']:
 before=git('rev-parse',CODE+':'+path);after=git('rev-parse',head+':'+path)
 assert before==after;components[path]={'code_tree':before,'delivery_tree':after}
commits=[]
for commit in chain:
 raw=rawgit('cat-file','commit',commit);headers,message=raw.split(b'\n\n',1);lines=headers.decode('utf-8').splitlines()
 assert len(lines)==4 and lines[0].startswith('tree ') and lines[1].startswith('parent ')
 item={'head':commit,'tree':lines[0][5:],'parent':lines[1][7:],'raw_commit_base64':base64.b64encode(raw).decode(),'message':message.decode('utf-8'),'files':[]}
 assert hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==commit
 item['base_tree']=git('rev-parse',item['parent']+'^{tree}')
 for role,line in zip(['author','committer'],lines[2:]):
  m=re.fullmatch(role+r' (.+) <([^<>]+)> ([0-9]+) ([+-][0-9]{4})',line);assert m and m[4]=='+0000'
  item[role]={'name':m[1],'email':m[2],'date':datetime.datetime.fromtimestamp(int(m[3]),datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
  assert m[1]=='ProfHepta' and m[2]=='102159240+ProfHepta@users.noreply.github.com'
 rows=git('diff-tree','--no-commit-id','--no-renames','--name-status','-r',item['parent'],commit).splitlines()
 for row in rows:
  change,path=row.split('\t',1);assert change in ('A','M')
  tree_row=git('ls-tree',commit,'--',path);attrs,actual_path=tree_row.split('\t',1);mode,kind,blob=attrs.split()
  assert actual_path==path and kind=='blob' and mode in ('100644','100755')
  content=rawgit('cat-file','blob',blob);content.decode('utf-8')
  assert hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()==blob
  item['files'].append({'path':path,'change':change,'mode':mode,'blob':blob,'bytes':len(content),'content_base64':base64.b64encode(content).decode()})
 if commit==head:assert all(e['path'].startswith('evidence/pon-native-completion-20261109/') for e in item['files'])
 commits.append(item)
q={'execution_source_commit':CODE,'execution_source_tree':TREE,'complete_source_verified':True,'actual_distinct_native_passes':89,'ignored_native_tests':2,'finite_model_tests':255,'source_negative_tests':43,'pq_source_negative_tests':57,'strict_clippy_passed':True,'repository_gate_passed':True,'push_preflight_passed':True,'new_execution_claim_on_evidence_head':False,'production_acceptance':False,'ag_joint_acceptance':'HOLD_NO_GO'}
body=(BASE/'inputs/b-pull-request-body.md').read_text().replace('@@CODE_HEAD@@',CODE).replace('@@CODE_TREE@@',TREE).replace('@@DELIVERY_HEAD@@',head).replace('@@DELIVERY_TREE@@',commits[-1]['tree'])
assert '@@' not in body
payload={'schema':'native-completion-frozen-publication-v1','repository':'TrillionniumFoundation/Trillionnium-Chain','base_head':FIRST,'base_tree':git('rev-parse',FIRST+'^{tree}'),'base_branch':'fix/chain-six-full-d9fb-20261108','branch':'fix/chain-native-completion-20261108-70ae','code_source':CODE,'delivery_head':head,'qualification':q,'commits':commits,'unchanged_component_trees':components,'pr_title':'fix(pon): require complete native admission before completion priority','pr_body':body}
plain=(json.dumps(payload,ensure_ascii=False,indent=2)+'\n').encode();packed=gzip.compress(plain,mtime=0)
(OUT/'publication.json').write_bytes(plain);(OUT/'publication.json.gz').write_bytes(packed)
summary={'code_source':CODE,'code_tree':TREE,'delivery_head':head,'delivery_tree':commits[-1]['tree'],'commits':[{'head':c['head'],'tree':c['tree'],'parent':c['parent'],'file_count':len(c['files'])} for c in commits],'gzip_bytes':len(packed),'gzip_sha256':hashlib.sha256(packed).hexdigest(),'plain_bytes':len(plain),'plain_sha256':hashlib.sha256(plain).hexdigest(),'unchanged_component_trees':components,'qualification':q}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');(OUT/'pull-request-body.md').write_text(body)
print(json.dumps(summary),flush=True)
