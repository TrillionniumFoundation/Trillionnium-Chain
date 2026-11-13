from pathlib import Path
import subprocess,json,hashlib,re,shutil,stat
root=Path('/home/qian-qi/work/chain-pon-outcome-7612-final')
src=Path('/home/qian-qi/work/chain-pon-outcome-7612-qualified-c1')
head='c2d67c5cf1ebb4caac525802362d5746b8fd957d'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==head
subprocess.run(['bash','scripts/project-preflight.sh'],cwd=root,check=True)
p=root/'docs/development/specs/pon/CELL_LOCAL_DECISION_COMPLETED_USE_V1.md'
body=p.read_text()
changes=[
('# Qualified local decisions and original acknowledged use','# Qualified local decisions and original completed use'),
('still cannot report acknowledged use. Neither profile changes a learning','still cannot report completed use. Neither profile changes a learning'),
('actual exported ACK state and exact final receipt match may the report set\n`acknowledged_use_observed=true` and','actual exported pending state and exact final receipt match may the report set\n`completed_use_observed=true`, `pending_work_and_delivery_clear=true` and'),
('the pinned materials. They do not authenticate their origin.','the pinned materials. They do not authenticate their origin. An empty pending\nqueue does not distinguish a task with no output from an explicit output ACK,\nso `output_ack_event_verified=false` remains explicit. The local actor fixtures\nuse empty output deltas; pending-output mutations test the refusal boundary,\nnot an observed ACK event.'),
('separately; an acknowledged advanced step is not relabelled a stopped model.','separately; a completed advanced step is not relabelled a stopped model.')]
for old,new in changes:
 assert body.count(old)==1,(p,old)
 body=body.replace(old,new)
p.write_text(body)
p=root/'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
body=p.read_text()
old='joins original HEPLCP04 Selection and completion cuts with the native ACKed\nuse export, without upgrading their authority. The'
new='joins original HEPLCP04 Selection and completion cuts with the native completed\nuse export, requiring no pending work or delivery without inferring an explicit\noutput ACK event or upgrading their authority. The'
assert body.count(old)==1
p.write_text(body.replace(old,new))
records=json.loads((src/'commands.json').read_text())
labels=['base-project-boundary','clone','canonical-origin','bundle-verify','bundle-import','checkout','project-boundary-before','source-before','toolchain','cargo-version','locked-metadata','format','source-integrity-negatives','project-boundary-negatives','repository-and-links','adoption-library','adoption-cli','outcome-role-separation','adoption-clippy','outcome-role-clippy','source-after']
assert [r['label'] for r in records['commands']]==labels
assert all(r['exit_code']==0 and r['timed_out'] is False for r in records['commands'])
before=json.loads((src/'source-before.json').read_text());after=json.loads((src/'source-after.json').read_text())
assert before==after and before['tested_commit']==head and before['candidate']==head and before['tracked_worktree_verified'] is True
counts={}
for name,n in [('adoption-library',25),('adoption-cli',13),('outcome-role-separation',1)]:
 raw=(src/(name+'.stdout')).read_text()
 found=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',raw)
 assert found==[(str(n),'0','0')],(name,found)
 counts[name]=n
for r in records['commands']:
 for k in ['stdout','stderr']:
  raw=(src/r[k]).read_bytes()
  assert hashlib.sha256(raw).hexdigest()==r[k+'_sha256']
  assert b'trnm SQLite I/O boundary UNQUALIFIED:' not in raw
out=root/'evidence/pon-learning-outcome-composition-20261111/native-c1'
out.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
for p in src.iterdir():
 assert stat.S_ISREG(p.lstat().st_mode)
 shutil.copyfile(p,out/p.name)
 assert (out/p.name).read_bytes()==p.read_bytes()
runner=Path('/home/qian-qi/chain-pon-outcome-7612-qualified-c1-run.py')
shutil.copyfile(runner,out/'runner.py')
witness=[]
for p in sorted(Path('/home/qian-qi/work/chain-pon-outcome-7612-qualified-target/debug/build').glob('trnm-sqlite-io-boundary-*/output')):
 raw=p.read_bytes()
 assert b'UNQUALIFIED' not in raw
 if b'cargo:rustc-cfg=trnm_sqlite_layout_witness' in raw and b'sqlite-3.54.0-normal-native-linux-layout-v4' in raw:
  name='sqlite-build-'+p.parent.name+'.stdout'
  (out/name).write_bytes(raw)
  witness.append({'path':str(p),'file':name,'sha256':sha(p)})
assert witness,'missing SQLite qualification witness'
binaries=[]
for label in counts:
 text=(src/(label+'.stderr')).read_text()
 paths=re.findall(r'Running [^\n]* \(([^)\n]+)\)',text)
 assert len(paths)==1,(label,paths)
 p=Path(paths[0]);assert p.is_file()
 binaries.append({'label':label,'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p),'observed_after_tests_only':True})
summary={'schema':'pon-learning-outcome-native-c1-readback-v1','source_head':head,'source_tree':before['tested_tree'],'result':'PASS','command_count':len(labels),'test_counts':counts,'unique_native_tests':sum(counts.values()),'source_before_equals_after':True,'tracked_worktree_verified':True,'sqlite_witnesses':witness,'binaries':binaries,'strict_clippy_scope':'DA library, adoption CLI and CLI integration; Node role integration','full_workspace_clippy_claimed':False,'actual_optimizer_executed_here':False,'independent_model_gain_certified':False,'production_activation':False}
(out/'qualification-readback.json').write_text(json.dumps(summary,indent=2)+'\n')
members=[{'file':p.name,'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(out.iterdir())]
(out/'ARCHIVE_MANIFEST.json').write_text(json.dumps({'schema':'pon-native-raw-observations-v1','source_head':head,'files':members,'original_bytes_preserved':True},indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
subprocess.run(['sha256sum','-c','SHA256SUMS'],cwd=out,check=True,stdout=subprocess.DEVNULL)
subprocess.run(['git','diff','--check'],cwd=root,check=True)
print('NATIVE_C1_ARCHIVE_READY',json.dumps(summary),flush=True)
