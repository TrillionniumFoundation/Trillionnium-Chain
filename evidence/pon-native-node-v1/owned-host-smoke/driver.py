"""Same-binary owned-host native conformance, not independent/public acceptance."""
from pathlib import Path
import hashlib,json,subprocess,sys,shlex,time,re
R=Path(sys.argv[1]).resolve();B=Path(sys.argv[2]).resolve();O=Path(sys.argv[3]).resolve()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=R,text=True).strip()
assert not git('status','--porcelain')
O.mkdir(exist_ok=False);(O/'driver.py').write_bytes(Path(__file__).read_bytes())
head=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}');binary=sha(B)
V=R/'formal/pon-nakamoto-v1/vectors/accepted-block'
header=(V/'header.bin').read_bytes();tx=(V/'transaction.bin').read_bytes();proof=(V/'work.bin').read_bytes()
packet=O/'accepted.packet';packet.write_bytes(header+b'\x01\x00'+len(tx).to_bytes(2,'little')+tx+proof)
expected=json.loads((V/'expected.json').read_text());(O/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
rows=[];hosts=[]
report={'schema':'pon-owned-native-smoke-v1','source_commit':head,'source_tree':tree,'source_clean':True,
'binary_sha256':binary,'packet_sha256':sha(packet),'hosts':hosts,'commands':rows,'all_passed':False,
'clock_scope':'explicit-logical-test','same_operator':True,'independent_accepted':False,
'public_network_ready':False,'physical_power_loss':False,'production_activation':False,'installed_services':False}
def run(args,timeout=90):
 start=time.monotonic_ns();p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 rows.append({'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'elapsed_ns':time.monotonic_ns()-start})
 if p.returncode:raise RuntimeError('command failed '+repr(args)+' '+p.stderr)
 return p.stdout
try:
 for host in ['rog','pocket4','x230-ts']:
  base=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',host]
  directory=run(base+['mktemp -d /tmp/trnm-owned-native-b34561d1a-XXXXXX']).strip()
  assert re.fullmatch('/tmp/trnm-owned-native-b34561d1a-[A-Za-z0-9]{6}',directory)
  record={'host_alias':host,'directory':directory,'environment':run(base+['hostname; uname -m; getconf GNU_LIBC_VERSION; date -u +%FT%TZ']),'admissions':0,'reopens':0,'all_passed':False};hosts.append(record)
  run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=8',str(B),host+':'+directory+'/trnm-pon-node'])
  run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=8',str(packet),host+':'+directory+'/accepted.packet'])
  checks=run(base+['sha256sum '+shlex.quote(directory+'/trnm-pon-node')+' '+shlex.quote(directory+'/accepted.packet')]).splitlines()
  assert [s.split()[0]for s in checks]==[binary,sha(packet)]
  common=['--development','--store',directory+'/store','--logical-now','1800010000']
  def call(command,*args):return json.loads(run(base+[shlex.join([directory+'/trnm-pon-node',command,*common,*args])]))
  first=call('submit','--packet',directory+'/accepted.packet');assert first['production_activation'] is False and first['clock_scope']=='logical-test'
  assert first['result']['block']==expected['block_id'] and first['result']['state']['state_root']==expected['post_state_root'];record['admissions']=1
  reopened=call('status');assert reopened['result']==first['result']['state'];record['reopens']=1
  duplicate=call('submit','--packet',directory+'/accepted.packet');assert duplicate==first;record['exact_duplicate_no_change']=True
  confirmation=call('confirm','--transaction',expected['tx_id'],'--block',expected['block_id'])['result']
  assert confirmation['confirmed'] is False and confirmation['reorged'] is False and confirmation['depth']==0
  assert confirmation['finalized'] is False and confirmation['execution_authority'] is False
  record.update(all_passed=True,observed_root=reopened['result']['state_root'],inclusion_checked=True,confirmed=False)
 assert not git('status','--porcelain') and git('rev-parse','HEAD')==head and sha(B)==binary
 report['all_passed']=True
finally:
 report['source_clean_after']=not git('status','--porcelain') and git('rev-parse','HEAD')==head
 (O/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 (O/'manifest.json').write_text(json.dumps({'source_commit':head,'source_tree':tree,'files':{str(p.relative_to(O)):sha(p)for p in sorted(O.iterdir())if p.is_file()}},indent=2)+'\n')
print(json.dumps({'source_commit':head,'all_passed':report['all_passed'],'hosts':hosts},indent=2))
