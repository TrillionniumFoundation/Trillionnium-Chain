"""Full-history, freshness, namespace and cleanup-order differential cases."""
from pathlib import Path
import os,hashlib,struct,shutil
from .fixtures import record

def disk(path):
 result={}
 for q in sorted(path.rglob('*')):
  st=q.lstat();result[str(q.relative_to(path))]={'mode':st.st_mode&0o7777,'links':st.st_nlink if q.is_file()else None,'target':os.readlink(q)if q.is_symlink()else None,'bytes':q.read_bytes().hex()if q.is_file()and not q.is_symlink()else None}
 return result
def state(p):
 a,b=disk(p.na),disk(p.nb);assert a==b,(p.name,a,b)
def write_private(path,data):path.write_bytes(data);path.chmod(0o600)
def anchor_digest(cp):return hashlib.sha256(b'trnm.node-commit-ledger.anchor.v1\0'+cp).digest()
def ledger_record(seq,prev,source,target):
 body=struct.pack('<Q',seq)+prev+source+target;return b'TRNMNCLR\1\0'+bytes(6)+body+hashlib.sha256(b'trnm.node-commit-ledger.record.v1\0'+body).digest()
def ledger_head(seq,digest):return b'TRNMNCLH\1\0'+bytes(6)+struct.pack('<Q',seq)+digest
def mutate_cp(cp,offset,byte):
 from .fixtures import digest
 b=bytearray(cp);b[offset]=byte;return bytes(b[:640])+digest(bytes(b[:640]))
def expect(value,status,text):assert value[0][0]==status and (text is None or text in value[1].decode()),value
def run(suite):
 root=suite.root; rows=suite.rows; Pair=lambda root,name:suite.pair(name)
 cp0=record();cp1=record(1,predecessor=cp0[640:]);cp2=record(2,predecessor=cp1[640:]);cp3=record(3,predecessor=cp2[640:])
 # Independent pins protect complete history; constructor failures release locks.
 p=Pair(root,'authority-pins');p.path(11,'journal');pin0=p.call(14)[1];p.call(17,struct.pack('<Q',0)+bytes(672)+cp0);pin1=p.call(14)[1]
 old=[(q/'journal').read_bytes()for q in (p.na,p.nb)];oldhead=[(q/'.journal.head-v2').read_bytes()for q in (p.na,p.nb)]
 p.call(17,struct.pack('<Q',1)+cp0+cp1);pin2=p.call(14)[1];p.call(19)
 expect(p.path(12,'journal',pin1),1,'external journal checkpoint mismatch');state(p)
 for q,log,head in zip((p.na,p.nb),old,oldhead): (q/'journal').write_bytes(log);(q/'.journal.head-v2').write_bytes(head)
 expect(p.path(12,'journal',pin2),1,'external journal checkpoint mismatch');p.path(12,'journal',pin1);p.call(16,cp0[16:48]);p.call(19)
 for q in (p.na,p.nb):(q/'.journal.head-v2').unlink()
 expect(p.path(12,'journal',pin1),1,'inspect existing checkpoint head');state(p);p.close()
 # Partial-tail detection precedes even a corrupt first record. Pinned length
 # mismatch precedes structural decoding, and neither path repairs a head.
 p=Pair(root,'authority-partial');p.path(11,'journal');empty=p.call(14)[1];p.call(17,struct.pack('<Q',0)+bytes(672)+cp0);pin=p.call(14)[1];p.call(19)
 for q in (p.na,p.nb):data=bytearray((q/'journal').read_bytes());data[0]^=1;(q/'journal').write_bytes(data+b'x')
 expect(p.path(10,'journal'),1,'trailing partial checkpoint record');expect(p.path(12,'journal',pin),1,'external journal checkpoint mismatch');state(p)
 for q in (p.na,p.nb):(q/'journal').write_bytes((q/'journal').read_bytes()[:-1])
 expect(p.path(12,'journal',pin),1,'record header');state(p);p.close()
 # Live owner observes exact retained namespace, including same-inode rollback.
 for which in ('log','lock','head','directory','hardlink','truncate'):
  p=Pair(root,'authority-live-'+which);p.path(11,'journal');p.call(17,struct.pack('<Q',0)+bytes(672)+cp0)
  for q in (p.na,p.nb):
   path=q/({'log':'journal','lock':'.journal.lock-v2','head':'.journal.head-v2','hardlink':'journal','truncate':'journal'}.get(which,'journal'))
   if which=='directory':
    old=q.with_name(q.name+'-displaced');q.rename(old);q.mkdir(mode=0o700)
    for item in old.iterdir():write_private(q/item.name,item.read_bytes())
   elif which=='hardlink':os.link(path,q/'linked')
   elif which=='truncate':path.write_bytes(b'')
   else:
    data=path.read_bytes();path.rename(q/(path.name+'.displaced'));write_private(path,data)
  expect(p.call(16,bytes(32)),1,'checkpoint');p.call(19);p.close()
 # Root and record inventories retain unknown and noncanonical evidence.
 for sub,name,mode,expected in [('', 'unknown',0o600,'unexpected ledger root entry'),('', 'unknown',0o777,'unexpected ledger root entry'),('records','unknown',0o777,'record inventory entry'),('records','unknown',0o600,'unexpected records directory entry'),('records','.record-00000000000000000001.tmp-0',0o600,'unexpected records directory entry'),('records','.record-00000000000000000001.tmp-01',0o600,'unexpected records directory entry'),('records','.record-00000000000000000001.tmp-4294967296',0o600,'unexpected records directory entry'),('records','record-00000000000001000001.v1',0o600,'unexpected records directory entry'),('', '.head.v1.tmp-1-0',0o600,'unexpected ledger root entry'),('', '.head.v1.tmp-01-1',0o600,'unexpected ledger root entry')]:
  p=Pair(root,'inventory-'+str(len(rows)));p.path(40,'ledger',cp0);p.call(45)
  for q in (p.na,p.nb):x=q/'ledger'/sub/name;write_private(x,b'evidence');x.chmod(mode)
  before=[disk(q)for q in(p.na,p.nb)];expect(p.path(41,'ledger',cp0+cp1),1,expected);assert before==[disk(q)for q in(p.na,p.nb)];state(p);p.close()
 # Permitted partial temps are cleaned only after operation context passes.
 for foreign in (False,True):
  p=Pair(root,'journal-ahead-'+str(foreign));p.path(40,'ledger',cp0);heads=[(q/'ledger/head.v1').read_bytes()for q in(p.na,p.nb)];p.call(43,cp0+cp1);p.call(45)
  for q,head in zip((p.na,p.nb),heads):
   (q/'ledger/head.v1').write_bytes(head);write_private(q/'ledger/records/.record-00000000000000000002.tmp-4294967295',b'partial');write_private(q/'ledger/.head.v1.tmp-4294967295-2',b'partial')
  before=[disk(q)for q in(p.na,p.nb)]
  if foreign:
   expect(p.path(41,'ledger',cp2+cp3),1,'neither exact source nor exact target');assert before==[disk(q)for q in(p.na,p.nb)]
  else:
   p.path(41,'ledger',cp0+cp1);expect(p.call(44,cp0+cp1),0,None);p.call(45);assert all(not list((q/'ledger/records').glob('.*'))and not list((q/'ledger').glob('.*'))for q in(p.na,p.nb))
  state(p);p.close()
 # Published-head validation and full-history rejection order.
 for scenario,expected in [('head-ahead','published head is ahead of durable records'),('gap','unexpected records directory entry'),('head-digest','published head digest differs'),('head-header','head header differs'),('old-record','record digest differs')]:
  p=Pair(root,'history-'+scenario);p.path(40,'ledger',cp0);p.call(43,cp0+cp1);p.call(43,cp1+cp2);p.call(45)
  for q in(p.na,p.nb):
   ledger=q/'ledger';rec1=ledger/'records/record-00000000000000000001.v1';rec2=ledger/'records/record-00000000000000000002.v1';head=ledger/'head.v1'
   if scenario=='head-ahead':rec2.unlink()
   if scenario=='gap':rec1.unlink()
   if scenario in('head-digest','head-header'):data=bytearray(head.read_bytes());data[-1 if scenario=='head-digest'else 0]^=1;head.write_bytes(data)
   if scenario in('head-header','old-record'):data=bytearray(rec1.read_bytes());data[-1]^=1;rec1.write_bytes(data)
   write_private(ledger/'records/.record-00000000000000000003.tmp-1',b'keep')
  before=[disk(q)for q in(p.na,p.nb)];expect(p.path(41,'ledger',cp2+cp3),1,expected);assert before==[disk(q)for q in(p.na,p.nb)];state(p);p.close()
 # A valid extension is accepted; a coherently rewritten observed prefix is
 # rejected before cleanup even if the published head is higher and consistent.
 for forged in(False,True):
  p=Pair(root,'live-prefix-'+str(forged));p.path(40,'ledger',cp0);p.call(43,cp0+cp1);observed=p.call(42)[1]
  target1=mutate_cp(cp1,424,61)if forged else cp1;target2=record(2,predecessor=target1[640:])
  for q in(p.na,p.nb):
   ledger=q/'ledger';first=ledger_record(1,anchor_digest(cp0),cp0,target1)
   if forged:(ledger/'records/record-00000000000000000001.v1').write_bytes(first)
   second=ledger_record(2,first[-32:],target1,target2);write_private(ledger/'records/record-00000000000000000002.v1',second)
   if forged:(ledger/'head.v1').write_bytes(ledger_head(2,second[-32:]));write_private(ledger/'records/.record-00000000000000000003.tmp-1',b'keep')
  before=[disk(q)for q in(p.na,p.nb)];result=p.call(44,target1+target2)
  if forged:
   expect(result,1,'observed ledger prefix changed');assert before==[disk(q)for q in(p.na,p.nb)];assert p.call(42)[1]==observed;expect(p.call(44,cp0+cp1),1,'ledger owner is fenced')
  else:expect(result,0,None);assert p.call(42)[1][:8]==struct.pack('<Q',2)
  p.call(45);state(p);p.close()
 # Retained root/records/anchor/lock descriptors cannot be rebound to copies.
 for which in('root','records','anchor.v1','ledger.lock'):
  p=Pair(root,'ledger-bound-'+which);p.path(40,'ledger',cp0)
  for q in(p.na,p.nb):
   path=q/'ledger' if which=='root'else q/'ledger'/which;old=path.with_name(path.name+'.displaced');path.rename(old)
   if old.is_dir():shutil.copytree(old,path);path.chmod(0o700)
   else:write_private(path,old.read_bytes())
  expect(p.call(44,cp0+cp1),1,'bound endpoint identity changed');p.call(45);p.close()
 # Symlinks/hardlinks are rejected without deleting referenced objects.
 for where,linkkind in [('record','symlink'),('record','hardlink'),('temp','symlink'),('headtemp','symlink')]:
  p=Pair(root,'links-'+where+'-'+linkkind);p.path(40,'ledger',cp0);p.call(43,cp0+cp1);p.call(45)
  for q in(p.na,p.nb):
   ledger=q/'ledger';reference=ledger/'records/record-00000000000000000001.v1'
   if where=='record':target=q/'retained';reference.rename(target);link=reference
   elif where=='temp':target=q/'retained';write_private(target,b'keep');link=ledger/'records/.record-00000000000000000002.tmp-1'
   else:target=q/'retained';write_private(target,b'keep');link=ledger/'.head.v1.tmp-1-2'
   if linkkind=='symlink':link.symlink_to(target)
   else:os.link(target,link)
  before=[disk(q)for q in(p.na,p.nb)];expect(p.path(41,'ledger',cp0+cp1),1,None);assert before==[disk(q)for q in(p.na,p.nb)];p.close()
