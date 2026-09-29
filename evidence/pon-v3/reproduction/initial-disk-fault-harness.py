"""Owned temporary-copy disk error tests only; no live node or service mutation."""
from pathlib import Path
import concurrent.futures,json,shlex,subprocess
H=Path('/tmp/pon-liveclock-campaign-9xv_c70x')
identities=json.loads((H/'results/remote-roots.json').read_text())
program=r'''
from pathlib import Path
import hashlib,json,os,shutil,sqlite3,sys,tempfile
base=Path(sys.argv[1]);assert str(base).startswith('/tmp/trnm-pon-host-qualification-')
sys.path.insert(0,str(base/'source/formal/pon-nakamoto-v1'))
from ledger import Ledger, canonical
original=base/'state/chain/ledger.sqlite'
assert original.is_file() and not original.is_symlink()
trials=Path(tempfile.mkdtemp(prefix='disk-fault-copies-',dir=base))
rows=[]
def copy_case(name):
    directory=trials/name;directory.mkdir(mode=0o700)
    src=sqlite3.connect('file:'+str(original)+'?mode=ro',uri=True)
    dst=sqlite3.connect(directory/'ledger.sqlite')
    try:src.backup(dst)
    finally:src.close();dst.close()
    return directory
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
# A schema attack is detected before writable PRAGMAs on the copied namespace.
directory=copy_case('extra-trigger');file=directory/'ledger.sqlite'
c=sqlite3.connect(file);c.execute('CREATE TRIGGER bad_scope AFTER INSERT ON events BEGIN DELETE FROM events; END');c.commit();c.close()
before=digest(file)
try:
    obj=Ledger(directory);obj.close();raise AssertionError('injected trigger accepted')
except ValueError as error:assert str(error)=='SCHEMA'
assert digest(file)==before
rows.append({'case':'extra-trigger','rejection':'SCHEMA','database_unchanged_after_refusal':True})
# A corrupted published value cannot be read as an authenticated state.
directory=copy_case('state-root');c=sqlite3.connect(directory/'ledger.sqlite')
slot=c.execute('SELECT state_slot FROM active').fetchone()[0]
name,raw=c.execute("SELECT key,value FROM kv WHERE generation=? AND key LIKE 'account:%' LIMIT 1",(slot,)).fetchone()
v=json.loads(raw);v['balance']+=1;c.execute('UPDATE kv SET value=? WHERE generation=? AND key=?',(canonical(v),slot,name));c.commit();c.close()
obj=Ledger(directory)
try:
    try:obj.read_active();raise AssertionError('modified state accepted')
    except ValueError as error:assert str(error)=='ROOT'
finally:obj.close()
rows.append({'case':'published-value-corruption','rejection':'ROOT','no_authoritative_read':True})
# A storage-engine full condition occurs inside a transaction and rolls back exactly.
directory=copy_case('sqlite-full');file=directory/'ledger.sqlite';c=sqlite3.connect(file,isolation_level=None)
c.execute('PRAGMA journal_mode=DELETE');pages=c.execute('PRAGMA page_count').fetchone()[0]
c.execute('PRAGMA max_page_count='+str(pages));size=c.execute('PRAGMA page_size').fetchone()[0]
before=c.execute('SELECT count(*) FROM metadata').fetchone()[0];full=False
try:
    c.execute('BEGIN IMMEDIATE')
    for i in range(10000):c.execute('INSERT INTO metadata VALUES(?,?)',('bounded-full-'+str(i),b'x'*(size*2)))
    c.execute('COMMIT')
except sqlite3.DatabaseError as error:
    full=getattr(error,'sqlite_errorcode',None)==sqlite3.SQLITE_FULL
    if c.in_transaction:c.execute('ROLLBACK')
assert full,'no actual SQLITE_FULL observed'
assert c.execute('SELECT count(*) FROM metadata').fetchone()[0]==before
assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok';c.close()
obj=Ledger(directory)
try:obj.read_active()
finally:obj.close()
rows.append({'case':'sqlite-page-limit-full','rejection':'SQLITE_FULL','partial_rows_committed':False,'original_state_reopens':True,'physical_device_full':False})
# Truncate only a copied file, then refuse it rather than initializing over corruption.
directory=copy_case('truncated-header');file=directory/'ledger.sqlite'
with file.open('r+b')as f:f.truncate(128);f.flush();os.fsync(f.fileno())
before=digest(file)
try:
    obj=Ledger(directory);obj.close();raise AssertionError('truncated database accepted')
except (ValueError,sqlite3.DatabaseError)as error:kind=type(error).__name__
assert digest(file)==before
rows.append({'case':'truncated-database','rejection_type':kind,'database_unchanged_after_refusal':True})
print(json.dumps({'schema':'pon-owned-disk-error-cases-v3','temporary_root':str(trials),'cases':rows,'uses_real_sqlite':True,'original_database_modified':False,'physical_power_loss':False,'independent_accepted':False,'production_activation':False}))
'''
def run(item):
 host=item['host'];root=item['temporary_root']
 result=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=8',host,'python3 - '+shlex.quote(root)],input=program,text=True,capture_output=True,timeout=75)
 record={'host':host,'returncode':result.returncode,'stderr':result.stderr[-2000:]}
 if result.returncode==0:record['report']=json.loads(result.stdout)
 else:record['output']=result.stdout[-2000:]
 return record
with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:results=list(pool.map(run,identities))
report={'schema':'pon-bound-physical-disk-error-followup-v3','source_commit':json.loads((H/'source-manifest.json').read_text())['source_commit'],'same_operator':True,'independent_operators':False,'all_cases_passed':all(r['returncode']==0 for r in results),'results':results,'physical_power_loss':False,'production_activation':False}
(H/'disk-errors.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
raise SystemExit(0 if report['all_cases_passed']else 2)
