import pathlib,sys,json,hashlib,os,stat
O=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1/linux-closed-originals-v1');P=O/'payloads'
rows=json.loads(sys.argv[1]);batch=sys.argv[2];expected={r['path']:r for r in json.loads((O/'source-roster.json').read_bytes())['files']}
written=[]
for row in rows:
 rel=row['target_relative'];e=expected[rel];b=row['text'].encode('utf-8')
 assert len(b)==e['bytes'] and hashlib.sha256(b).hexdigest()==e['sha256'] and row['path']==e['origin']['path'] and row['version']==e['source_version']
 p=P/rel;assert p.parent.resolve()==p.parent and not p.exists() and not p.is_symlink()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b)
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 check=p.read_bytes();assert check==b
 written.append({'path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'origin':e['origin'],'source_version':row['version']})
summary={'schema':'trnm-policy-prefix-official-read-copy-batch-v1','batch':batch,'files':written,'verified':True}
raw=(json.dumps(summary,indent=2)+'\n').encode()
with (O/('batch-'+batch+'.json')).open('xb')as f:f.write(raw)
print(json.dumps({'batch':batch,'files':len(written),'bytes':sum(r['bytes']for r in written),'sha256':hashlib.sha256(raw).hexdigest()}))
