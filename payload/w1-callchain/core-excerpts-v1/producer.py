import json,os,stat,hashlib,pathlib,re,sys
base=pathlib.Path("/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1")
out=base/'core-excerpts-v1'
out.mkdir(mode=0o700)
(out/'producer.py').write_text("" if False else sys.argv[1],encoding='utf-8')
rows=json.loads(sys.argv[2]); sources={}
for row in rows:
 p=pathlib.Path(row['captured']['path'])
 with p.open('rb') as f:
  a=os.fstat(f.fileno()); raw=f.read(); b=os.fstat(f.fileno())
 assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
 assert len(raw)==row['captured']['bytes'] and hashlib.sha256(raw).hexdigest()==row['captured']['sha256']
 sources[p.name]=raw.decode().splitlines()
plans={
 'pon-work-active-core1.txt':('04-pon_work.rs.raw',[(164,447),(464,911)]),
 'pon-work-active-core2.txt':('04-pon_work.rs.raw',[(912,1295)]),
 'scalar-checkpoint-paths.txt':('32-scalar_cpu.rs.raw',[(635,884),(1108,1148),(1220,1284)]),
 'history-observer-setup.txt':('30-history_import.rs.raw',[(105,265)]),
}
info=[]
for name,(src,ranges) in plans.items():
 lines=sources[src]
 text=''.join('\n'+src+' lines '+str(a)+'-'+str(b)+'\n'+''.join(f'{i+1}: {lines[i]}\n' for i in range(a-1,b)) for a,b in ranges)
 raw=text.encode(); p=out/name
 with p.open('xb') as f:f.write(raw)
 info.append({'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'source':src,'ranges':ranges})
for src in ['31-request_observation.rs.raw','32-scalar_cpu.rs.raw']:
 hits=[{'line':i+1,'text':s} for i,s in enumerate(sources[src]) if re.search(r'history_checkpoint|observe_submit_phase|struct .*Guard|fn .*phase|fn .*history|fn .*checkpoint|verified_completion|impl .*Observation|impl .*Guard|impl .*Phase|observe_sample|sleep|\.lock\(|try_lock',s)]
 raw=(json.dumps(hits,ensure_ascii=False,indent=2)+'\n').encode();p=out/(src+'.sites.json')
 with p.open('xb') as f:f.write(raw)
 info.append({'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
(out/'index.json').write_text(json.dumps(info,indent=2)+'\n')
print(json.dumps({'status':'EXCERPTS_ONLY_NO_EXECUTION','files':info},sort_keys=True))
