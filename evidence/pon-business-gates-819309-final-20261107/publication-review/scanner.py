import os,re,json,hashlib,zipfile,gzip,tarfile,io,subprocess,datetime,time
from pathlib import Path
BASE=Path('/home/qian-qi/throughput-final-ci-observation-20261107')
OUT=BASE/'publication-secret-review-v1'
OUT.mkdir(exist_ok=True)
ROOTS=[BASE/x for x in ['core-14-package-v1','w1-components-metadata-package-v1','w1-components-transport-v2-package','w1-range-v3-package']]
START=datetime.datetime.now(datetime.timezone.utc).isoformat()
LIMIT=8*1024**3
ITEM_LIMIT=1024**3
NEST_LIMIT=128*1024**2
stats={'outer_files':0,'outer_bytes':0,'archive_members':0,'archive_member_bytes':0,'gzip_decoded_streams':0,'gzip_decoded_bytes':0,'streams':0,'scanned_bytes':0}
inventory=[];findings={};errors=[];unscanned=[];seals=[];packages=[]
patterns=[
 ('github_token',re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b')),
 ('authorization_literal',re.compile(rb'(?i)(?:proxy-)?authorization["\x27]?\s*[:=]\s*["\x27]?(?:basic|bearer|token)\s+([^\s"\x27\\,;]{4,2048})')),
 ('pem_private_key',re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')),
 ('jwt',re.compile(rb'\beyJ[A-Za-z0-9_-]{8,2048}\.eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{16,2048}\b')),
 ('named_secret_literal',re.compile(rb'(?i)["\x27]?(?:github_token|gh_token|access_token|refresh_token|client_secret|private_key|secret_key|signing_key|cookie_key|api_key|mnemonic)["\x27]?\s*[:=]\s*["\x27]([^"\x27\r\n]{16,4096})["\x27]')),
 ('named_private_key_array',re.compile(rb'(?i)(?:private_key|secret_key|signing_key)\s*[:=]\s*\[[0-9a-fx_,; \t\r\nu]{16,2048}\]')),
 ('url',re.compile(rb'https?(?::|%3[Aa])(?:/|\\/|%2[Ff]){2}[^\s<>"\x27]{1,16384}'))
]
TEXT={'.json','.jsonl','.ndjson','.md','.py','.rs','.toml','.yml','.yaml','.txt','.log','.xml','.csv','.html','.sh','.tsv','.sarif'}
def digest_file(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def classify(cat,raw,label):
 val=raw
 if cat=='authorization_literal':
  m=patterns[1][1].search(raw)
  if m:val=m.group(1)
 if re.fullmatch(rb'[\*\-_.]{3,}',val) or val.lower() in [b'redacted',b'<redacted>',b'[redacted]',b'***']:
  return 'masked_value'
 if b'$'+b'{' in val or b'{{' in val or val.startswith((b'os.environ',b'process.env',b'$GH_',b'$GITHUB_',b'$TOKEN')):
  return 'template_or_environment_reference'
 if 'test_range_v3_response_controls' in label and cat in ['authorization_literal','url']:
  return 'synthetic_response_control_requires_source_check'
 if cat=='url':
  from urllib.parse import unquote,urlsplit,parse_qsl
  s=unquote(raw.decode('ascii','ignore').replace('\\/','/'))
  try:
   u=urlsplit(s);q={k.lower():v for k,v in parse_qsl(u.query,keep_blank_values=True)}
  except Exception:return None
  secret_keys=set(q)&{'sig','signature','token','access_token','x-amz-signature','x-goog-signature','se','jwt','credential'}
  if not secret_keys:return None
  host=(u.hostname or '').lower()
  if host in ['example.com','example.org','example.net','localhost'] or host.endswith(('.example','.invalid','.test')):
   return 'synthetic_or_documentation_url'
  expiry=None
  try:
   if 'se' in q:expiry=datetime.datetime.fromisoformat(q['se'].replace('Z','+00:00')).timestamp()
   elif 'expires' in q and q['expires'].isdigit():expiry=float(q['expires'])
   elif 'x-amz-date' in q and 'x-amz-expires' in q:expiry=datetime.datetime.strptime(q['x-amz-date'],'%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()+float(q['x-amz-expires'])
   elif 'x-goog-date' in q and 'x-goog-expires' in q:expiry=datetime.datetime.strptime(q['x-goog-date'],'%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()+float(q['x-goog-expires'])
  except Exception:pass
  return 'signed_url_expired_by_embedded_timestamp' if expiry is not None and expiry<time.time() else 'signed_url_active_or_unknown_requires_review'
 return 'requires_review'
def scan_stream(fp,label,size,kind):
 if size is not None and size>ITEM_LIMIT:
  unscanned.append({'path':label,'reason':'item_limit','bytes':size});return None
 h=hashlib.sha256();offset=0;tail=b'';line_before=0;is_text=Path(label.split('!')[-1]).suffix.lower() in TEXT
 while True:
  block=fp.read(1024*1024)
  if not block:break
  if offset+len(block)>ITEM_LIMIT or stats['scanned_bytes']+len(block)>LIMIT:
   unscanned.append({'path':label,'reason':'byte_limit','already_scanned_bytes':offset});return None
  h.update(block);stats['scanned_bytes']+=len(block)
  data=tail+block;startbase=offset-len(tail);base_line=line_before-tail.count(b'\n')
  for cat,rx in patterns:
   for m in rx.finditer(data):
    if startbase+m.end()<=offset:continue
    classification=classify(cat,m.group(0),label)
    if classification is None:continue
    if len(findings)>=100000:raise RuntimeError('finding_bound')
    key=(label,cat,startbase+m.start())
    entry={'path':label,'category':cat,'classification':classification,'byte_offset':startbase+m.start(),'matched_bytes':m.end()-m.start()}
    if is_text:entry['line']=base_line+data[:m.start()].count(b'\n')+1
    prev=findings.get(key)
    if prev is None or entry['matched_bytes']>prev['matched_bytes']:findings[key]=entry
  line_before+=block.count(b'\n');offset+=len(block);tail=data[-65536:]
 item={'path':label,'kind':kind,'bytes':offset,'sha256':h.hexdigest(),'expected_bytes':size,'size_matches':size is None or offset==size}
 inventory.append(item);stats['streams']+=1
 if not item['size_matches']:errors.append({'path':label,'reason':'stream_size_mismatch'})
 return item
def archive_kind(name):
 n=name.lower()
 if n.endswith(('.tar.gz','.tgz','.tar')):return 'tar'
 if n.endswith('.zip'):return 'zip'
 if n.endswith('.gz'):return 'gzip'
 return None
def scan_archive(src,label,kind,depth=0):
 if depth>2:
  unscanned.append({'path':label,'reason':'nested_depth'});return
 try:
  if kind=='zip':
   with zipfile.ZipFile(src) as z:
    for m in z.infolist():
     if m.is_dir():continue
     member=label+'!'+m.filename
     if (m.external_attr>>16)&0o170000==0o120000:errors.append({'path':member,'reason':'archive_symlink'})
     with z.open(m) as f:got=scan_stream(f,member,m.file_size,'zip_member')
     if got:stats['archive_members']+=1;stats['archive_member_bytes']+=got['bytes']
     nested=archive_kind(m.filename)
     if nested:
      if m.file_size>NEST_LIMIT:unscanned.append({'path':member,'reason':'nested_archive_memory_bound','bytes':m.file_size})
      else:
       with z.open(m) as f:buf=io.BytesIO(f.read())
       scan_archive(buf,member,nested,depth+1)
  elif kind=='gzip':
   with gzip.GzipFile(fileobj=src if not isinstance(src,Path) else None,filename=str(src) if isinstance(src,Path) else '') as f:got=scan_stream(f,label+'!gzip-content',None,'gzip_decoded')
   if got:stats['gzip_decoded_streams']+=1;stats['gzip_decoded_bytes']+=got['bytes']
  elif kind=='tar':
   with tarfile.open(str(src) if isinstance(src,Path) else None,fileobj=None if isinstance(src,Path) else src,mode='r:*') as t:
    for m in t:
     if not m.isfile():
      if m.issym() or m.islnk():errors.append({'path':label+'!'+m.name,'reason':'archive_link'})
      continue
     member=label+'!'+m.name
     with t.extractfile(m) as f:got=scan_stream(f,member,m.size,'tar_member')
     if got:stats['archive_members']+=1;stats['archive_member_bytes']+=got['bytes']
     nested=archive_kind(m.name)
     if nested:
      if m.size>NEST_LIMIT:unscanned.append({'path':member,'reason':'nested_archive_memory_bound','bytes':m.size})
      else:
       with t.extractfile(m) as f:buf=io.BytesIO(f.read())
       scan_archive(buf,member,nested,depth+1)
 except Exception as ex:errors.append({'path':label,'reason':'archive_read_failed','error_class':type(ex).__name__})
def progress(p):
 print(json.dumps({'progress':p,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stats':stats,'finding_count':len(findings),'error_count':len(errors),'unscanned_count':len(unscanned)},separators=(',',':')),flush=True)
for root in ROOTS:
 controls={}
 for name in ['SHA256SUMS','SEAL.json']:controls[name]={'before':digest_file(root/name)}
 seals.append({'package':root.name,'controls':controls})
 manifest={}
 for line in (root/'SHA256SUMS').read_text().splitlines():
  m=re.fullmatch(r'([0-9a-f]{64}) [ *](.+)',line)
  if not m:errors.append({'path':root.name+'/SHA256SUMS','reason':'invalid_manifest_line'});continue
  manifest[m.group(2)]=m.group(1)
 proc=subprocess.run(['rg','--files','--hidden','--no-ignore','--no-messages',str(root)],capture_output=True)
 if proc.returncode not in [0,1]:raise RuntimeError('file_inventory_failed')
 files=sorted(Path(x) for x in proc.stdout.decode().splitlines())
 actual={str(p.relative_to(root)) for p in files};expected=set(manifest)|{'SHA256SUMS','SEAL.json'}
 if actual!=expected:errors.append({'path':root.name,'reason':'outer_set_mismatch','missing':sorted(expected-actual),'unexpected':sorted(actual-expected)})
 count=0;total=0;progress('begin '+root.name)
 for p in files:
  rel=str(p.relative_to(root));label=root.name+'/'+rel
  if p.is_symlink():errors.append({'path':label,'reason':'outer_symlink'});continue
  before=p.stat()
  with p.open('rb') as f:got=scan_stream(f,label,before.st_size,'outer_file')
  after=p.stat()
  if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):errors.append({'path':label,'reason':'changed_while_reading'})
  if got:
   count+=1;total+=got['bytes'];stats['outer_files']+=1;stats['outer_bytes']+=got['bytes']
   if rel in manifest and got['sha256']!=manifest[rel]:errors.append({'path':label,'reason':'sealed_sha_mismatch'})
  kind=archive_kind(p.name)
  if kind:scan_archive(p,label,kind)
  if count%50==0:progress(root.name+' files '+str(count))
 packages.append({'name':root.name,'outer_files':count,'outer_bytes':total,'manifest_payload_files':len(manifest)})
 for name in ['SHA256SUMS','SEAL.json']:
  controls[name]['after']=digest_file(root/name);controls[name]['unchanged']=controls[name]['before']==controls[name]['after']
  if not controls[name]['unchanged']:errors.append({'path':root.name+'/'+name,'reason':'seal_changed'})
 progress('end '+root.name)
results=sorted(findings.values(),key=lambda x:(x['path'],x['byte_offset'],x['category']))
from collections import Counter
summary={'schema':'sealed-publication-secret-review-v1','started_utc':START,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope_roots':[str(p) for p in ROOTS],'stats':stats,'packages':packages,'finding_count':len(results),'by_category':dict(Counter(x['category'] for x in results)),'by_classification':dict(Counter(x['classification'] for x in results)),'errors':errors,'unscanned':unscanned,'seal_checks':seals,'complete_scan':not errors and not unscanned,'scan_only_no_validity_test':True,'limits':{'total_bytes':LIMIT,'item_bytes':ITEM_LIMIT,'nested_archive_bytes':NEST_LIMIT,'nested_depth':2},'findings':results}
for name,val in [('scan-result.json',summary),('scanned-stream-inventory.json',inventory)]:(OUT/name).write_text(json.dumps(val,ensure_ascii=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='findings'},separators=(',',':')),flush=True)
print(json.dumps({'outputs':[{'path':str(OUT/name),'bytes':(OUT/name).stat().st_size,'sha256':digest_file(OUT/name)} for name in ['scan-result.json','scanned-stream-inventory.json']]},separators=(',',':')),flush=True)
