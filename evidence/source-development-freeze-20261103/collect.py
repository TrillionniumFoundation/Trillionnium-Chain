"""AST-based source-only collection; no model fit or historical task-set reads."""
import os,sys,json,hashlib,re,subprocess,collections
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=Path(os.environ.get("CHAIN_REPOSITORY",str(HERE.parents[1]))).resolve()
O=Path(os.environ['CHAIN_SOURCE_CACHE']).resolve()
# Install the pinned parser requirements in the interpreter environment.
if (O/'parser-deps').is_dir():sys.path.insert(0,str(O/'parser-deps'))
import tree_sitter,tree_sitter_rust
parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_rust.language()))
os.environ['GIT_NO_LAZY_FETCH']='1'
BASE='6cdbf9551aae1754e489773bac29bc0598e20a9b'
def git(*a):return subprocess.check_output(['git',*a],cwd=ROOT,timeout=10)
def content(blob):
 p=O/'blobs'/blob;b=p.read_bytes() if p.exists() else git('cat-file','blob',blob)
 assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==blob
 return b
def leaves(n,b):
 if n.type in ('line_comment','block_comment'):return []
 if n.child_count==0:return [b[n.start_byte:n.end_byte].decode()]
 return [s for ch in n.children for s in leaves(ch,b)]
def attributes(n,b):
 out=[];p=n.prev_named_sibling
 while p is not None and p.type=='attribute_item':out.append(b[p.start_byte:p.end_byte].decode());p=p.prev_named_sibling
 return out
def extract(b):
 tree=parser.parse(b);out=[];rejected=0
 def walk(n):
  nonlocal rejected
  if n.type=='function_item':
   if n.has_error or n.child_by_field_name('body')is None:rejected+=1;return
   raw=b[n.start_byte:n.end_byte]
   if len(raw)<80:return
   tokens=leaves(n,b);token_hash=hashlib.sha256(json.dumps(tokens,separators=(',',':')).encode()).hexdigest()
   name=n.child_by_field_name('name').text.decode();q=[];a=n.parent
   while a is not None:
    if a.type=='impl_item':
     typ=a.child_by_field_name('type');trait=a.child_by_field_name('trait');q.append('impl:'+(''if trait is None else trait.text.decode()+' for ')+(''if typ is None else typ.text.decode()))
    elif a.type=='mod_item':
     z=a.child_by_field_name('name');q.append('mod:'+(''if z is None else z.text.decode()))
    a=a.parent
   attrs=attributes(n,b)
   out.append({'token_id':token_hash,'name':name,'qualified':list(reversed(q))+[name],'start_byte':n.start_byte,'end_byte':n.end_byte,'source_sha256':hashlib.sha256(raw).hexdigest(),'source':raw.decode(),'tokens':tokens,'direct_test':any(re.search(r'#\[\s*(?:test|tokio::test)(?:\W|$)',x)for x in attrs)})
   return # Never collect overlapping nested functions.
  for c in n.named_children:walk(c)
 walk(tree.root_node)
 return out,{'file_parse_errors':tree.root_node.has_error,'rejected_function_nodes':rejected}
def shingles(tokens):return set(tuple(tokens[i:i+5]) for i in range(max(1,len(tokens)-4)))
def similar(a,b,hits):
 if not a or not b:return False
 return hits/(a+b-hits)>=.85 or (min(a,b)/max(a,b)>=.5 and hits/min(a,b)>=.90)
def features(s):
 # Original fixed hash representation, but fed exact comment-free AST tokens.
 tokens=re.findall(r'[a-zA-Z_][a-zA-Z_0-9]*',s.lower());tokens=[t for t in tokens if not t.startswith('trnm')and t not in {'m00','m04','m10'}]
 counts=[0]*256
 for t in tokens[:1024]:
  h=hashlib.sha256(t.encode()).digest();counts[int.from_bytes(h[:2],'little')%256]+=1 if h[2]&1 else -1
 return [max(-8,min(8,n))for n in counts]+[8]
def run():
 plan=(HERE/'COLLECTION_PLAN.json').read_bytes();owners=json.loads((O/'owner-discovery.json').read_text());old=set(json.loads((O/'history-filter.json').read_text())['historical_blobs'])
 inv=json.loads(git('show',BASE+':config/portability-inventory-v1.json'));paths=[x['path']for x in inv['packages']if x['module']in ('M00','M04','M10')]
 base={};parse=[];baseline_error_paths=set()
 for line in git('ls-tree','-r',BASE,'--',*paths).decode().splitlines():
  meta,path=line.split('\t');mode,kind,blob=meta.split()
  if kind!='blob'or not path.endswith('.rs'):continue
  funcs,status=extract(content(blob));parse.append({'role':'baseline','blob':blob,'path':path,**status})
  if status['file_parse_errors']:baseline_error_paths.add(path)
  for f in funcs:base[f['token_id']]=shingles(f['tokens'])
 candidates={};reasons=collections.Counter()
 for v in owners['variants']:
  if v['blob']in old:reasons['blob_in_baseline_history']+=1;continue
  eligible=[p for p in v['paths']if '/tests/'not in p and not p.endswith('/tests.rs')]
  if not eligible:reasons['excluded_test_path']+=1;continue
  if any(p in baseline_error_paths for p in eligible):reasons['baseline_parse_error_path_quarantine']+=1;continue
  funcs,status=extract(content(v['blob']));parse.append({'role':'candidate','blob':v['blob'],'paths':eligible,**status})
  if status['file_parse_errors']:reasons['candidate_parse_error_blob_quarantine']+=1;continue
  for f in funcs:
   if f['token_id']in base:reasons['exact_baseline_function_occurrences']+=1;continue
   r=candidates.setdefault(f['token_id'],dict(f,modules=set(),paths=set(),provenance=[]))
   r['modules'].update(v['modules']);r['paths'].update(eligible);r['direct_test']=r['direct_test'] or f['direct_test']
   r['provenance'].append({'blob':v['blob'],'paths':eligible,'head':v['heads'][0]['head'],'inventory_blob':v['heads'][0]['inventory_blob'],'start_byte':f['start_byte'],'end_byte':f['end_byte'],'source_sha256':f['source_sha256'],'qualified':f['qualified']})
 index=collections.defaultdict(set)
 for ident,s in base.items():
  for z in s:index[z].add(ident)
 kept={};excluded=[]
 for ident,r in candidates.items():
  s=shingles(r['tokens']);r['shingles']=s;hits=collections.Counter(x for z in s for x in index.get(z,()))
  matches=[x for x,h in hits.items()if similar(len(s),len(base[x]),h)]
  if len(r['modules'])!=1:excluded.append({'token_id':ident,'reason':'owner_conflict'});continue
  if matches:excluded.append({'token_id':ident,'reason':'near_baseline','baseline_matches':sorted(matches)});continue
  kept[ident]=r
 parent={i:i for i in kept};family_edges=[]
 def find(x):
  while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
  return x
 def union(a,b):
  a,b=find(a),find(b)
  if a!=b:parent[max(a,b)]=min(a,b)
 groups=collections.defaultdict(list)
 for ident,r in kept.items():
  for path in r['paths']:
   groups['path:'+path].append(ident)
   groups['versionpath:'+re.sub(r'[_-]v\d+(?=[./_-]|$)','',path)].append(ident)
   pkg=path.split('/')[2]
   for proof in r['provenance']:groups['qualified:'+pkg+'::'+'::'.join(proof['qualified'])].append(ident)
 path_groups={k[5:]:v for k,v in groups.items()if k.startswith('path:')}
 for path,ids in path_groups.items():
  prefix=path.removesuffix('.rs')+'/'
  for child,other in path_groups.items():
   if child.startswith(prefix):groups['parent-split:'+path].extend(ids+other)
 for reason,ids in groups.items():
  ids=sorted(set(ids))
  for ident in ids[1:]:union(ids[0],ident);family_edges.append({'reason':reason,'a':ids[0],'b':ident})
 index=collections.defaultdict(set);near_edges=[]
 for ident,r in sorted(kept.items()):
  s=r['shingles'];hits=collections.Counter(x for z in s for x in index.get(z,()))
  for x,h in hits.items():
   if similar(len(s),len(kept[x]['shingles']),h):union(ident,x);near_edges.append([x,ident])
  for z in s:index[z].add(ident)
 components=collections.defaultdict(list)
 for ident in kept:components[find(ident)].append(ident)
 component_records=[];rows=[];mixed_quarantine=[]
 for ids in components.values():
  modules={m for i in ids for m in kept[i]['modules']}
  if len(modules)>1:mixed_quarantine.append({'token_ids':sorted(ids),'modules':sorted(modules)});continue
  cid=hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest();split='dev_probe'if int(cid,16)%5==0 else 'dev_fit'
  component_records.append({'component':cid,'split':split,'functions':len(ids),'modules':sorted({m for i in ids for m in kept[i]['modules']}),'paths':sorted({p for i in ids for p in kept[i]['paths']}),'token_ids':sorted(ids)})
  for ident in ids:
   r=kept[ident];module=next(iter(r['modules']))
   rows.append({'id':ident,'family':cid,'split':split,'module':module,'label':['M00','M04','M10'].index(module),'function_name':r['name'],'qualified_identity':r['qualified'],'paths':sorted(r['paths']),'direct_test':r['direct_test'],'x':features(' '.join(r['tokens'])),'source':r['source'],'provenance':r['provenance']})
 rows.sort(key=lambda r:r['id']);component_records.sort(key=lambda r:r['component'])
 counts={s:dict(collections.Counter(r['module']for r in rows if r['split']==s))for s in ('dev_fit','dev_probe')}
 ready=len(component_records)>=5 and all(set(counts[s])=={'M00','M04','M10'}for s in counts)
 summary={'schema':'chain-frozen-development-v2','collection_plan_sha256':hashlib.sha256(plan).hexdigest(),'baseline_unique_ast_functions':len(base),'candidate_unique_ast_before_near_filter':len(candidates),'excluded':dict(collections.Counter(x['reason']for x in excluded)),'eligibility_rejections':dict(reasons),'retained_functions':len(rows),'connected_components':len(component_records),'mixed_owner_components_quarantined':len(mixed_quarantine),'near_duplicate_edges':len(near_edges),'split_counts':counts,'split_components':dict(collections.Counter(r['split']for r in component_records)),'collection_split_viable':ready,'parser_file_error_records':sum(r['file_parse_errors']for r in parse),'functions_rejected_parse_errors':sum(r['rejected_function_nodes']for r in parse),'model_training_run':False,'independent_acceptance':False,'future_window':False}
 for name,val in [('summary.json',summary),('rows.json',rows),('groups.json',component_records),('parse-audit.json',parse),('excluded.json',excluded),('near-edges.json',near_edges),('family-edges.json',family_edges),('mixed-owner-quarantine.json',mixed_quarantine)]: (HERE/name).write_text(json.dumps(val,indent=2)+'\n')
 print(json.dumps(summary,indent=2))
if __name__=='__main__':run()
