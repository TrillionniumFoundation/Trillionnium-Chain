import pathlib,json,hashlib,re
p=pathlib.Path("/private/tmp/chain-prci-N-cross-cost-job-log-review-20261114-v1/x64-job132415017426.log")
b=p.read_bytes();assert len(b)==184799 and hashlib.sha256(b).hexdigest()=="154555d87f24fbaed2609d14b18837c228256c65af29633eb42f611b9e291c81"
lines=b.decode().splitlines();objects=[];commands=[];special=[]
def walk(v,path=""):
 out=[]
 if isinstance(v,dict):
  for k,x in v.items():
   q=path+"/"+k
   if re.search(r"(exit|status|failure|error|returncode|command_argv|timed_out|signal|wall|elapsed)",k,re.I)and not isinstance(x,dict):out.append({"path":q,"value":x})
   if isinstance(x,(dict,list)):out+=walk(x,q)
 elif isinstance(v,list):
  for i,x in enumerate(v):
   if isinstance(x,(dict,list)):out+=walk(x,path+"/"+str(i))
 return out
for i,line in enumerate(lines,1):
 text=re.sub(r"^\\S+Z ","",line)
 # GitHub timestamps include seven fractional digits.
 text=re.sub(r"^20[0-9-]+T[0-9:.]+Z ","",text)
 if text.startswith("{"):
  try:
   x=json.loads(text)
  except Exception:continue
  objects.append({"line":i,"keys":sorted(x),"schema":x.get("schema"),"source_identity":x if x.get("schema")=="trnm-ci-source-v1"else None,"failures":walk(x)})
 if any(q in line for q in("run_from_zero_native.py","run_from_zero_host.py","CONFIRMATION_TARGET","pressure_workers","confirmation_target","signed_confirmation")):
  commands.append({"line":i,"text":line if len(line)<6000 else line[:600]+" [JSON full preserved in original log]"})
 if "Artifact "in line or "artifact zip" in line or "Final size" in line:special.append({"line":i,"text":line})
print(json.dumps({"line_count":len(lines),"objects":objects,"commands":commands,"artifact_lines":special},indent=2))
