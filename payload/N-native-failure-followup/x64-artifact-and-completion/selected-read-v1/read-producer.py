import pathlib,os,stat,sys,json,hashlib,zipfile
names=json.loads(sys.argv[1]);SELF=sys.argv[2]
B=pathlib.Path("/private/tmp/chain-prci-N-x64-native-artifact-14109658844-20261114-v1");O=B/"selected-read-v1";O.mkdir(mode=0o700)
zp=B/"N-cost-x64-14109658844.zip";ib=(B/"ZIP_MEMBER_INDEX.json").read_bytes();assert hashlib.sha256(ib).hexdigest()=="989f6ec25dc46aae82ce6a418693a0bca1b69a50b25ccb77d7ddddc3ef3b9199"
index=json.loads(ib);pins={r["path"]:r for r in index["files"]}
assert len(names)==17 and sum(pins[n]["bytes"]for n in names)<2*1024*1024
def js(v):return(json.dumps(v,indent=2)+"\n").encode()
def save(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return{"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
raw=zp.read_bytes();assert len(raw)==9884207 and hashlib.sha256(raw).hexdigest()=="10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4"
data={};rows=[]
with zipfile.ZipFile(zp,"r")as z:
 for n in names:
  b=z.read(n);p=pins[n];assert len(b)==p["bytes"] and hashlib.sha256(b).hexdigest()==p["sha256"]
  data[n]=b;row=save(O/"originals"/n,b);row.update({"artifact_id":14109658844,"source_member":n,"source_member_sha256":p["sha256"]});rows.append(row)
m=json.loads(data["from-zero-native/manifest.json"]);source=json.loads(data["source.json"]);native=[]
for n in names:
 if n.endswith("/process.json"):
  base=n.rsplit("/",1)[0];native.append({"selector":base.split("/")[-1],"process":json.loads(data[n]),"stdout":data[base+"/stdout"].decode(),"stderr":data[base+"/stderr"].decode()})
shape={k:{"type":type(v).__name__,"length":len(v)if isinstance(v,(dict,list,str))else None,"value":v if len(json.dumps(v))<4500 else None,"keys":list(v)if isinstance(v,dict)else None}for k,v in m.items()}
out={"source":source,"manifest_shape":shape,"native":native,"manifest_keys":list(m)}
save(O/"read-producer.py",SELF.encode());rp=save(O/"initial-reading.json",js(out))
ip=save(O/"SELECTED_MEMBER_INDEX.json",js({"schema":"trnm-N-x64-selected-from-zero-originals-v1","zip":index["zip"],"whole_member_index_sha256":hashlib.sha256(ib).hexdigest(),"files":rows,"selected_count":len(rows),"selected_bytes":sum(r["bytes"]for r in rows),"package_code_executed":False,"report_json_large_members_not_interpreted":True}))
print(json.dumps({"index":ip,"initial_reading":rp,"reading":out}),flush=True)
