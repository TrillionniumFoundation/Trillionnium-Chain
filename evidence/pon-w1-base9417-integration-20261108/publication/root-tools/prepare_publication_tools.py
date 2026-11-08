#!/usr/bin/env python3
import pathlib,hashlib,json
old=pathlib.Path('/home/qian-qi/work/chain-w1-c7-root-tools-20261108-ec265b')
new=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
records=[]
def derive(src,dst,replacements):
 b=(old/src).read_bytes();s=b.decode()
 for before,after,count in replacements:
  assert s.count(before)==count,(src,before,s.count(before),count)
  s=s.replace(before,after)
 p=new/dst
 with p.open('x') as w:w.write(s)
 compile(s,str(p),'exec')
 records.append({'source':str(old/src),'source_sha256':hashlib.sha256(b).hexdigest(),'result':str(p),'result_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'replacements':[{'old':a,'new':b,'count':c} for a,b,c in replacements]})
derive('verify_git_publication.py','verify_git_publication.py',[
 ("('evidence/pon-w1-base96-integration-20261108',a.expected_new_inventory_sha256,None)","('evidence/pon-w1-base96-integration-20261108','9c0c06ea019853aededd8e24475b34480ec05b45f7cc101a3e54d7a27f0b982a',1242),\n ('evidence/pon-w1-base9417-integration-20261108',a.expected_new_inventory_sha256,None)",1),
 ('40a3a45d6b8afc5c4706c5235fec47634f4aabbe','4e007a87ceecbec8d265f6a70cfd71d512a514b5',1),
 ('no_extra_tracked_paths_in_three_packages','no_extra_tracked_paths_in_four_packages',2)
])
derive('publish_c7_source.py','publish_c8_source.py',[
 ('chain-w1-base96-integration-20261108-ec265b','chain-w1-base9417-integration-20261108-ec265b',1),
 ('chain-w1-c7-root-validation-20261108-ec265b','chain-w1-c8-root-validation-20261108-ec265b',1),
 ('40a3a45d6b8afc5c4706c5235fec47634f4aabbe','4e007a87ceecbec8d265f6a70cfd71d512a514b5',1),
 ('4b25e3194a0682adff40bb476f2e7c0a395639fe','19a4f1a6e1cec5c27e595fa555b97cddc4717a3c',1),
 ('2bdd252aa6c300b7431b9ee897b254b7953cf562','40a3a45d6b8afc5c4706c5235fec47634f4aabbe',1),
 ('exact-owner-01/manifest.json','exact-owner-02/manifest.json',1),
 ("('history-local',v/'exact-history-local-01/manifest.json')","('history-local',v/'exact-history-local-01/manifest.json'),('historical-regressions',v/'exact-historical-regressions-01/manifest.json')",1),
 ('chain-w1-c7-backend-qualification','chain-w1-c8-backend-qualification',1),
 ('chain-w1-c7-native-qualification','chain-w1-c8-native-qualification',1),
 ('(69,655,4,1)','(73,665,4,1)',1),
 ('TRNM-W1-C7-SOURCE-PUBLICATION1','TRNM-W1-C8-SOURCE-PUBLICATION1',1),
 ('96a241bf43f6a46d35dfb3d4ced9594ed8ceca75','9417e495165865ef6c1288b39084856e31020634',2)
])
out=new/'publication-tool-derivation.json'
with out.open('x') as w:w.write(json.dumps({'schema':'TRNM-W1-C8-PUBLICATION-TOOL-DERIVATION1','records':records},indent=2)+'\n')
print(json.dumps(records))
