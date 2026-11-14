import hashlib,json,os,pathlib,stat,types
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
hp=ROOT/"root_merge_helpers.py";hb=hp.read_bytes()
assert hashlib.sha256(hb).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("reviewed_root_merge_helpers");exec(compile(hb,str(hp),"exec"),h.__dict__)
h.setup("combined-binding-followup-integration-v1")
def sha(b):return hashlib.sha256(b).hexdigest()
def fixed(path, expected, n=None):
 q=pathlib.Path(path);assert str(q.resolve())==str(q)
 fd=os.open(q,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
  with os.fdopen(fd,"rb",closefd=False) as f:b=f.read()
  z=os.fstat(fd);assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 finally:os.close(fd)
 assert sha(b)==expected and (n is None or len(b)==n),(str(q),sha(b),len(b))
 return b
before="e99fe0e0e48a96185e1d02ac5acc458311814f65";base="7d8d4c59fcd01480a12e1c64835b202079091800";b1="341a8b5f751342b51a4aaf9512534853c79d7b5b"
assert h.git("rev-parse","HEAD").decode().strip()==before
assert not h.git("status","--porcelain=v1","--untracked-files=all")
assert h.git("rev-parse",b1+"^").decode().strip()==base
assert h.git("rev-parse",b1+"^{tree}").decode().strip()=="234b37f6a0dfd8adf758d78d533b055499b295b8"
brec=json.loads(fixed("/private/tmp/chain-native-bridge-history-binding-review-20261114/commit-v1/summary.json","148d68ffd71fa5ffc48fe529d0b3df72982485a80713f2625d2aeeaf8bba1267",27536))
bpaths={r["path"] for r in brec["exact_paths"]};assert len(bpaths)==12
assert set(h.git("diff","--name-only",base,b1).decode().splitlines())==bpaths
for row in brec["exact_paths"]:
 raw=h.show(b1,row["path"]);assert len(raw)==row["bytes"] and sha(raw)==row["sha256"]
 assert h.git("rev-parse",b1+":"+row["path"]).decode().strip()==row["git_blob_sha1"]
plan_path=h.src/h.plan;audit_path=h.src/"docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md"
old_plan=fixed(plan_path,"5151414e11e11f53af688ba043106412976149dfa1e3d6a5d4e36e1791d29887",1138840)
old_audit=fixed(audit_path,"b63e729b9b989bec332e0f26f6ded582a691ecb752b04c7496d13fb1ca007625",35374)
h.run("preflight-before",["/bin/bash","scripts/project-preflight.sh","--audit"])
h.run("normal-b1-merge",["git","merge","--no-ff","--no-commit",b1])
assert h.git("rev-parse","MERGE_HEAD").decode().strip()==b1
for path in bpaths:assert (h.src/path).read_bytes()==h.show(b1,path)
prov=json.loads((h.src/"evidence/branch-consolidation-followup-20261114/native-collector-history-v1/provenance.json").read_bytes())
raw_path="formal/pon-nakamoto-v1/fixtures/native-collector-e4abb172.py.raw"
raw=fixed(h.src/raw_path,"f40c5d621454d0532141920724a3cfd57e240f4a3b061536162313daa676c254",23639)
assert raw==h.show("e4abb172147e941b62483652b0ceabaae4317624","formal/pon-native-fullpath-v1/collect_native.py")
for row in prov["objects"]:
 data=fixed(h.src/row["path"],row["sha256"],row["bytes"])
 assert h.git("cat-file",row["type"],row["oid"])==data
 assert hashlib.sha1(row["type"].encode()+b" "+str(len(data)).encode()+b"\0"+data).hexdigest()==row["oid"]
old_rel="evidence/pon-fixed-joint-source-binding-20261114/historical/JOINT_CONSENSUS_QUALIFICATION_V1-2bb56596.md"
new_rel=old_rel+".original"
orig=fixed(h.src/old_rel,"cd4908e6e71297dd40b76c1703f04ae3430eb80a4850ec851086a3de71ced04b",13956)
assert not (h.src/new_rel).exists();(h.src/old_rel).rename(h.src/new_rel);assert (h.src/new_rel).read_bytes()==orig
ixrel="evidence/pon-fixed-joint-source-binding-20261114/f2/EVIDENCE_INDEX.json"
ixraw=fixed(h.src/ixrel,"9a692e0b337d0a8f75ce0e1cf2e1a509ebccc40b033f0e03190e6f45892d14ea",4996)
ix=json.loads(ixraw);matches=[x for x in ix["files"] if x["path"]=="historical/JOINT_CONSENSUS_QUALIFICATION_V1-2bb56596.md"];assert len(matches)==1
matches[0]["path"]+=".original"
ixnew=(json.dumps(ix,indent=2,sort_keys=True)+"\n").encode();(h.src/ixrel).write_bytes(ixnew)
pin_updates={
"config/pon/hash-use-contract-v1.json":"986a94eaf6b1c44a11595cc98ac4f9925e7c943e",
"scripts/ci/hash_use_contract.py":"cf55d45678bfb27d9ad9fcf2863a05aa1bc0540b",
"docs/security/HASH_USE_CONTRACT_V1.md":"caeef93f9bc11228fc8fe5d18923ffca42a7af16",
"config/pon/joint-consensus-qualification-v1.json":"b2ce9946df65598ea1068ee5d2fbdcac131de6c8",
"formal/pon-nakamoto-v1/joint_consensus_qualification.py":"675a93aef57d928cb7054778b64232e922ca57e4",
"formal/pon-nakamoto-v1/test_joint_consensus_qualification.py":"7983a260ff6cfb91c4f2f8ab4b128f0769fa166c",
"docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_QUALIFICATION_V1.md":"fb577f6b424f19db48e21d0027cf3618e3556bbf",
"formal/pon-nakamoto-v1/w1_quantum_native_bridge.py":"61731a92ddf7e5fd27f8712dc204c2d065b22eff",
"formal/pon-nakamoto-v1/test_w1_quantum_native_bridge.py":"89bbe4a78c3d258e7799556257f4919cc280e17f",
"docs/research/W1_ORACLE_EVIDENCE_SCOPE_V1.md":"bae4d5c9692e451bddb2e46e67facefeb649848b",
"scripts/ci/check_pq_research_integration.py":"17d6cfd501ce311f3239dc0c9eb53753c255f3be",
"scripts/ci/test_pq_research_integration.py":"b43c38008095eff5ab7a5cac35c00beddd2803d0"}
mp=h.src/h.manifest;m=json.loads(mp.read_bytes());oldm=json.loads(mp.read_bytes())
assert len(m["pinned_blobs"])==2599 and len(m["required_paths"])==2503
for path,oid in pin_updates.items():
 assert path in m["pinned_blobs"] and h.blob(path)==oid and m["pinned_blobs"][path]!=oid
 m["pinned_blobs"][path]=oid
assert raw_path not in m["required_paths"] and raw_path not in m["pinned_blobs"]
assert h.blob(raw_path)=="421b10241820580efcdabc692ccb1f6dd27b6586"
m["required_paths"]=sorted(m["required_paths"]+[raw_path]);m["pinned_blobs"][raw_path]=h.blob(raw_path)
m["pinned_blobs"]=dict(sorted(m["pinned_blobs"].items()))
assert {k for k in m if m[k]!=oldm[k]}=={"required_paths","pinned_blobs"}
assert {k for k in m["pinned_blobs"] if m["pinned_blobs"][k]!=oldm["pinned_blobs"].get(k)}==set(pin_updates)|{raw_path}
mp.write_text(json.dumps(m,indent=2,ensure_ascii=False)+"\n")
e_rel="evidence/branch-consolidation-followup-20261114/source-binding-integration-v1"
ep=h.src/e_rel;ep.mkdir(exist_ok=False)
copy_root=ROOT/"remaining-repository-truth-diagnostics-7d8d4c-copy-v1"
payloads=[
("original-diagnostics-7d8d4c-v1.zip","diagnostics.zip",180498,"038fb138c75fef1eca35422e08f7d5e2c784bec70fcc739695c4ca71b5637c5a"),
("EVIDENCE_INDEX.json","diagnostics-index.json",97406,"4711b610ad6cf1f9711947caece9bc562002a8857d0ce454bc295806ad608ac1"),
("copy-verification.json","diagnostics-copy-verification.json",8637,"bc7f7b95bd73b52919ce9e86ffba6e20b8117a896d54d0569687a02494d15a2a"),
("original-summary.json","diagnostics-original-summary.json",None,"d47c5501b2087a4ac8d9b092b51f246450cf57b2f02b5dbaf83b96e63672bef3")]
copied=[]
for old,new,n,s in payloads:
 data=fixed(copy_root/old,s,n)
 with (ep/new).open("xb") as f:f.write(data)
 assert (ep/new).read_bytes()==data
 copied.append({"path":new,"bytes":len(data),"sha256":s,"origin":{"host":"mac","path":str(copy_root/old)}})
review={"schema":"trnm-reviewed-source-binding-integration-v1","integration_parent":before,"components":{"H1":"e811c204e039565c06f5bb2cba3543564f510f7b","F1":"2d9baf313e54e49a4507c5057578e89ddbe7a1b6","F2":"6418023d7f60e6e0c42f08c8726085a2b983757b","B1":b1},"existing_corpus_pin_updates":pin_updates,"new_required_path":raw_path,"new_required_blob":h.blob(raw_path),"source_pins_after":len(m["pinned_blobs"]),"required_paths_after":len(m["required_paths"]),"historical_carrier":{"old_path":old_rel,"new_path":new_rel,"bytes":len(orig),"sha256":sha(orig),"original_f2_index_sha256":sha(ixraw),"current_index_sha256":sha(ixnew),"old_relative_links":13,"original_bytes_unchanged":True},"diagnostic_originals":copied,"diagnostic_scope":{"source":base,"commands":122,"zero_exits":116,"nonzero_units":[1,6,10,22,23,107],"qualifies_original_full_lane":False},"historical_git_object_bodies_compared_to_original_git":4,"native_execution":False,"full_lane_pass_claimed":False,"hosted_pass_claimed":False,"production_activation":False,"remote_merge_or_deletion_claimed":False}
(ep/"integration-review.json").write_text(json.dumps(review,indent=2,sort_keys=True)+"\n")
(ep/"README.md").write_text("# Reviewed source-binding follow-up integration\n\nThe original complete repository-truth lane on 7d8d4c59 failed; the subsequent\n122-unit continuation diagnostic completed with 116 zero and six nonzero exits.\nIt is diagnostic evidence, not a passing original full lane.\n\n- [Original diagnostic summary](diagnostics-original-summary.json)\n- [Complete original diagnostic ZIP](diagnostics.zip)\n- [Exact ZIP member index](diagnostics-index.json)\n- [Cross-host copy verification](diagnostics-copy-verification.json)\n- [Integration decisions and original carrier identities](integration-review.json)\n\nThe ZIP contains 266 original files plus its index. Original stdout, stderr,\ncommand bodies, timing, source records and failure exits are preserved.\nThe four reviewed component commits are H1 e811c204, F1 2d9baf31, F2 6418023d\nand B1 341a8b5f. Their local controls and explicit qualification boundaries\nremain separate from any later exact-source complete lane or hosted result.\n\nThe current corpus changes only twelve existing reviewed blob pins and adds\none required raw historical collector dependency. The historical joint Markdown\ndocument keeps its original bytes under a .md.original carrier; its original\nindex and file remain available at the F2 commit. No current Markdown checker\nexception is added. No native runtime or original acceptance limit is changed.\n\nThe source commit which contains this integration cannot contain its own later\ncomplete gate receipts. Those are collected separately with the actual head,\ntree, original outputs and source readbacks before any publication decision.\n")
plan_path.write_bytes(old_plan+"\n### 2026-11-14 reviewed follow-up after the second full-lane failure\n\nThe complete original Linux lane on source 7d8d4c59fcd01480a12e1c64835b202079091800\nfailed in the hash-use source binding after 30.922 seconds of its unchanged\n2700-second limit. Preserve that failed receipt and both original streams.\nA separate diagnostic then executed all 122 remaining original command units:\n116 exited zero and six exited nonzero. Its outer continuation process completed,\nbut it is not a successful full fail-fast lane. The six failures identify the\nhash-use map, fixed-probability map, joint-consensus map and historical collector\nbinding. The complete original diagnostic package is retained in the\n[follow-up integration record](../../evidence/branch-consolidation-followup-20261114/source-binding-integration-v1/README.md).\n\nIntegrate the reviewed component commits e811c204e039565c06f5bb2cba3543564f510f7b,\n2d9baf313e54e49a4507c5057578e89ddbe7a1b6, 6418023d7f60e6e0c42f08c8726085a2b983757b\nand 341a8b5f751342b51a4aaf9512534853c79d7b5b without rewriting their history.\nThe hash-use map retains 31 inputs and 19 uses; the fixed-probability relation\nretains its four inputs, probability 1/16 and research credit 16u; the joint map\nretains exactly 23 inputs and names the actual committed fixed-probability child.\nThe original 33 hash-use, 16 fixed-probability and 35 joint methods passed.\nOnly the joint revision-identity method adapts its current checkpoint and adds\nthe old revision to its refusals. Independent old-map refusals remain.\n\nFor the retained native collector, require the one original e4abb172 source,\n016ebf3 tree, original context digest and exact 23,639-byte producer as data.\nKeep current collector improvements and all original ZIP/context/report bytes.\nThe original 25 bridge methods remain unchanged and pass with six new boundary\ncontrols; the new corpus dependency-omission/tamper control also passes.\nNo historical native producer is imported, compiled or executed. These results\ndo not authenticate a native build or grant service or quantum qualification.\n\nRefresh only the twelve reviewed existing corpus pins and add the one required\nhistorical raw producer. Preserve the complete historical Markdown text while\nchanging its evidence carrier to .md.original, so its thirteen old relative links\nare not misrepresented as links in the new current location. The repository\nlink checker and all original test thresholds remain unchanged.\n\nThe exact committed successor still needs the original complete source and\nLinux gates and required hosted checks. The newly observed C0 external-evidence\nfailure is independently under review; these four fixes do not claim to repair\nthat different gate. No protected main merge, branch deletion, production\nactivation, deadline relaxation or one-branch completion is declared here.\n".encode())
audit_path.write_bytes(old_audit+"\n## Follow-up source bindings and preserved complete-lane failures\n\nThe published dc42ce4d source failed its original complete Linux\nrepository-truth run in the 58-method lifetime suite, with 57 passes and one\nsource-lock error. The reviewed lifetime successor\n7d8d4c59fcd01480a12e1c64835b202079091800 passed all seven local source gates, but\nits complete original Linux lane then failed in the hash-use source binding:\n31 of the original 33 methods passed, one failed and one errored. That lane\nexited 1 after 30.922 seconds; its original limit remained 2700 seconds.\nBoth failed complete runs and their original source readbacks are preserved.\n\nTo identify the remaining causes, a separate diagnostic executed the 122\nremaining original command units from the unchanged lane, preserving each\nunit's body and arguments. All units ran; 116 exited zero and six exited nonzero\n(units 1, 6, 10, 22, 23 and 107). The original 58 repository mutation controls\nwere among the successful units. The diagnostic continued between failed\nunits and therefore cannot qualify as a complete original lane pass.\nThe [complete diagnostic package and integration record](../../evidence/branch-consolidation-followup-20261114/source-binding-integration-v1/README.md)\nretain the original summary, all 266 original files in the indexed ZIP,\nand the exact source identity before and after.\n\nThe four independently reviewed corrections are:\n\n| Component | Exact scope | Focused result |\n| --- | --- | --- |\n| Hash-use source map, e811c204 | Six changed and 25 unchanged inputs in the fixed 31-path map; original 19 uses and semantic digest retained | Original 33 methods and the existing CI registration control pass; actual reader remains HOLD_NO_GO |\n| Fixed-probability source map, 2d9baf31 | One changed and three unchanged inputs; original probability 1/16, research credit 16u, reader and all original methods retained | Original 16 methods pass; old map is refused; actual reader remains HOLD_NO_GO |\n| Joint-consensus source map, 6418023d | Four changed and 19 unchanged inputs, bound to the actual F1 source commit; no parameter or runtime change | Original 35 methods pass; one current-revision assertion is adapted and old-revision rejection is added; qualification request still exits 3 |\n| Historical collector binding, 341a8b5f | One fixed historical source/tree/producer tuple checked as bounded raw data; current collector and original native evidence remain unchanged | All original 25 methods plus six new boundary methods pass; one new corpus omission/tamper method passes |\n\nThe [hash-use review](../../evidence/hash-use-current-source-review-20261114/README.md),\n[fixed and joint source review](../../evidence/pon-fixed-joint-source-binding-20261114/README.md)\nand [historical collector provenance](../../evidence/branch-consolidation-followup-20261114/native-collector-history-v1/README.md)\nstate their exact coverage. The historical producer is never imported, compiled\nor executed. Its content-address proof does not authenticate a native build.\nThe fixed source contexts identify reviewed inputs; they are not presented as\nthe later commits which store the new mapping metadata.\n\nThe original failed Mac temporary-path control and the two failed staged\nwhitespace checks remain recorded. Canonical temporary-path selection and\nbyte-preserving ZIP carriers corrected those execution/carrier issues without\nweakening readers, tests or the repository checker. The old joint Markdown\ndocument is retained byte-for-byte as .md.original because its thirteen original\nrelative links do not describe its new archival location.\n\nNo Rust runtime source, original service deadline, worker count, probability,\ncost parameter or qualification flag is changed by these four follow-ups.\nThe next complete gate receipts must identify their actual committed successor.\nThe current published C0 external-evidence failure is a separate unresolved\nobservation at this checkpoint and is not claimed as fixed by these changes.\n\n## Later remote and dependency observations\n\nThe original e40d workflow 43551533528 subsequently completed with 15 successful\nand six failed jobs. Its two protocol runs and two architecture-specific service\nruns retained real CONFIRMATION_TARGET failures under the original four-second,\n16-worker contract. The exact-head and prospective protocol receipts both\nrecorded zero accepted confirmations out of one pressure request; all five\nnative processes in each run exited normally. These business acceptance\nfailures are preserved and are not inferred from an outer process exit.\nThe later C0 workflow 43567821538 remains a separate source and observation;\nits ongoing or failed checks cannot be replaced by the predecessor's results.\n\nThe seven then-open Dependabot alerts all concern the main branch's\ncryptography 41.0.7 requirement. The selected candidate uses cryptography 50.0.2,\noutside each of the seven reported vulnerable ranges. Four alerts were high,\ntwo medium and one low. Their original API responses and advisory records are\nretained in the later execution evidence; no alert was manually dismissed or\nclosed. This narrow comparison is not a claim that every dependency, wheel or\nOpenSSL deployment is qualified. The 27 historical registry/yank-query timeouts\nand the unresolved macOS physical-retention result remain open observations.\n\nThe original 908-name archive was confirmed remotely before any merge or branch\ncleanup. Its annotated tag is archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2,\ntag object 9dafd9192e4040fab530958ef71598aaec9265b9, commit\n5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b. That commit retains all 892 original\ntips plus the published C0 candidate as its 893 direct parents. A later execution\narchive may retain this archive and the reviewed successor as separate parents;\nan older tag is never represented as capturing source added afterward.\nAt this source checkpoint, main integration and the single-branch remote result\nare still uncompleted actions.\n".encode())
assert plan_path.read_bytes().startswith(old_plan) and audit_path.read_bytes().startswith(old_audit)
added=[str(p.relative_to(h.src)) for p in ep.iterdir()];assert len(added)==6
stage=sorted(bpaths|{h.manifest,h.plan,"docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md",old_rel,new_rel,ixrel}|set(added))
h.run("stage-exact-combined",["git","add","--",*stage])
actual=set(h.git("diff","--cached","--name-only","--no-renames").decode().splitlines());assert actual==set(stage),(actual,set(stage))
h.run("staged-diff-check",["git","diff","--cached","--check"])
h.run("preflight-staged",["/bin/bash","scripts/project-preflight.sh","--staged"])
focus=h.git("diff","--cached","--",h.manifest,h.plan,"docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md",ixrel);(h.ev/"integration-existing-metadata.patch").write_bytes(focus)
(h.ev/"staged-full.patch").write_bytes(h.git("diff","--cached","--binary","--full-index"))
h.run("normal-integration-commit",["git","commit","-m","Merge reviewed historical collector binding and reconcile current source records"])
after=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
parents=[line[7:].decode() for line in h.git("cat-file","commit",after).split(b"\n") if line.startswith(b"parent ")]
assert parents==[before,b1]
assert not h.git("status","--porcelain=v1","--untracked-files=all")
for path in bpaths:assert h.show(after,path)==h.show(b1,path)
result={"schema":"root-combined-source-bindings-integration-commit-v1","head_before":before,"head_after":after,"tree":tree,"parents":parents,"clean":True,"corpus_pins_updated":12,"required_path_added":raw_path,"carrier_bytes_unchanged":True,"staged_paths":stage,"metadata_patch":{"path":str(h.ev/"integration-existing-metadata.patch"),"bytes":len(focus),"sha256":sha(focus)},"component_controls_reexecuted":False,"original_full_lane_run":False,"remote_mutation":False,"steps":h.steps}
rb=(json.dumps(result,indent=2)+"\n").encode();(h.ev/"summary.json").write_bytes(rb)
print(json.dumps({"path":str(h.ev/"summary.json"),"bytes":len(rb),"sha256":sha(rb),"head":after,"tree":tree,"clean":True}),flush=True)
