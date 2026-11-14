import pathlib,sys,json,hashlib,ast
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
helper=ROOT/"root_merge_helpers.py"
assert hashlib.sha256(helper.read_bytes()).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
sys.path.insert(0,str(ROOT)); import root_merge_helpers as h
h.setup("closed-exec-gate-reviewed-component-merge-v1")
old="1a7afcdb820b051d1e4bfde3d436f96fc050c487"
part="b71b84bbccd9bc403384921802e7edcf2e682242"
assert h.git("rev-parse","HEAD").decode().strip()==old
assert h.git("rev-parse","HEAD^{tree}").decode().strip()=="18c3d20df915f5c31ee38c7037775c61e5c12e3f"
assert not h.git("status","--porcelain","--untracked-files=all").strip()
cp=h.git("cat-file","commit",part)
assert hashlib.sha1(b"commit "+str(len(cp)).encode()+b"\0"+cp).hexdigest()==part
parents=[x[7:].decode() for x in cp.split(b"\n\n",1)[0].splitlines() if x.startswith(b"parent ")]
assert parents==[old] and h.git("rev-parse",part+"^{tree}").decode().strip()=="d4b694838d70191a5206f7cec3253c8f63613e8e"
receipt=pathlib.Path("/private/tmp/chain-M4-owned-process-collector-review-20261114-v1/commit-v3/commit-summary.json")
rb=receipt.read_bytes();assert len(rb)==6541 and hashlib.sha256(rb).hexdigest()=="e6e08399879524b6c19b3aa8e1e5617205b0ea057bea3726cd7ece3811bcc092"
component=json.loads(rb);assert component["head"]==part and len(component["paths"])==20 and component["original14_source_and_ast_preserved"] is True and component["changed_source_linux_tests_executed"] is False
for x in component["paths"]:
 b=h.show(part,x["path"]);assert len(b)==x["bytes"] and hashlib.sha256(b).hexdigest()==x["sha256"] and hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==x["git_blob"]
changed=set(h.git("diff-tree","--no-commit-id","--name-only","-r",old,part).decode().splitlines())
assert changed=={x["path"] for x in component["paths"]}
test="scripts/test_w1_owned_process_collector_v1.py"; collector="scripts/w1_owned_process_collector_v1.py"
def methods(text):
 nodes=[n for n in ast.walk(ast.parse(text)) if isinstance(n,ast.FunctionDef) and n.name.startswith("test_")]
 assert len({n.name for n in nodes})==len(nodes)
 return {n.name:(ast.get_source_segment(text,n),ast.dump(n,include_attributes=False)) for n in nodes}
om=methods(h.show(old,test).decode());nm=methods(h.show(part,test).decode())
assert len(om)==14 and len(nm)==16 and all(nm[n]==v for n,v in om.items())
h.run("preflight-before",["bash","scripts/project-preflight.sh","--audit"])
h.run("normal-component-merge",["git","merge","--no-ff","--no-commit",part])
report="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md"
plan_add="""

### 2026-11-14 original Linux lane and closed exec-gate cleanup

The exact 1a7afc source passed all seven local source gates with identical
before/after identities: 41,653 tracked entries and 3,994,532,888 bytes.
Its original Linux repository-truth command then ran for 496.806 seconds and
failed. The final owned-process collector suite passed 13 of its original
14 methods; the post-fork identity-refusal control received the actual wait4
return code -15 where the original contract requires 125. The original
source-before/source-after identities remained equal. Preserve that full
failed execution, not only its last assertion.

Merge reviewed component b71b84bbccd9bc403384921802e7edcf2e682242. After a
successful close of the never-released exec gate, defer only the first TERM
to that exact root so it can read EOF and return its original refusal code.
Keep the existing KILL escalation, total cleanup grace, descendant signals,
released-root cleanup, actual wait4 status and original command deadline.
The original 14 method bodies remain byte- and AST-identical. Two new
deterministic controls cover the unchanged escalation boundary and the roots
that must not receive this deferral.

At this integration checkpoint the changed collector has syntax/static
validation only. Run the complete 16-method suite and the original full
Linux lane on the committed integration source; do not infer a pass from
the code review. Historical source-object recovery and the external-evidence
lane remain separate validation. The unchanged active Rust implementation
still has original C0 pressure-confirmation failures. No main merge, branch
deletion, production qualification or single-branch completion is declared.
"""
report_add="""

## Original full Linux failure and bounded exec-gate repair

The 1a7afc candidate passed its seven local source gates. Its complete original
Linux repository-truth command subsequently exited 1 after 496.806 seconds,
with identical source identities before and after execution. The last suite
passed 13 of 14 original collector controls. In the post-fork identity-refusal
case, the recorded root exit was -15 rather than the required 125. The
[collector review and complete failed-run package](../audit/20261114-m4-closed-exec-gate/README.md)
retain the raw result and its source identity.

The source review found a concrete ordering race: the parent closes the exec
gate, but cleanup can signal TERM before the child is scheduled to read EOF.
Component b71b84bb adds a successful-close flag and defers only that root's
TERM when exec was never released. The original KILL threshold and total
cleanup grace remain unchanged; descendants, already released roots and
unconfirmed gate closures retain their original signal behavior. No return
code is rewritten. All original 14 test methods are preserved, and two
deterministic signal-order controls are added.

Linux execution of the changed 16-method suite and the complete original lane
is still pending at this source checkpoint. This Python collector correction
does not change the active Rust workload or resolve its four-second pressure
confirmation failure. Local source checks, hosted qualification and the final
remote one-branch result remain distinct observations.
"""
for path,addition in ((h.plan,plan_add),(report,report_add)):
 oldbytes=(h.src/path).read_bytes(); assert addition.strip().encode() not in oldbytes
 (h.src/path).write_bytes(oldbytes+addition.encode())
manifest_before=json.loads((h.src/h.manifest).read_text())
h.refresh_pins([collector,test,h.plan,report])
manifest_after=json.loads((h.src/h.manifest).read_text())
updates={p:{"old":manifest_before["pinned_blobs"][p],"new":v} for p,v in manifest_after["pinned_blobs"].items() if manifest_before["pinned_blobs"].get(p)!=v}
assert set(updates)<={collector,test,h.plan,report}
h.run("stage-root-metadata",["git","add","--",h.manifest,h.plan,report])
index={}
for entry in h.git("ls-files","--stage","-z").split(b"\0"):
 if not entry:continue
 meta,path=entry.split(b"\t",1);mode,oid,stage=meta.split();assert stage==b"0";index[path.decode()]=oid.decode()
assert len(manifest_after["pinned_blobs"])==2600 and all(index[p]==v for p,v in manifest_after["pinned_blobs"].items())
for x in component["paths"]: assert index[x["path"]]==x["git_blob"]
patch=h.git("diff","--cached",part,"--",h.manifest,h.plan,report)
(h.ev/"root-metadata.patch").write_bytes(patch)
h.run("staged-diff-check",["git","diff","--cached","--check"])
h.run("preflight-staged",["bash","scripts/project-preflight.sh","--audit"])
h.run("normal-commit",["git","commit","-m","Merge reviewed closed exec-gate cleanup correction"])
head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
assert h.git("show","-s","--format=%P",head).decode().strip().split()==[old,part]
assert not h.git("status","--porcelain","--untracked-files=all").strip()
for x in component["paths"]:assert hashlib.sha256(h.show(head,x["path"])).hexdigest()==x["sha256"]
r={"schema":"root-reviewed-closed-exec-gate-integration-v1","head_before":old,"head_after":head,"tree":tree,"parents":[old,part],"clean":True,"component_paths_preserved":20,"original14_source_AST_preserved":True,"added_deterministic_controls":2,"linux16_executed":False,"full_linux_pass_claimed":False,"existing_corpus_updates":updates,"all_indexed_corpus_pins_match":2600,"steps":h.steps,"root_metadata_patch":{"path":str(h.ev/"root-metadata.patch"),"bytes":len(patch),"sha256":hashlib.sha256(patch).hexdigest()}}
b=(json.dumps(r,indent=2)+"\n").encode();(h.ev/"summary.json").write_bytes(b)
print(json.dumps({"head":head,"tree":tree,"summary":str(h.ev/"summary.json"),"summary_bytes":len(b),"summary_sha256":hashlib.sha256(b).hexdigest()}),flush=True)
