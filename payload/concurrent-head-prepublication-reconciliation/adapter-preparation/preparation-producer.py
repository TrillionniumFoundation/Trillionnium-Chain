import ast, datetime, difflib, hashlib, json, os, pathlib, stat, sys

def need(condition, message):
    if not condition:
        raise ValueError(message)
def digest(raw):
    return hashlib.sha256(raw).hexdigest()
def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
def fp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def read_fixed(path, length=None, sha256=None):
    p = pathlib.Path(path)
    need(p.is_absolute() and p.parent.resolve(strict=True) == p.parent, "noncanonical input")
    before = p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 1024*1024,
         "regular bounded single-link input required")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        need(fp(os.fstat(stream.fileno())) == fp(before), "input changed before read")
        raw = stream.read(before.st_size + 1)
        need(fp(os.fstat(stream.fileno())) == fp(before), "input changed while reading")
    need(fp(p.lstat()) == fp(before) and len(raw) == before.st_size, "input path/size changed")
    need(length is None or len(raw) == length, "input bytes differ")
    need(sha256 is None or digest(raw) == sha256, "input SHA differs")
    return raw, {"path": str(p), "bytes": len(raw), "sha256": digest(raw), "stat": list(fp(before))}
def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
def apply_exact(text, rules):
    for old, new in rules:
        need(text.count(old) == 1, "replacement is not unique: " + old[:120])
        text = text.replace(old, new, 1)
    return text
def segment_map(text):
    module = ast.parse(text)
    return {node.name: ast.get_source_segment(text, node)
            for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
def assignment_map(text):
    module = ast.parse(text)
    return {node.targets[0].id: ast.get_source_segment(text, node)
            for node in module.body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
def unchanged_functions(old, new, changed, added=()):
    a, b = segment_map(old), segment_map(new)
    need(set(b) == set(a) | set(added), "function roster differs")
    rows = []
    for name in sorted(set(a)-set(changed)):
        need(a[name] == b[name], "unexpected function source change: " + name)
        need(ast.dump(ast.parse(a[name]), include_attributes=False) ==
             ast.dump(ast.parse(b[name]), include_attributes=False), "function AST drift")
        rows.append({"name": name, "bytes": len(a[name].encode()), "sha256": digest(a[name].encode()),
                     "raw_source_identical": True, "ast_identical": True})
    return rows
def unchanged_assignments(old, new, exceptions):
    a, b = assignment_map(old), assignment_map(new)
    need(set(a) == set(b), "top-level assignment roster changed")
    rows = []
    for name in sorted(set(a)-set(exceptions)):
        need(a[name] == b[name], "unexpected top-level assignment change: " + name)
        rows.append({"name": name, "bytes": len(a[name].encode()), "sha256": digest(a[name].encode())})
    return rows
def exact_slice(text, start, end=None):
    need(text.count(start) == 1, "slice start is not unique")
    value = text[text.index(start):]
    if end is not None:
        need(value.count(end) == 1, "slice end is not unique")
        value = value[:value.index(end)]
    return value
def write_new(path, raw):
    p = pathlib.Path(path)
    need(p.parent.resolve(strict=True) == p.parent, "noncanonical output parent")
    fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    actual, info = read_fixed(p, len(raw), digest(raw))
    need(actual == raw, "new output differs")
    return info

started = now()
p = json.loads(sys.argv[1])
producer_raw = sys.argv[2].encode()
need(p["schema"] == "trnm-concurrent-publication-static-preparation-inputs-v1", "input schema")
root = pathlib.Path(p["root"])
out = pathlib.Path(p["output_directory"])
need(root == pathlib.Path("/private/tmp/chain-consolidation-20261114-root"), "fixed ROOT")
need(out == pathlib.Path("/private/tmp/chain-prci-concurrent-publication-preparation-20261114-v1"),
     "fixed output directory")
need(root.resolve(strict=True) == root and out.parent.resolve(strict=True) == out.parent,
     "canonical directories")
need(not out.exists() and not out.is_symlink(), "preparation directory already exists")
original_text, original_raw, original_info = {}, {}, {}
for pin in p["originals"]:
    raw, info = read_fixed(root/pin["filename"], pin["bytes"], pin["sha256"])
    original_raw[pin["name"]] = raw
    original_text[pin["name"]] = raw.decode("utf-8")
    original_info[pin["name"]] = info
hold = json.loads(original_raw["original_hold"])
need(hold["status"] == "HOLD" and hold["push_started"] is False
     and hold["push_exit"] is None and hold["archive"] is None,
     "retained pre-push HOLD boundary differs")
publisher = apply_exact(original_text["publisher"], p["publisher_rules"])
publisher_raw = publisher.encode()
preparer = apply_exact(original_text["preparer"], p["preparer_rules"])
need(preparer.count("__FOLLOWUP_V2_BYTES__") == preparer.count("__FOLLOWUP_V2_SHA__") == 1,
     "exact followup dependency placeholder required")
preparer = preparer.replace("__FOLLOWUP_V2_BYTES__", str(len(publisher_raw)))
preparer = preparer.replace("__FOLLOWUP_V2_SHA__", digest(publisher_raw))
preparer_raw = preparer.encode()
apply = apply_exact(original_text["apply"], p["apply_rules"])
need(apply.count("__PREPARER_V5_SHA__") == 1, "exact preparer dependency placeholder required")
apply = apply.replace("__PREPARER_V5_SHA__", digest(preparer_raw))
apply_raw = apply.encode()
sources = {"publisher": publisher, "preparer": preparer, "apply": apply}
names = {"publisher":"publish_followup_candidate_execution_archive_v2.py",
         "preparer":"prepare_pr847_audit_update_v5.py",
         "apply":"apply_pr847_audit_update_and_ready_v3.py"}
for name, text in sources.items():
    ast.parse(text, filename=str(root/names[name]))
    compile(text, str(root/names[name]), "exec", dont_inherit=True, optimize=0)
    need(not (root/names[name]).exists() and not (root/names[name]).is_symlink(),
         "create-only target already exists")
need("__FOLLOWUP_" not in preparer and "__PREPARER_" not in apply, "unresolved identity placeholder")
function_proofs = {
    "publisher": unchanged_functions(original_text["publisher"], publisher,
                                     {"validate_spec", "main"}, {"bind_expected_remote_heads"}),
    "preparer": unchanged_functions(original_text["preparer"], preparer, {"validate_inputs", "main"}),
    "apply": unchanged_functions(original_text["apply"], apply, {"main"}),
}
assignment_proofs = {
    "publisher": unchanged_assignments(original_text["publisher"], publisher, {"SELF"}),
    "preparer": unchanged_assignments(original_text["preparer"], preparer,
                                       {"SELF", "FOLLOWUP", "FOLLOWUP_BYTES", "FOLLOWUP_SHA"}),
    "apply": unchanged_assignments(original_text["apply"], apply, {"SELF", "PREPARER", "PREPARER_SHA"}),
}
segments = {
    "publisher_push_and_unconditional_readback_tail": (
        original_text["publisher"], publisher,
        '        state["push_started"], state["status"] = True, "UNKNOWN"\n', None),
    "publisher_original_rog_start_chain": (
        original_text["publisher"], publisher,
        '        rog_start = spec["rog_invocation"]["expected_start_head"]\n',
        '        actor = strict_json(run("actor",'),
    "publisher_exact_two_parent_git_creation": (
        original_text["publisher"], publisher,
        '        old_tag_raw = object_bytes("old-archive-tag-object"',
        '        archive_scope = {'),
    "apply_fresh_pr_and_edit_ready_readback_tail": (
        original_text["apply"], apply,
        '        run("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])\n', None),
}
segment_proofs = {}
for name, (old, new, start, end) in segments.items():
    before, after = exact_slice(old,start,end), exact_slice(new,start,end)
    need(before == after, "protected source segment changed: "+name)
    segment_proofs[name] = {"bytes":len(before.encode()), "sha256":digest(before.encode()),
                            "raw_source_identical":True}
# Every nested original publisher helper must retain exact source bytes.
old_main = next(n for n in ast.parse(original_text["publisher"]).body
                if isinstance(n,ast.FunctionDef) and n.name=="main")
new_main = next(n for n in ast.parse(publisher).body
                if isinstance(n,ast.FunctionDef) and n.name=="main")
old_nested = {n.name:ast.get_source_segment(original_text["publisher"],n)
              for n in old_main.body if isinstance(n,ast.FunctionDef)}
new_nested = {n.name:ast.get_source_segment(publisher,n)
              for n in new_main.body if isinstance(n,ast.FunctionDef)}
need(old_nested == new_nested, "publisher nested capture/readback helper drift")
nested_proofs = [{"name":name,"sha256":digest(text.encode()),"bytes":len(text.encode())}
                 for name,text in sorted(old_nested.items())]
# Show that the original finite spec fields gain only expected_remote_head.
def spec_fields(text):
    fn = next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=="validate_spec")
    node = next(n for n in fn.body if isinstance(n,ast.Assign)
                and isinstance(n.targets[0],ast.Name) and n.targets[0].id=="fields")
    return ast.literal_eval(node.value)
old_fields,new_fields=spec_fields(original_text["publisher"]),spec_fields(publisher)
need(new_fields == old_fields|{"expected_remote_head"}, "spec field change is not narrow")
# Stored source/AST proofs do not execute any candidate helper or main.
need("expected_previous_head" not in publisher+preparer, "ambiguous old-head receipt field remains")
for text in (publisher,preparer):
    need("previous_own_published_head" in text and "expected_remote_head" in text,
         "separate C0/remote identities missing")
need(p["reviewed_expected_remote_head"] == "5a4b7fe8de1adce803184f262fd9f704ead1930c",
     "reviewed concurrent input differs")
need(p["reviewed_expected_remote_head"] not in publisher+preparer+apply,
     "remote expected head must be a reviewed spec input, not silently hardcoded")

contract = {
    "schema": "trnm-concurrent-publication-input-contract-not-executable-v1",
    "purpose": "Preparation only. This is not a runnable publication spec or a terminal receipt.",
    "previous_own_published_head": "dc42ce4df5cff79cc61c5addbaf01074b56b06ca",
    "previous_own_published_tree": "9fda17fed2542b2baccaa34585bb00afd699e12b",
    "reviewed_expected_remote_head_for_next_spec": p["reviewed_expected_remote_head"],
    "candidate_head": {"state":"not_supplied_by_root_yet"},
    "candidate_tree": {"state":"not_supplied_by_root_yet"},
    "required_spec_schema":"trnm-followup-candidate-execution-publication-spec-v2",
    "spec_exact_fields": sorted(new_fields),
    "spec_new_field": "expected_remote_head",
    "spec_required_ancestry": [
        ["previous_own_published_head", "expected_remote_head"],
        ["expected_remote_head", "candidate_head"],
        ["previous_own_published_head", "rog_invocation.expected_start_head"],
        ["rog_invocation.expected_start_head", "candidate_head"]],
    "remote_head_need_not_precede_rog_start":True,
    "map": "Original frozen 908-name map with only candidate replaced by the explicit expected remote head; main and other 907 names remain exact.",
    "old_archive_unchanged": {
        "tag":"archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2",
        "tag_oid":"9dafd9192e4040fab530958ef71598aaec9265b9",
        "commit":"5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b"},
    "new_archive_ordered_parents":["old_archive_commit","candidate_head"],
    "new_archive_tag_rule":"archive/execution-receipts-20261114-<candidate_head first 12 hex>-v1",
    "publication_receipt_schema":"trnm-followup-candidate-execution-publication-receipt-v2",
    "archive_scope_schema":"trnm-followup-execution-archive-scope-v2",
    "pr_final_input_schema_unchanged":"trnm-pr847-final-audit-inputs-v1",
    "prepared_summary_schema":"prepared-pr847-audit-update-v5",
    "apply_summary_schema":"trnm-pr847-audit-metadata-ready-v3",
    "required_future_inputs": [
        "root-reviewed final candidate head/tree", "exact seven-source-gate receipt and raw closure",
        "original successful offline-v4 full lane receipt and exact 18-step raw closure",
        "reviewed ROG expected_start_head and actual invocation",
        "frozen execution payload manifest and all stable regular-file originals",
        "new distinct evidence directory and absent archive tag",
        "new publisher SHA bound into the future reviewed spec",
        "confirmed V2 publication raw receipt before PR preparation",
        "separately reviewed final PR inputs, prepared-summary SHA and desired SHA before apply"],
    "executed":False,"remote_writes":False,"source_or_stage_or_git_refs_changed":False,
    "hosted_qualification_granted":False,
}
patches={}
for name,text in sources.items():
    old_name=next(x["filename"] for x in p["originals"] if x["name"]==name)
    patch="".join(difflib.unified_diff(original_text[name].splitlines(keepends=True),
                                     text.splitlines(keepends=True),
                                     fromfile=str(root/old_name),tofile=str(root/names[name])))
    need(bool(patch),"empty change patch")
    patches[name]=patch.encode()
combined=b"".join(patches[k] for k in ("publisher","preparer","apply"))
outputs={}
os.umask(0o077)
out.mkdir(mode=0o700,exist_ok=False)
outputs["preparation-producer.py"]=write_new(out/"preparation-producer.py",producer_raw)
outputs["preparation-inputs.json"]=write_new(out/"preparation-inputs.json",encode(p))
for name,text in sources.items():
    outputs[name]=write_new(root/names[name],text.encode())
for name,data in patches.items():
    outputs[name+"-precise.patch"]=write_new(out/(name+"-precise.patch"),data)
outputs["all-three-precise.patch"]=write_new(out/"all-three-precise.patch",combined)
outputs["input-contract-v2.json"]=write_new(out/"input-contract-v2.json",encode(contract))
old_after={}
for pin in p["originals"]:
    raw,info=read_fixed(root/pin["filename"],pin["bytes"],pin["sha256"])
    need(info==original_info[pin["name"]],"original identity changed during preparation")
    old_after[pin["name"]]=info
proof={
    "schema":"trnm-concurrent-publication-static-identity-proof-v1",
    "started_at":started,"finished_at":now(),
    "scope":"Static creation and syntax/AST/source identity comparison only; no candidate module import or execution.",
    "syntax_compiled_in_memory":list(names.values()),
    "originals_before":original_info,"originals_after":old_after,
    "unchanged_top_level_functions":function_proofs,
    "unchanged_top_level_assignments":assignment_proofs,
    "unchanged_nested_publisher_helpers":nested_proofs,
    "unchanged_protected_source_segments":segment_proofs,
    "exact_replacement_rule_counts":{k:len(p[k+"_rules"]) for k in ("publisher","preparer","apply")},
    "new_publisher_function":"bind_expected_remote_heads",
    "spec_field_added_only":"expected_remote_head",
    "original_template_retained_byte_exact":True,
    "original_pre_push_hold_retained_byte_exact":True,
    "previous_own_published_head_not_relabelled":True,
    "remote_expected_head_is_explicit_reviewed_spec_input":True,
    "new_candidate_head_not_fabricated":True,
    "base_to_rog_start_chain_retained_byte_exact":True,
    "new_remote_to_rog_start_requirement_added":False,
    "publisher_helpers_or_main_executed":False,
    "preparer_helpers_or_main_executed":False,"apply_helpers_or_main_executed":False,
    "git_commands_executed":False,"network_actions_executed":False,
    "tests_or_native_lanes_run":False,
    "source_or_stage_or_git_refs_changed":False,
    "qualification_granted":False,"outputs":outputs,
}
proof_info=write_new(out/"static-identity-proof.json",encode(proof))
outputs["static-identity-proof.json"]=proof_info
readme=(
"# Concurrent remote advance: prepared publisher and PR adapters\n\n"
"Status: PREPARED ONLY. The three new programs were syntax-compiled in memory and compared with "
"their fixed predecessors. None was imported or executed. No Git, network, PR, source-tree, stage or "
"ref operation was performed by this preparation.\n\n"
"## Bound identities\n\n"
"- Previous own published C0 remains dc42ce4df5cff79cc61c5addbaf01074b56b06ca with its original archive.\n"
"- The reviewed remote advance for the next explicit spec is 5a4b7fe8de1adce803184f262fd9f704ead1930c.\n"
"- The final integrated candidate head/tree and final gate receipts have not been supplied here.\n"
"- V2 requires C0 → reviewed remote → final candidate and separately C0 → actual ROG start → final "
"candidate. It does not require the reviewed remote advance to be an ancestor of the ROG start.\n\n"
"## Preserved boundaries\n\n"
"The original_frozen_state function, original archive pins, seven gate and 18-step ROG validators, "
"full two-ref pre-push hook, 1800-second single normal atomic push, unconditional readbacks, "
"source-after logic, and all scope/qualification flags retain their original source. The C0 map "
"keeps its truthful original filename; a separate reviewed-remote map binds only the candidate ref. "
"Both maps and separate C0/remote fields enter the V2 archive metadata and PR validation.\n\n"
"The PR input manifest schema remains v1 because its five input fields are unchanged. It must point "
"to a V2 publication spec/confirmed receipt and new fixed producer. Prepared output is v5 and the "
"apply receipt is v3. The original template v3 is unchanged. The apply route remains exact metadata "
"edit, readback, mark-ready if needed, and final readback; no merge or CI action is added.\n\n"
"## Review artifacts\n\n"
"all-three-precise.patch contains the complete changes. static-identity-proof.json lists original "
"and new identities, exact unchanged functions and source segments. input-contract-v2.json is "
"explicitly not executable and contains no invented final candidate or successful receipt. "
"The original V1 pre-push HOLD remains unchanged, including its status and SHA.\n\n"
"Runtime validation, eventual publication and PR changes require separate root review and execution. "
"No hosted or protocol pass is inferred from this static preparation.\n")
outputs["README.md"]=write_new(out/"README.md",readme.encode())
index={"schema":"trnm-concurrent-publication-preparation-index-v1","created_at":now(),
       "files":[{"label":name,"path":info["path"],"bytes":info["bytes"],"sha256":info["sha256"]}
                for name,info in sorted(outputs.items())],"self_excluded":"EVIDENCE_INDEX.json"}
index_info=write_new(out/"EVIDENCE_INDEX.json",encode(index))
summary={
    "schema":"trnm-concurrent-publication-preparation-summary-v1","status":"PREPARED_NOT_EXECUTED",
    "started_at":started,"finished_at":now(),
    "new_scripts":{k:outputs[k] for k in ("publisher","preparer","apply")},
    "combined_patch":outputs["all-three-precise.patch"],"static_identity_proof":proof_info,
    "index":index_info,"template_unchanged":original_info["template"],
    "original_hold_unchanged":original_info["original_hold"],
    "remote_write_performed":False,"git_command_performed":False,
    "source_stage_or_refs_changed":False,"tests_or_native_lanes_run":False,
    "review_required_before_execution":True}
summary_info=write_new(out/"summary.json",encode(summary))
print(json.dumps({"status":summary["status"],"summary":summary_info,
                  "scripts":{k:{q:outputs[k][q] for q in ("path","bytes","sha256")}
                             for k in ("publisher","preparer","apply")},
                  "patch":{q:outputs["all-three-precise.patch"][q] for q in ("path","bytes","sha256")},
                  "proof":{q:proof_info[q] for q in ("path","bytes","sha256")}},sort_keys=True),flush=True)
