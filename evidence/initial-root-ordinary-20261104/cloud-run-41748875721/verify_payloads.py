#!/usr/bin/env python3
"""Verify this evidence bundle as data only. Never extract or execute ZIP contents."""
from pathlib import Path, PurePosixPath
import base64, collections, csv, hashlib, io, json, re, shlex, stat, sys, zipfile
BASE=Path(__file__).resolve().parent
H='4c46eca89a006616e9240d983c66919071f79b41'
M='e0f831d0af21cc9eea69b5ec84788ef66e0b025c'
B='2e72a989d001cf51bd0aed0e1401526e45db31f1'
TREE='a32c5e3b169370b1c923bb9a6ef7094a3d3ef041'
S='01404de030c0d560e32a4b86620cea027878d2df'
WORKFLOW_SHA='af6f66151bba9dc3d7d58218b2dbf84b570e75cd2acc2eec86b165200f8d5983'
BUILD=['cargo','+1.95.0','test','--locked','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--no-run','--message-format=json']
CPU=['store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner','store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator']
LIFETIME=['ingress::public_v2::tests::public_loop_exit_records_lifetime_before_internal_stop','ingress::public_v2::tests::public_loop_exit_records_external_stop_after_signed_read']
ORIGINALS=[
(13285312643,'ubuntu-24.04','head',126308679902,302305,'db3c36eeb85f3d25d4c3c265c12e5c19233722388d25126fc1970d4ee6da40a0'),
(13285398555,'ubuntu-24.04','prospective-merge',126308679928,302532,'0ed10048afd1a9eb5a6c985972f544e31f78318d3d98b92f290913e6b68b708a'),
(13285472881,'ubuntu-24.04-arm','head',126308679850,302055,'528fdcd6627a7d73fdc5c9e6a8a0a0346bd34e27bf1071eb7542a60ebb800ca4'),
(13285614471,'ubuntu-24.04-arm','prospective-merge',126308679673,302200,'0723ed3296af00718bc2d84f7575a3adbb75be11aefa49c170814c2f561a5e61')]
def need(ok,message):
 if not ok:raise AssertionError(message)
def sha(b):return hashlib.sha256(b).hexdigest()
def get(name,limit=512*1024):
 need(isinstance(name,str) and PurePosixPath(name).name==name and name not in ('.','..'),'unsafe outer path')
 p=BASE/name
 need(p.is_file() and not p.is_symlink(),'outer file type '+name)
 data=p.read_bytes();need(len(data)<=limit,'outer file limit '+name);return data
def check_file(f):
 data=get(f['path']);need(len(data)==f['size'] and sha(data)==f['sha256'],'outer file identity '+f['path'])
 if 'git_blob_sha' in f:need(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==f['git_blob_sha'],'outer Git blob '+f['path'])
 return data
def tsv(text):return list(csv.DictReader(io.StringIO(text),delimiter='\t'))
def registry(text):
 names=re.findall(r'^([A-Za-z_][A-Za-z0-9_:]*): test$',text,re.M)
 need(names and len(names)==len(set(names)),'registry duplicates');return set(names)
def objects(text):
 result=[]
 for line in text.splitlines():
  pos=line.find('{')
  if pos<0:continue
  try:value=json.loads(line[pos:])
  except json.JSONDecodeError:continue
  if isinstance(value,dict):result.append(value)
 return result
def resources(text):
 match=re.search(r'^\s*Command being timed: "(.*)"\s*$',text,re.M)
 need(match is not None and re.search(r'^\s*Exit status: 0$',text,re.M),'native command/time exit')
 return shlex.split(match.group(1))

SEMANTIC_GROUPS=json.loads("[{\"crate\":\"m06\",\"group\":\"full-root-arithmetic\",\"prefix\":\"pon_commitment::full_root_arithmetic_tests::\",\"expected_count\":7,\"tests\":[\"pon_commitment::full_root_arithmetic_tests::arithmetic_parent_keeps_execution_results_cancellation_and_unlocked_callbacks\",\"pon_commitment::full_root_arithmetic_tests::arithmetic_prefix_keeps_two_signed_appends_and_cancelled_successor_rollback\",\"pon_commitment::full_root_arithmetic_tests::configured_root_preserves_real_pq_and_growth_validation_on_warm_arithmetic\",\"pon_commitment::full_root_arithmetic_tests::configured_root_rechecks_original_grammar_context_and_current_values\",\"pon_commitment::full_root_arithmetic_tests::full_root_arithmetic_contention_poison_and_retention_refusal_keep_the_original_root\",\"pon_commitment::full_root_arithmetic_tests::full_root_arithmetic_preserves_forks_charges_and_error_order\",\"pon_commitment::full_root_arithmetic_tests::large_parent_full_root_arithmetic_rechecks_all_bytes_without_a_snapshot\"]},{\"crate\":\"m06\",\"group\":\"canonical-ascii\",\"expected_count\":7,\"tests\":[\"pon_executor::root_arithmetic_tests::canonical_ascii_guard_matches_exhaustive_bytes_pairs_and_borrow_chains\",\"pon_executor::root_arithmetic_tests::canonical_ascii_keeps_original_serde_bytes_and_vec_capacities\",\"pon_executor::root_arithmetic_tests::canonical_ascii_into_keeps_reused_capacity_and_failed_input_untouched\",\"pon_executor::root_arithmetic_tests::canonical_ascii_commitment_keeps_late_grammar_before_wire_and_cache_errors\",\"pon_executor::root_arithmetic_tests::arithmetic_root_ascii_encoding_matches_independent_serde_reference\",\"pon_executor::root_arithmetic_tests::arithmetic_root_preserves_complete_grammar_before_all_wire_limits\",\"pon_commitment::bounded_encoding_tests::canonical_ascii_fast_encoding_keeps_direct_serde_budget_decisions_and_charges\"]},{\"crate\":\"m06\",\"group\":\"immutable-root-projection\",\"prefix\":\"pon_executor::root_projection::tests::\",\"expected_count\":4,\"tests\":[\"pon_executor::root_projection::tests::complete_projection_empty_and_all_account_states_keep_original_roots\",\"pon_executor::root_projection::tests::complete_projection_large_current_input_keeps_exact_roots_and_hash_only_bound\",\"pon_executor::root_projection::tests::non_account_projection_requires_exact_current_bytes_and_key_set\",\"pon_executor::root_projection::tests::projection_keeps_complete_grammar_before_wire_limits_and_refuses_retention_only\"]},{\"crate\":\"node\",\"group\":\"complete-projection-current-input\",\"expected_count\":2,\"tests\":[\"store::native_authenticated::arithmetic_cache::large_input_tests::large_complete_inputs_keep_actual_accounts_conservation_and_context_checks\",\"store::native_authenticated::arithmetic_cache::large_input_tests::warmed_large_arithmetic_keeps_actual_sql_rows_cancellation_and_cold_reopen\"]},{\"crate\":\"node\",\"group\":\"sql-canonical-string\",\"expected_count\":2,\"tests\":[\"store::canonical_json::tests::native_string_decoder_matches_serde_at_every_ascii_position_and_boundary\",\"store::canonical_json::tests::native_string_decoder_preserves_every_nonfast_input_for_original_serde\"]},{\"crate\":\"node\",\"group\":\"canonical-packet\",\"expected_count\":4,\"tests\":[\"ingress::public_v3::tests::canonical_packet_decoder_hex_blocks_match_scalar_at_every_alignment\",\"ingress::public_v3::tests::canonical_packet_decoder_matches_streamed_parent_for_every_single_byte_mutation\",\"ingress::public_v3::tests::canonical_packet_decoder_preserves_empty_maximum_and_structural_refusals\",\"ingress::public_v3::tests::canonical_streaming_rejects_escaped_packets_and_extra_fields\"]},{\"crate\":\"node\",\"group\":\"operation-full-root\",\"expected_count\":6,\"tests\":[\"store::native_authenticated::arithmetic_cache::operation_root_tests::one_use_calculation_keeps_complete_results_and_actual_hash_counts\",\"store::native_authenticated::arithmetic_cache::operation_root_tests::calculation_refuses_other_state_objects_and_all_settings_bindings\",\"store::native_authenticated::arithmetic_cache::operation_root_tests::failed_input_and_original_early_hits_clear_the_out_calculation\",\"store::native_authenticated::arithmetic_cache::operation_root_tests::original_account_and_conservation_errors_keep_the_full_root_callback_order\",\"store::native_authenticated::arithmetic_cache::operation_root_tests::persisted_root_and_missing_record_refusals_still_precede_later_callbacks\",\"store::native_authenticated::arithmetic_cache::operation_root_tests::later_sql_record_reads_and_cancellation_remain_mandatory_with_a_calculation\"]},{\"crate\":\"node\",\"group\":\"reorg-tail\",\"prefix\":\"store::reorg_readback_tests::\",\"expected_count\":6,\"tests\":[\"store::reorg_readback_tests::final_callback_writes_fail_with_or_without_a_consumed_graph_hit\",\"store::reorg_readback_tests::no_scope_keeps_full_graphs_and_rejects_transaction_replacement_with_cancel_source\",\"store::reorg_readback_tests::non_genesis_common_ancestor_keeps_every_cut_and_publication_on_cold_reopen\",\"store::reorg_readback_tests::original_write_lock_blocks_foreign_writer_and_no_scope_survives_commit\",\"store::reorg_readback_tests::prehit_write_cannot_restamp_and_callback_errors_keep_original_precedence\",\"store::reorg_readback_tests::real_reorg_tail_keeps_rows_events_fault_recovery_and_cold_reopen\"]},{\"crate\":\"node\",\"group\":\"current-sql-root\",\"expected_count\":1,\"tests\":[\"store::detached_admission::tests::large_parent_root_arithmetic_keeps_current_sql_and_original_read_checkpoints\"]},{\"crate\":\"node\",\"group\":\"prepared-current-history\",\"expected_count\":3,\"tests\":[\"store::historical_commitment_tests::legacy_prepared_history_reads_observe_current_rows_writes_and_rollback\",\"store::historical_commitment_tests::legacy_prepared_history_reads_reprepare_after_schema_and_authorizer_changes\",\"store::historical_commitment_tests::actual_foreign_snapshot_delta_and_root_damage_preserve_original_failures\"]},{\"crate\":\"node\",\"group\":\"postwrite-readback\",\"prefix\":\"store::native_authenticated::post_write_readback::tests::\",\"expected_count\":15,\"tests\":[\"store::native_authenticated::post_write_readback::tests::actual_admission_reuses_graphs_and_keeps_original_state_packet_and_reopen\",\"store::native_authenticated::post_write_readback::tests::actual_original_writer_excludes_an_independent_database_writer\",\"store::native_authenticated::post_write_readback::tests::actual_stored_graph_damage_is_reread_after_a_receipt\",\"store::native_authenticated::post_write_readback::tests::another_actual_connection_cannot_use_the_original_write_scope\",\"store::native_authenticated::post_write_readback::tests::changed_schema_or_namespace_never_creates_a_new_scope\",\"store::native_authenticated::post_write_readback::tests::consumed_active_reader_refuses_a_last_callback_write\",\"store::native_authenticated::post_write_readback::tests::current_complete_state_remains_mandatory_on_a_graph_hit\",\"store::native_authenticated::post_write_readback::tests::fences::final_callback_after_a_first_match_falls_back_to_the_actual_original_graph\",\"store::native_authenticated::post_write_readback::tests::fences::four_original_roles_are_bounded_and_a_fifth_root_never_becomes_a_receipt\",\"store::native_authenticated::post_write_readback::tests::fences::trusted_reset_exposes_preexisting_catalog_and_prepared_vm_divergence\",\"store::native_authenticated::post_write_readback::tests::first_graph_callback_write_cannot_mint_a_result_or_reenable_it\",\"store::native_authenticated::post_write_readback::tests::no_row_writes_and_reversed_ddl_disable_reuse_without_resetting_the_scope\",\"store::native_authenticated::post_write_readback::tests::original_cancellation_before_and_after_a_match_is_preserved\",\"store::native_authenticated::post_write_readback::tests::original_transaction_owner_refuses_commit_begin_and_savepoint_aba\",\"store::native_authenticated::post_write_readback::tests::prepare_only_schema_reset_preserves_the_normalized_writer\"]},{\"crate\":\"node\",\"group\":\"initial-history-root\",\"prefix\":\"store::native_authenticated::initial_root_tests::\",\"expected_count\":7,\"tests\":[\"store::native_authenticated::initial_root_tests::first_record_failures_preserve_root_and_progress_error_order_without_a_result\",\"store::native_authenticated::initial_root_tests::history_cancellation_keeps_every_original_checkpoint_and_discards_unused_roots\",\"store::native_authenticated::initial_root_tests::history_initial_root_reuse_keeps_results_progress_and_actual_hash_counts\",\"store::native_authenticated::initial_root_tests::history_rereads_callback_changed_sql_fields_types_records_and_snapshot_bytes\",\"store::native_authenticated::initial_root_tests::history_still_checks_complete_commitment_and_actual_account_nodes\",\"store::native_authenticated::initial_root_tests::initial_root_does_not_replace_actual_snapshot_root_account_or_conservation_checks\",\"store::native_authenticated::initial_root_tests::initial_root_requires_same_settings_and_never_reissues_a_consumed_value\"]}]")
PROTOCOL_TESTS=json.loads("[\"pon_wire::state_root_arithmetic::tests::complete_inputs_match_original_across_random_changes_and_reordered_rows\",\"pon_wire::state_root_arithmetic::tests::failed_complete_input_never_publishes_a_projection_or_partial_material\",\"pon_wire::state_root_arithmetic::tests::incomplete_sources_and_original_wire_limits_publish_no_partial_material\",\"pon_wire::state_root_arithmetic::tests::large_values_reuse_only_identical_complete_leaf_lists\",\"pon_wire::state_root_arithmetic::tests::opaque_projection_preserves_current_inputs_empty_subsets_and_payload_edges\",\"pon_wire::state_root_arithmetic::tests::projection_payload_limit_uses_hash_tuples_at_the_two_mib_boundary\",\"pon_wire::state_root_arithmetic::tests::retention_refusal_and_eviction_preserve_root_and_existing_budget\",\"pon_wire::state_root_arithmetic::tests::single_partition_forks_collision_checks_and_replacement_use_original_roots\"]")
def main():
 index=json.loads(get('index.json'))
 need(index['schema']=='chain-initial-root-four-zip-archive-v1' and index['run_id']==41748875721,'archive index')
 need(index['head']==H and index['merge']==M and index['base']==B and index['source_tree']==TREE and index['harness']==S,'archive pins')
 need(len(index['artifacts'])==4,'artifact denominator')
 for f in index['data_files']:check_file(f)
 need(sha(get('audit_artifacts_v1.py'))=='2debe9b9954ed4fda4186bfe43a3a99883c8a6d78d1eabf736ba2f3d2042942f','unchanged original audit reader')
 need(sha(get('FOUR_LANE_INDEPENDENT_AUDIT_V1.json'))=='7b21e65999fb7b1c646fe1fcb1ae57958c8a5435a30f14811cccf4fa67d89d05','unchanged original audit summary')
 summary=json.loads(get('FOUR_LANE_INDEPENDENT_AUDIT_V1.json'))
 need(summary['result']=='PASS' and summary['counts']['passed']==summary['counts']['actual_native_total']==304 and summary['counts']['failed']==summary['counts']['ignored']==0,'original complete audit result')
 completion=json.loads(get('AUDIT_V1_COMPLETION_RECEIPT.json'))
 need(completion['result']=='PASS' and completion['report']['sha256']==sha(get('FOUR_LANE_INDEPENDENT_AUDIT_V1.json')),'original audit completion')
 status=json.loads(get('ORIGINAL_AUDIT_PROCESS_STATUS.json'))
 need(status['job_id']=='1a1a421b0e1-96a-78a6' and status['state']=='succeeded' and status['exit_code']==0 and status['output_complete'] is True and status['timed_out'] is False,'original audit process terminal')
 need(get('ORIGINAL_AUDIT_STDERR.txt')==b'','original auditor stderr')
 inp=json.loads(get('audit-input-v1.json'));run=inp['run'];git=inp['git_objects']
 need(run['id']==41748875721 and run['run_attempt']==1 and run['event']=='push' and run['head_sha']==S and run['status']=='completed' and run['conclusion']=='success','official run metadata')
 need(git['H']['sha']==H and git['H']['tree']['sha']==TREE and git['M']['sha']==M and git['M']['tree']['sha']==TREE,'official source trees')
 need([p['sha'] for p in git['M']['parents']]==[B,H] and git['S']['sha']==S and [p['sha'] for p in git['S']['parents']]==[H],'actual merge and harness parents')
 jobs={j['id']:j for j in inp['jobs']['jobs']};need(len(jobs)==4,'official jobs')
 expected_selected=[(g['crate'],g['group'],s) for g in SEMANTIC_GROUPS for s in g['tests']]
 need(len(expected_selected)==64,'literal original/additive semantic controls')
 lanes=[];credits=[]
 for entry,original in zip(index['artifacts'],ORIGINALS):
  artifact_id,runner,kind,job_id,size,digest=original
  need(entry['artifact_id']==artifact_id and entry['runner']==runner and entry['source_kind']==kind,'artifact lane mapping')
  official=entry['official_metadata']
  need(official['id']==artifact_id and official['size_in_bytes']==size and official['digest']=='sha256:'+digest and not official['expired'],'official ZIP metadata')
  need(official['workflow_run']['id']==41748875721 and official['workflow_run']['head_sha']==S,'official ZIP run')
  need(official['name']=='pinned-initial-root-normal-'+runner+'-'+kind+'-'+H+'-1','official artifact name')
  need(jobs[job_id]['status']=='completed' and jobs[job_id]['conclusion']=='success' and jobs[job_id]['run_id']==41748875721,'official lane job terminal')
  need(runner in jobs[job_id]['name'] and kind in jobs[job_id]['name'],'official job name')
  stream=bytearray();chunk_names=set()
  for f in entry['chunks']:
   need(f['path'] not in chunk_names,'duplicate chunk');chunk_names.add(f['path'])
   encoded=check_file(f);need(len(encoded)<=48*1024,'48KiB JSON chunk cap')
   chunk=json.loads(encoded);raw=base64.b64decode(chunk['data_base64'],validate=True)
   need(chunk['artifact_id']==artifact_id and chunk['offset']==len(stream)==f['raw_offset'],'chunk exact offset')
   need(len(raw)==chunk['size']==f['raw_size'] and sha(raw)==chunk['sha256']==f['raw_sha256'],'chunk raw identity')
   stream.extend(raw)
  zipped=bytes(stream);need(len(zipped)==size and sha(zipped)==digest,'reconstructed complete official ZIP')
  files={}
  with zipfile.ZipFile(io.BytesIO(zipped)) as archive:
   infos=archive.infolist()
   need(len(infos)<4096 and sum(i.file_size for i in infos)<256*1024*1024,'bounded ZIP')
   names=set()
   for info in infos:
    p=PurePosixPath(info.filename)
    need(not p.is_absolute() and '..' not in p.parts and '\\' not in info.filename and info.filename not in names,'safe unique ZIP name');names.add(info.filename)
    need(stat.S_IFMT(info.external_attr>>16) in (0,stat.S_IFREG,stat.S_IFDIR),'non-link ZIP members')
    if info.is_dir():continue
    raw=archive.read(info)
    need(len(raw)==info.file_size and not raw.startswith(b'\x7fELF'),'member length/ELF scope')
    files[info.filename]=raw
  need(len(files)==433,'all original ZIP member denominator')
  def text(name):return files[name].decode('utf-8')
  def data(name):return json.loads(text(name))
  before=data('source-before.json');after=data('source-after.json');tested=H if kind=='head' else M
  need(before==after and before['tested_commit']==tested and before['tested_tree']==TREE and before['kind']==kind and before['candidate']==H,'unchanged exact source')
  need(before['tracked_worktree_verified'] is True and before['tracked_entries']==6862 and before['tracked_bytes']==784979280 and before['tests_executed_by_identity_check'] is False,'source byte verification receipt')
  need((kind=='head' and before['base'] is None and before['prospective_merge'] is None) or (kind=='prospective-merge' and before['base']==B and before['prospective_merge']==M),'source branch identity')
  wh=data('workflow-harness.json')
  need(wh['harness_commit']==wh['github_workflow_sha']==S and wh['harness_parents']==[H] and wh['harness_workflow_sha256']==WORKFLOW_SHA,'pinned harness')
  need(wh['harness_delta']==['A\t.github/workflows/pon-pinned-history-initial-root-normal.yml'],'only added normal harness')
  need(wh['tested_commit']==tested and wh['tested_tree']==wh['candidate_tree']==wh['expected_prospective_merge_tree']==TREE,'harness tested product tree')
  need(wh['candidate']==H and wh['base']==B and wh['prospective_merge']==M,'harness source pins')
  if kind=='prospective-merge':need(wh['prospective_merge_tree']==TREE and wh['prospective_merge_parents']==[B,H],'actual merge original proof')
  cmd=data('build-command.json');env=cmd['environment']
  need(cmd['argv']==BUILD and resources(text('build.resources.txt'))==BUILD,'original complete workspace build')
  need(env['CI']=='true' and env['CARGO_BUILD_JOBS']=='2' and env['CARGO_INCREMENTAL']=='0' and env['RUST_TEST_THREADS']=='1','original build environment')
  for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTC_BOOTSTRAP','RUSTDOC','RUSTDOCFLAGS','CARGO_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTDOC','CARGO_BUILD_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER']:need(env.get(k) is None,'forbidden build override '+k)
  need(not any(k.startswith('CARGO_PROFILE_') for k in env),'profile override')
  need(not any(v for k,v in env.items() if k.startswith('CARGO_TARGET_') and k!='CARGO_TARGET_DIR'),'target override')
  need(env['TRNM_PQ_OPENSSL_VERSION']=='3.5.9' and env['OPENSSL_STATIC']=='1','pinned PQ provider')
  rows=[json.loads(s) for s in text('build.jsonl').splitlines() if s.strip()]
  need([r for r in rows if r.get('reason')=='build-finished']==[{'reason':'build-finished','success':True}],'original Cargo build finished')
  for name in ['build.exit','build-input-check.exit','build-artifact-check.exit','binary-before.exit','binary-after.exit','m06-binary-after.exit','test-step.exit','semantic-controls/registry-check.exit','semantic-controls/semantic-step.exit','protocol-controls/registry.exit']:need(text(name).strip()=='0','recorded step exit '+name)
  binaries={}
  for crate,package,targetname,opt,features,receipt_name,hashnames in [
   ('node','trnm-pon-node','trnm_pon_node','3',['default','pq-native-openssl'],'binary.json',['binary.sha256','binary-before.sha256','binary-after.sha256','semantic-controls/node-binary-before.sha256']),
   ('m06','trnm-mvcc-fee','trnm_mvcc_fee','1',['default','pq-native-openssl'],'m06-binary.json',['m06-binary.sha256','m06-binary-after.sha256','semantic-controls/m06-binary-before.sha256']),
   ('protocol','trnm-protocol','trnm_protocol','3',[],'protocol-controls/binary.json',['protocol-controls/binary-before.sha256','protocol-controls/binary-after.sha256'])]:
   receipt=data(receipt_name);a=receipt['artifact'];exe=a['executable'];cwd=str(PurePosixPath(a['manifest_path']).parent)
   actual=[r for r in rows if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')==targetname and r['target'].get('kind')==['lib'] and r.get('profile',{}).get('test') is True and r.get('executable')]
   need(actual==[a] and a['features']==features,'unique original same-build test ELF '+crate)
   need(a['profile']=={'opt_level':opt,'debuginfo':2,'debug_assertions':True,'overflow_checks':True,'test':True},'original test profile '+crate)
   need(PurePosixPath(exe).parent==PurePosixPath(env['CARGO_TARGET_DIR'])/'debug/deps' and cwd.endswith('/trillionnium/crates/'+package) and a['target']['src_path']==cwd+'/src/lib.rs','actual artifact path '+crate)
   need(all(text(n).strip()==receipt['sha256']+'  '+exe for n in hashnames),'recorded same ELF before/after '+crate)
   if crate!='node':need(receipt['package_cwd']==cwd,'package cwd receipt '+crate)
   if crate=='m06':need(receipt['dependency_artifact'] in rows and receipt['dependency_artifact']['profile']['opt_level']=='1' and receipt['dependency_artifact']['features']==features,'same-build M06 dependency')
   binaries[crate]={'executable':exe,'cwd':cwd,'sha256':receipt['sha256'],'profile':a['profile'],'features':features}
  expected_arch='aarch64-unknown-linux-gnu' if runner.endswith('-arm') else 'x86_64-unknown-linux-gnu'
  need('rustc 1.95.0' in text('rustc.txt') and 'host: '+expected_arch in text('rustc.txt') and 'cargo 1.95.0' in text('cargo.txt'),'actual architecture and toolchain')
  executions=[]
  def native(crate,group,selector,prefix,cwd_file=None):
   log=text(prefix+'.log')
   found=re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$',log,re.M)
   need(len(found)==1 and found[0][:5]==('ok','1','0','0','0'),'actual one native pass '+selector)
   need(len(re.findall(r'^running 1 test$',log,re.M))==1 and len(re.findall(r'^test '+re.escape(selector)+r' \.\.\. ',log,re.M))==1,'actual named denominator '+selector)
   need(bool(re.search(r'^test '+re.escape(selector)+r' \.\.\. ok$',log,re.M) or re.search(r'\nok\n\s*\ntest result: ok\.',log)),'actual native ok '+selector)
   need(data(prefix+'.execution.json')=={'executed_tests':1,'result':'PASS','scope':'named-libtest-execution-only','test':selector} and files[prefix+'.execution.stderr']==b'','named reader result '+selector)
   need(resources(text(prefix+'.resources.txt'))==[binaries[crate]['executable'],selector,'--exact','--nocapture','--test-threads=1'],'actual exact native command '+selector)
   if cwd_file:need(text(cwd_file).strip()==binaries[crate]['cwd'],'actual package cwd '+selector)
   executions.append({'crate':crate,'group':group,'selector':selector,'passed':1,'failed':0,'ignored':0,'measured':0})
   return log
  original=tsv(text('test-exits.tsv'))
  need(original==[{'selector':s,'native_exit':'0','log_exit':'0','reader_exit':'0'} for s in CPU+LIFETIME],'CPU/lifetime original exits')
  for position,selector in enumerate(CPU+LIFETIME):
   log=native('node','cpu' if position<2 else 'lifetime',selector,selector.rsplit('::',1)[-1],'test-cwd.txt')
   if position>=2:continue
   values=objects(log)
   diagnostics=[v for v in values if v.get('schema')=='native-large-parent-original-dispatch-diagnostic-v1']
   parities=[v for v in values if v.get('schema')=='native-large-parent-schedule-parity-v1']
   expected_backends=[False,True] if position==0 else [True]
   need([v['authenticated_backend'] for v in diagnostics]==expected_backends and [v['authenticated_backend'] for v in parities]==expected_backends,'original CPU backend count')
   for diagnostic,parity in zip(diagnostics,parities):
    before_flow=diagnostic['actual_cpu_flow_before'];after_flow=diagnostic['actual_cpu_flow_after']
    need(before_flow['initial_credit_ns']==after_flow['initial_credit_ns']==2_000_000_000,'explicit original initial CPU credit')
    need(before_flow['paid_cpu_debit_ns']==before_flow['credited_refill_ns']==0 and before_flow['remaining_paid_credit_ns']==2_000_000_000,'original clean CPU balance')
    need(after_flow['initial_credit_ns']+after_flow['credited_refill_ns']-after_flow['paid_cpu_debit_ns']==after_flow['remaining_paid_credit_ns'],'independent CPU balance')
    need(after_flow['remaining_paid_credit_ns']>0 and after_flow['balance_identity_verified'] is True and after_flow['live_owners']==after_flow['booked_reservation_ns']==after_flow['unsettled_known_live_cpu_ns']==0,'complete positive settled CPU')
    need(after_flow['remaining_paid_credit_ns']==after_flow['stored_credit_ns']==diagnostic['cpu_budget_after']['stored_credit_ns'],'CPU budget/flow same balance')
    for point in ['before','after']:
     budget=diagnostic['cpu_budget_'+point]
     need({k:budget[k] for k in ['burst_ns','refill_ns_per_second','start_reserve_ns','worker_limit']}=={'burst_ns':2_000_000_000,'refill_ns_per_second':250_000_000,'start_reserve_ns':100_000_000,'worker_limit':2},'original CPU budget unchanged')
     need(budget['accounting_unavailable'] is False and budget['in_flight']==0,'original CPU accounting')
    need(diagnostic['original_dispatch_result']=={'Ok':'ok'} and parity['native_result']=={'Ok':'ok'},'CPU outer and inner acceptance')
    need(diagnostic['complete_key_utf8_and_canonical_value_bytes']==8625548 and diagnostic['observed_held_capacity_lower_bound_bytes']==8391103,'original legal State size')
    cpu=parity['original_cpu_receipt']
    need(cpu['total_cpu_ns']==after_flow['paid_cpu_debit_ns']==after_flow['settled_full_cpu_ns'] and cpu['owner_cpu_ns']+cpu['scoped_worker_cpu_ns']==cpu['total_cpu_ns'] and cpu['live_paid_cpu_ns']+cpu['residual_cpu_ns']==cpu['total_cpu_ns'],'full owner/worker paid CPU')
    need(cpu['accounting_unavailable'] is False and cpu['live_refused'] is False and all(cpu[k]==2 for k in ['known_workers','spawned_workers','started_workers','finished_workers']),'original CPU worker settlement')
    if diagnostic['authenticated_backend']:
     cb=diagnostic['arithmetic_before']['complete_root_arithmetic']['counters'];ca=diagnostic['arithmetic_after']['complete_root_arithmetic']['counters']
     for key,expected_value in {'calculations':25,'complete_computations':11,'operation_initial_root_reuses':3,'operation_full_root_reuses':2,'partition_inputs_hashed':29534,'partition_projection_uses':11,'partition_projection_compared_keys':23145}.items():need(ca[key]-cb[key]==expected_value,'actual current CPU workload '+key)
    credits.append({'artifact_id':artifact_id,'runner':runner,'source_kind':kind,'selector':selector,'backend':'Authenticated' if diagnostic['authenticated_backend'] else 'Legacy','before_initial_credit_ns':before_flow['initial_credit_ns'],'after_initial_credit_ns':after_flow['initial_credit_ns'],'paid_cpu_ns':after_flow['paid_cpu_debit_ns'],'credited_refill_ns':after_flow['credited_refill_ns'],'remaining_credit_ns':after_flow['remaining_paid_credit_ns'],'outer_result':diagnostic['original_dispatch_result'],'inner_result':parity['native_result']})
  registered=data('semantic-controls/registry-check.json')
  need(registered['result']=='PASS' and registered['groups']==SEMANTIC_GROUPS and registered['selected_count']==64,'all original semantic selections plus seven initial-root controls')
  registries={c:registry(text('semantic-controls/'+c+'-registry.log')) for c in ['node','m06']}
  need({c:len(r) for c,r in registries.items()}=={'node':938,'m06':110},'actual registry counts')
  for group in SEMANTIC_GROUPS:
   names=group['tests'];need(set(names)<=registries[group['crate']] and len(names)==group['expected_count'],'exact selected semantic members')
   if 'prefix' in group:need(sorted(n for n in registries[group['crate']] if n.startswith(group['prefix']))==names,'prefix exact complete member set')
  need(text('semantic-controls/selected-tests.tsv')==''.join('\t'.join(v)+'\n' for v in expected_selected),'exact semantic ordering')
  need(text('semantic-controls/executed-selector-count.txt').strip()=='64','actual semantic execution count')
  need(tsv(text('semantic-controls/test-exits.tsv'))==[{'crate':c,'group':g,'selector':s,'native_exit':'0','log_exit':'0','reader_exit':'0'} for c,g,s in expected_selected],'actual semantic native/reader exits')
  need(tsv(text('semantic-controls/elf-before-exits.tsv'))==[{'crate':c,'reader_exit':'0'} for c in ['node','m06']],'semantic before ELF checks')
  need(tsv(text('semantic-controls/registry-exits.tsv'))==[{'crate':c,'native_exit':'0','log_exit':'0'} for c in ['m06','node']],'semantic native registries')
  for number,(crate,group,selector) in enumerate(expected_selected,1):
   prefix='semantic-controls/'+f'{number:02d}-{crate}-{selector.rsplit("::",1)[-1]}';native(crate,group,selector,prefix,prefix+'.cwd.txt')
  proto=registry(text('protocol-controls/registry.log'))
  need(len(proto)==53 and sorted(n for n in proto if n.startswith('pon_wire::state_root_arithmetic::tests::'))==PROTOCOL_TESTS,'eight protocol controls')
  need(data('protocol-controls/selected-tests.json')=={'prefix':'pon_wire::state_root_arithmetic::tests::','expected_count':8,'registered_count':53,'tests':PROTOCOL_TESTS},'protocol selected list')
  need(data('protocol-controls/test-exits.json')==[{'selector':s,'native_exit':0,'reader_exit':0} for s in PROTOCOL_TESTS],'protocol actual executions')
  ps=data('protocol-controls/summary.json')
  need(ps['result']=='PASS' and ps['expected_count']==ps['executed_count']==8 and ps['same_elf_before_after'] is True,'protocol scope result')
  for number,selector in enumerate(PROTOCOL_TESTS,1):native('protocol','protocol',selector,'protocol-controls/'+f'{number:02d}-{selector.rsplit("::",1)[-1]}')
  need(len(executions)==len({x['selector'] for x in executions})==76,'76 unique actual native executions')
  need(sum(x['passed'] for x in executions)==76 and sum(x['failed']+x['ignored']+x['measured'] for x in executions)==0,'actual 76 pass denominator')
  counts=collections.Counter((x['crate'] if x['group'] not in ['cpu','lifetime'] else x['group']) for x in executions)
  need(counts=={'node':46,'m06':18,'protocol':8,'cpu':2,'lifetime':2},'per lane actual scope counts')
  lanes.append({'artifact_id':artifact_id,'runner':runner,'source_kind':kind,'tested_commit':tested,'tested_tree':TREE,'zip_size':size,'zip_sha256':digest,'member_count':len(files),'all_member_crc_verified':True,'counts':dict(counts),'actual_native_passed':76,'failed':0,'ignored':0,'measured':0,'recorded_elf_sha256':{c:b['sha256'] for c,b in binaries.items()}})
 need(len(credits)==12 and all(c['before_initial_credit_ns']==c['after_initial_credit_ns']==2_000_000_000 for c in credits),'all 12 explicit initial credits')
 if (BASE/'HANDOFF.json').exists():
  handoff=json.loads(get('HANDOFF.json'))
  for f in handoff['files']:check_file(f)
 return {'schema':'chain-initial-root-portable-data-verification-v1','result':'PASS','run_id':41748875721,'run_attempt':1,'head':H,'merge':M,'tree':TREE,'harness':S,'lanes':lanes,'actual_native_passed':304,'failed':0,'ignored':0,'measured':0,'original_budget_and_initial_credit_supplement':credits,'native_invocations':0,'artifact_code_executions':0,'zip_extraction':False,'binary_identity_limit':'Recorded CI before/after ELF hashes only; no executables are stored in the original ZIPs.','scope_limit':'Original selected ordinary controls; not full runtime, V5, DAG, pressure, or whole-chain PQ release qualification.'}
if __name__=='__main__':
 try:
  print(json.dumps(main(),sort_keys=True,indent=2))
 except Exception as error:
  print(json.dumps({'result':'FAIL_DATA_VERIFICATION','error':str(error),'native_invocations':0,'artifact_code_executions':0}),file=sys.stderr)
  raise
