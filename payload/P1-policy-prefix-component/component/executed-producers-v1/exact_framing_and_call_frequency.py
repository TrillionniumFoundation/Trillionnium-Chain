import pathlib,hashlib,json,re,subprocess,os
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114'); E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1'); O=E/'equivalence-and-call-frequency-v1'
assert not O.exists();O.mkdir()
P='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
original=(E/'originals'/P.replace('/','--')).with_suffix('.rs.original') if False else E/'originals'/(P.replace('/','--')+'.original')
old=original.read_bytes(); new=(S/P).read_bytes()
assert len(old)==433736 and hashlib.sha256(old).hexdigest()=='1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70'
assert len(new)==438782 and hashlib.sha256(new).hexdigest()=='0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a'
before=old.decode();after=new.decode()
anchor='#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct PublicPolicy'
helper_start=after.index('// Only immutable wire framing and code constants are cached.')
helper_end=after.index(anchor,helper_start)
helper=after[helper_start:helper_end]
test_start=after.index('    fn original_policy_id(')
test_end=after.index('    #[test]\n    fn paid_envelope_resource_profile_has_fresh_exact_signed_commitment()',test_start)
added_tests=after[test_start:test_end]
new_id=re.search(r'    pub fn id\(self\) -> Hash \{\n(.*?)\n    \}',after,re.S).group()
old_id=re.search(r'    pub fn id\(self\) -> Hash \{\n(.*?)\n    \}',before,re.S).group()
reversed_source=after.replace(added_tests,'',1).replace(new_id,old_id,1).replace(helper,'',1).replace('        Arc, Mutex, OnceLock,\n','        Arc, Mutex,\n',1).encode()
assert reversed_source==old,'all existing bytes must reconstruct exactly after four declared additions/replacement'
def write(n,b):
 if isinstance(b,str):b=b.encode()
 path=O/n;path.write_bytes(b);return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='')
wp='trillionnium/crates/trnm-protocol/src/pon_wire.rs'
r=subprocess.run(['/usr/bin/git','show','HEAD:'+wp],cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);assert r.returncode==0
wire=r.stdout;assert hashlib.sha1(b'blob '+str(len(wire)).encode()+b'\0'+wire).hexdigest()=='a92d02b7e1edd316aba52cb1b2ff8b546e65c03d'
assert wire==(S/wp).read_bytes()
wire_hash=re.search(r'pub fn hash\(.*?\n\}',wire.decode(),re.S).group()
literal=re.findall(r'b"(resource-revision-r20-authenticated-caller-grants-v1/[^"]+)"',before)
assert len(literal)==1 and re.findall(r'b"(resource-revision-r20-authenticated-caller-grants-v1/[^"]+)"',after)==literal
testnames=re.findall(r'#\[test\]\s+fn ([a-zA-Z0-9_]+)',before)
newnames=re.findall(r'#\[test\]\s+fn ([a-zA-Z0-9_]+)',after)
added=['cached_policy_id_matches_original_hash_for_public_fields','cached_policy_id_retains_all_six_framed_suffix_parts','cached_policy_id_clones_are_independent_across_callers']
assert [n for n in newnames if n not in added]==testnames and len(newnames)==len(testnames)+3
proof=json.loads((E/'implementation-v1/original-preimage-proof.json').read_bytes())
artifacts={'original_wire_function':write('pon-wire-hash.original.rs',wire_hash),'candidate_helper':write('hash-public-policy.candidate.rs',helper),'original_id':write('PublicPolicy-id.original.rs',old_id),'candidate_id':write('PublicPolicy-id.candidate.rs',new_id),'added_tests':write('cached-policy-id-controls.candidate.rs',added_tests)}
report={'schema':'trnm-public-policy-prefix-equivalence-and-frequency-v1','source_base':'ed0d35487f2a67239e4d646fd41c2c7acb5cc740','source_base_tree':'1aa9c21812489080980bdc3c1c2bb43611e88354','original_source':{'path':P,'bytes':len(old),'sha256':hashlib.sha256(old).hexdigest(),'blob':'b9bbe75b8509eaf10a73b50aab7e7892f6796e64'},'candidate_source':{'path':P,'bytes':len(new),'sha256':hashlib.sha256(new).hexdigest(),'blob':'b62de39bdba906c9d989498a6299df9a14d900e8'},'exact_original_reconstruction':True,'declared_changes':['import OnceLock','add private immutable resource constant and hash-prefix helper','replace only PublicPolicy::id computation with same six framed suffixes','add test-only original algorithm oracle and three tests'],'all_preexisting_test_source_bytes_preserved':True,'preexisting_top_level_test_count':len(testnames),'original_test_names':testnames,'new_test_names':added,'preimage':{'framing':['TRNM-PON1 NUL','u16 little-endian tag byte length','tag bytes','u32 little-endian PROFILE length','PROFILE bytes','u32 little-endian resource literal length','resource literal bytes','six original u32-length-prefixed suffix parts in original order'],'resource_literal_bytes':5027,'resource_literal_sha256':hashlib.sha256(literal[0].encode()).hexdigest(),'immutable_prefix_bytes':5105,'complete_cached_blocks':79,'buffered_prefix_bytes':49,'dynamic_suffix_bytes':61,'full_preimage_bytes':5166,'full_padded_blocks':81,'warm_suffix_and_padding_blocks':2,'cached_state_is_unfinalized':True,'cold_initialization_does_not_avoid_prefix_work':True,'measured_time_savings':None,'original_development_hash':'59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b'},'production_call_sites':[{'function':'PublicServer::cookie','path':P,'base_line':855,'base_policy_id_calls_per_entry':1,'stage':'WaitChallenge success transition at 2935'},{'function':'PublicServer::validate','path':P,'base_line':893,'base_policy_id_calls_per_entry_max':1,'stages':['complete Solution at 3020','decode_task_body at 1874, invoked at 2556']},{'function':'response','path':P,'base_line':1007,'base_policy_id_calls_per_entry_max':1,'stage':'worker ResponseEncoding at 2685'},{'function':'call_public_authenticated_with_timing','path':P,'base_line':3724,'base_policy_id_calls_per_entry':1,'reuse':['cookie validation receives expected_profile at 3806','response compares saved expected_profile at 3883']}],'frequency_bound':{'scope':'one complete successful paid RPC on the reviewed core client/server state-machine path','server_base_id_calls':4,'client_base_id_calls':1,'early_refusals_may_use_fewer_calls':True,'wait_challenge_or_grant_poll_does_not_recompute_id':True,'universal_public_API_or_campaign_call_upper_bound_proved':False,'historical_1099_1553_are_counter_derived_lower_bounds_not_id_instrumentation':True,'host_checks_equal_policy_id_calls':False},'hash_use_scope':{'existing_manifest_uses':19,'existing_manifest_sources':31,'public_v3_is_in_that_fixed_roster':False,'profile_byte_commitment_is_CPQ1_SHA512_not_this_policy':True,'new_helper_semantics':'Same existing domain-framed PublicPolicy byte commitment. No algorithm/domain/width/authorization/migration change. Direct SHA implementation equivalence is established separately by exact framing and original-algorithm Rust controls.','complete_callgraph_coverage_proved':False,'hash_use_manifest_reader_pins_need_change':False},'unchanged_contracts':['all fresh Host reads and callback cadence','four-second window and sixteen pressure workers','nonce order and deadline cadence','r20 authorization/grant policy and literal','all serialized fields and returned hash bytes','frozen V1 mathematical sources and qualification flags'],'artifacts':artifacts,'rust_tests_outcome':'recorded separately in actual Linux receipt; no inference here','hosted_performance_proved':False}
meta=write('review.json',json.dumps(report,indent=2)+'\n')
md='''# PublicPolicy ID prefix candidate: exact computation boundary

Only the fixed code prefix of the existing domain-framed SHA-256 invocation is cached. The cache holds an unfinalized state after 5,105 bytes (79 full blocks plus 49 buffered bytes). Each call clones that state, appends the original six framed suffixes (61 bytes), and finalizes. The cold initialization still performs the original prefix work. The block counts are an encoding calculation, not a measured time saving or a 4-second qualification result.

The four declared transformations can be reversed mechanically to reconstruct the original M8 file byte for byte. This proves that all preexisting test bodies, fresh Host checks, callback boundaries, nonce logic, resource fields, deadlines, and state-machine code remain unchanged. The original Rust hash function is captured in full; its ordered framing is the same as the new helper.

On the reviewed successful paid-RPC path, the server computes the base policy identity once for cookie construction, once for Solution validation, once for body validation, and once for response construction. The client computes it once at call entry and reuses that value. WaitChallenge polls before the grant and WaitGrant polls do not repeat this computation. Thus this path has four server calls plus one client call; refusals can take fewer stages. This is not a universal bound for an arbitrary number of public API calls or connections. The prior 1,099/1,553 figures are derived lower bounds from distinct server counters, not measured invocation totals or counts of fresh Host checks.

The existing Hash-use reader validates a closed 19-purpose, 31-source inventory. It does not scan or classify every direct SHA call, and this PublicPolicy source is not in that inventory. Its CPQ1 profile-byte-commitment row describes SHA-512 for a different operation. The new private helper keeps the existing PublicPolicy SHA-256 purpose and framing; that equivalence is established by the captured original algorithm, fixed preimage/golden, suffix controls and actual Rust tests, not by treating the Hash-use inventory as complete. H1 pins and all false qualification flags remain unchanged.
'''
write('README.md',md)
print(json.dumps({'review':meta,'original_reconstruction':True,'original_test_methods':len(testnames),'new_tests':3,'server_calls_per_reviewed_successful_rpc':4,'client_calls':1,'hosted_performance_proved':False}),flush=True)
