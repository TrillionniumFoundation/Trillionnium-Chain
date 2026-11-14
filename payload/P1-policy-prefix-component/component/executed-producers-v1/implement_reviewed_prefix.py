#!/usr/bin/env python3
import ast,difflib,hashlib,json,os,re,subprocess,time
from pathlib import Path
W=Path("/private/tmp/chain-public-policy-prefix-cache-20261114")
E=Path("/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1")
O=E/"implementation-v1"
if O.exists():raise ValueError("create-only implementation evidence")
O.mkdir()
env=os.environ.copy();env.update(PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0")
P="trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs"
OLD_SHA="1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70"
def sha(b):return hashlib.sha256(b).hexdigest()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+"\n").encode()
def put(name,b):
 p=O/name
 with p.open("xb") as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError("evidence readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
state={"schema":"trnm-public-policy-prefix-implementation-v1","status":"HOLD","base":"ed0d35487f2a67239e4d646fd41c2c7acb5cc740","changed_scope":[P],"tests_run":False,"native_or_hosted_performance_proved":False,"current_pins_modified":False,"errors":[],"steps":[]}
def run(label,args):
 r=subprocess.run(args,cwd=W,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
 state["steps"].append({"label":label,"argv":args,"exit":r.returncode,"stdout":put(label+".stdout",r.stdout),"stderr":put(label+".stderr",r.stderr)})
 if r.returncode:raise ValueError(label+" failed")
 return r.stdout
try:
 run("preflight",["/bin/bash","scripts/project-preflight.sh"])
 if run("initial-status",["/usr/bin/git","status","--porcelain=v1","--untracked-files=all"]).strip():raise ValueError("unexpected worktree delta")
 raw=(W/P).read_bytes()
 if sha(raw)!=OLD_SHA:raise ValueError("fixed original source mismatch")
 text=raw.decode()
 if "PUBLIC_RESOURCE_CONTRACT" in text or "fn hash_public_policy(" in text:raise ValueError("new symbol collision")
 match=re.search(r'    pub fn id\(self\) -> Hash \{\n(.*?)\n    \}',text,re.S)
 if not match:raise ValueError("original id not found")
 old_id=match.group(0)
 contracts=re.findall(r'b"(resource-revision-r20-authenticated-caller-grants-v1/[^"]+)"',old_id)
 if len(contracts)!=1:raise ValueError("one fixed resource contract required")
 contract=contracts[0].encode()
 if len(contract)!=5027 or sha(contract)!="624232b02e70ecbb1a2d80972a40aafefe63f12a8fc02d70a61112b6a6b42caf":raise ValueError("literal mismatch")
 tag=b"public-protected-profile-v3";profile=b"public-protected-development-v3"
 frame=lambda b:len(b).to_bytes(4,"little")+b
 prefix=b"TRNM-PON1\0"+len(tag).to_bytes(2,"little")+tag+frame(profile)+frame(contract)
 if len(prefix)!=5105:raise ValueError("original prefix length")
 scalar=(W/"trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs").read_text()
 def const(name):
  m=re.search(r"(?:pub(?:\([^)]*\))? )?const "+name+r":\s*(?:u64|usize)\s*=\s*([^;]+);",scalar)
  if not m:raise ValueError("missing original scalar constant "+name)
  expression=m.group(1);tree=ast.parse(expression,mode="eval")
  def calc(n):
   if isinstance(n,ast.Constant) and type(n.value) is int:return n.value
   if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Mult,ast.Add,ast.Sub)):
    a,b=calc(n.left),calc(n.right)
    return a*b if isinstance(n.op,ast.Mult) else a+b if isinstance(n.op,ast.Add) else a-b
   raise ValueError("unsupported immutable scalar expression")
  return expression,calc(tree.body)
 names=["MUTATION_CPU_BURST_NS","MUTATION_CPU_REFILL_NS_PER_SECOND","MUTATION_CPU_START_RESERVE_NS","MUTATION_CPU_WORKERS"]
 constants={n:{"expression":const(n)[0],"value":const(n)[1]}for n in names}
 parts=[bytes([16]),(2000).to_bytes(8,"little")]+[constants[n]["value"].to_bytes(8,"little")for n in names[:3]]+[constants[names[3]]["value"].to_bytes(4,"little")]
 preimage=prefix+b"".join(frame(x)for x in parts)
 golden="59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b"
 if len(preimage)!=5166 or sha(preimage)!=golden:raise ValueError("independent original development preimage")
 proof={
  "original_source_sha256":OLD_SHA,"original_function":put("PublicPolicy-id.original.rs",old_id.encode()),
  "contract":put("r20-resource-contract.original.bin",contract),
  "immutable_prefix":put("policy-id-prefix.original.bin",prefix),
  "full_development_preimage":put("policy-id-development-preimage.original.bin",preimage),
  "development_golden":golden,"constants":constants,"original_padded_blocks":81,
  "reusable_completed_blocks":79,"buffered_prefix_tail_bytes":49,"dynamic_suffix_bytes":61,
  "finalized_prefix_digest_is_not_the_cached_state":True,"Rust_tests_executed":False,
 }
 put("original-preimage-proof.json",js(proof))
 helper='''// Only immutable wire framing and code constants are cached. Each call appends
// all six original suffix parts to its own unfinalized SHA-256 state.
const PUBLIC_RESOURCE_CONTRACT: &[u8] = b"'''+contracts[0]+'''";

fn hash_public_policy(dynamic_parts: [&[u8]; 6]) -> Hash {
    static PREFIX: OnceLock<Sha256> = OnceLock::new();
    let mut digest = PREFIX
        .get_or_init(|| {
            let tag = b"public-protected-profile-v3";
            let mut prefix = Sha256::new();
            prefix.update(b"TRNM-PON1\\0");
            prefix.update((tag.len() as u16).to_le_bytes());
            prefix.update(tag);
            for part in [PROFILE.as_bytes(), PUBLIC_RESOURCE_CONTRACT] {
                prefix.update((part.len() as u32).to_le_bytes());
                prefix.update(part);
            }
            prefix
        })
        .clone();
    for part in dynamic_parts {
        digest.update((part.len() as u32).to_le_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

'''
 new_id='''    pub fn id(self) -> Hash {
        hash_public_policy([
            &[self.bits],
            &self.lifetime_ms.to_le_bytes(),
            &MUTATION_CPU_BURST_NS.to_le_bytes(),
            &MUTATION_CPU_REFILL_NS_PER_SECOND.to_le_bytes(),
            &MUTATION_CPU_START_RESERVE_NS.to_le_bytes(),
            &(MUTATION_CPU_WORKERS as u32).to_le_bytes(),
        ])
    }'''
 tests='''    fn original_policy_id(
        bits: u8,
        lifetime_ms: u64,
        burst_ns: u64,
        refill_ns: u64,
        start_reserve_ns: u64,
        workers: u32,
    ) -> Hash {
        // The original complete pon_wire::hash call is the independent oracle.
        hash(
            b"public-protected-profile-v3",
            &[
                PROFILE.as_bytes(),
                PUBLIC_RESOURCE_CONTRACT,
                &[bits],
                &lifetime_ms.to_le_bytes(),
                &burst_ns.to_le_bytes(),
                &refill_ns.to_le_bytes(),
                &start_reserve_ns.to_le_bytes(),
                &workers.to_le_bytes(),
            ],
        )
    }

    #[test]
    fn cached_policy_id_matches_original_hash_for_public_fields() {
        // Public fields can be deserialized without passing the constructor.
        for bits in [0, 7, 8, 12, 16, 20, 21, u8::MAX] {
            for lifetime_ms in [0, 99, 100, 1999, 2000, 2001, u64::MAX] {
                let policy = PublicPolicy { bits, lifetime_ms };
                assert_eq!(
                    policy.id(),
                    original_policy_id(
                        bits,
                        lifetime_ms,
                        MUTATION_CPU_BURST_NS,
                        MUTATION_CPU_REFILL_NS_PER_SECOND,
                        MUTATION_CPU_START_RESERVE_NS,
                        MUTATION_CPU_WORKERS as u32,
                    )
                );
            }
        }
    }

    #[test]
    fn cached_policy_id_retains_all_six_framed_suffix_parts() {
        let base = (16, 2000, 1, 2, 3, 4);
        let cases = [
            base,
            (17, 2000, 1, 2, 3, 4),
            (16, 2001, 1, 2, 3, 4),
            (16, 2000, 5, 2, 3, 4),
            (16, 2000, 1, 5, 3, 4),
            (16, 2000, 1, 2, 5, 4),
            (16, 2000, 1, 2, 3, 5),
            (0, 0, 0, 0, 0, 0),
            (u8::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u32::MAX),
        ];
        let baseline = original_policy_id(base.0, base.1, base.2, base.3, base.4, base.5);
        for (index, (bits, lifetime, burst, refill, reserve, workers)) in
            cases.into_iter().enumerate()
        {
            let expected = original_policy_id(bits, lifetime, burst, refill, reserve, workers);
            let actual = hash_public_policy([
                &[bits],
                &lifetime.to_le_bytes(),
                &burst.to_le_bytes(),
                &refill.to_le_bytes(),
                &reserve.to_le_bytes(),
                &workers.to_le_bytes(),
            ]);
            assert_eq!(actual, expected);
            if index != 0 {
                assert_ne!(actual, baseline);
            }
        }
    }

    #[test]
    fn cached_policy_id_clones_are_independent_across_callers() {
        let barrier = std::sync::Barrier::new(4);
        thread::scope(|scope| {
            for worker in 0..4u8 {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for round in 0..32u64 {
                        let policy = PublicPolicy {
                            bits: 8 + worker,
                            lifetime_ms: 100 + round + u64::from(worker),
                        };
                        let expected = original_policy_id(
                            policy.bits,
                            policy.lifetime_ms,
                            MUTATION_CPU_BURST_NS,
                            MUTATION_CPU_REFILL_NS_PER_SECOND,
                            MUTATION_CPU_START_RESERVE_NS,
                            MUTATION_CPU_WORKERS as u32,
                        );
                        assert_eq!(policy.id(), expected);
                    }
                });
            }
        });
        assert_eq!(
            hex::encode(PublicPolicy::development().id()),
            "59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b"
        );
    }

'''
 anchor='#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct PublicPolicy'
 if text.count(anchor)!=1 or text.count("        Arc, Mutex,\n")!=1:raise ValueError("fixed source anchors")
 text=text.replace("        Arc, Mutex,\n","        Arc, Mutex, OnceLock,\n",1)
 text=text.replace(anchor,helper+anchor,1)
 if text.count(old_id)!=1:raise ValueError("id anchor changed")
 text=text.replace(old_id,new_id,1)
 anchor='    #[test]\n    fn paid_envelope_resource_profile_has_fresh_exact_signed_commitment()'
 if text.count(anchor)!=1:raise ValueError("golden method anchor")
 text=text.replace(anchor,tests+anchor,1)
 if re.findall(r'b"(resource-revision-r20-authenticated-caller-grants-v1/[^"]+)"',text)!=contracts:
  raise ValueError("literal changed/duplicated")
 if (W/P).read_bytes()!=raw:raise ValueError("source changed before write")
 (W/P).write_text(text)
 run("rustfmt-changed-file",["rustfmt","--edition","2021","--config","skip_children=true",P])
 new=(W/P).read_bytes()
 patch=run("source-diff",["/usr/bin/git","diff","--no-ext-diff","--no-textconv","--",P])
 run("diff-check",["/usr/bin/git","diff","--check"])
 state.update(status="RUST_CANDIDATE_PREPARED_NOT_TESTED",original_source={"bytes":len(raw),"sha256":sha(raw)},candidate_source={"bytes":len(new),"sha256":sha(new),"git_blob":hashlib.sha1(b"blob "+str(len(new)).encode()+b"\0"+new).hexdigest()},patch={"path":str(O/"source-diff.stdout"),"bytes":len(patch),"sha256":sha(patch)},original_preimage_proof={"path":str(O/"original-preimage-proof.json"),"sha256":sha((O/"original-preimage-proof.json").read_bytes())})
except BaseException as e:
 state["errors"].append(type(e).__name__+": "+str(e));raise
finally:
 put("summary.json",js(state))
print(js(state).decode(),flush=True)
