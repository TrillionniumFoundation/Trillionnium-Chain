//! Explicit SP27-01 functional/accounting experiment. Never changes admission rules.
//! Run only on a frozen source through the ignored native_credit_observer entry.
use crate::{development_public, Node, Packet, Settings};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    self, PreparedGenerationError, PreparedGenerationProgress, PreparedTask,
};
use trnm_mvcc_fee::{continuity_v1, pon_executor::State};
use trnm_protocol::pon_wire::{Hash, Header};

type ExperimentResult<T> = Result<T, Box<dyn std::error::Error>>;
const EVENT_SCHEMA: &str = "sp27-01-node-credit-event-v1";
const MAX_ATTEMPTS: u64 = 4096;

fn require(condition: bool, message: &str) -> ExperimentResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_new(path: &Path, bytes: &[u8]) -> ExperimentResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    require(fs::read(path)? == bytes, "ARCHIVE_READBACK")
}

#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(stamp.tv_sec).ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    (nanos < 1_000_000_000)
        .then_some(())
        .and_then(|_| seconds.checked_mul(1_000_000_000)?.checked_add(nanos))
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> Option<u64> {
    None
}

#[derive(Clone)]
struct Context {
    operation_id: String,
    strategy: String,
    chain_instance_id: String,
    pair_id: String,
}

struct Span {
    id: String,
    context: Context,
    actor: &'static str,
    stage: &'static str,
    scope: &'static str,
    attempt_id: Option<String>,
    started_ns: Option<u64>,
    cpu: Option<u64>,
}

struct Journal {
    root: PathBuf,
    file: File,
    run_id: String,
    process_epoch: String,
    clock: Instant,
    next_event: u64,
    next_span: u64,
    active_span: Option<String>,
    completed_attempts: u64,
    target_hits: u64,
    target_misses: u64,
    cancelled_attempts: u64,
    plan_sha256: String,
    plan: Value,
}

impl Journal {
    fn new(mode: &str, cases: &[String], labels: &[&str]) -> ExperimentResult<Self> {
        let root = PathBuf::from(env::var("TRNM_SP27_COST_OUTPUT")?);
        require(!root.exists(), "OUTPUT_MUST_NOT_EXIST")?;
        let run_id = env::var("TRNM_SP27_RUN_ID")?;
        require(
            !run_id.is_empty()
                && run_id.len() <= 160
                && run_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b)),
            "RUN_ID",
        )?;
        let source_sha = env::var("TRNM_SP27_SOURCE_SHA")?;
        let source_tree = env::var("TRNM_SP27_SOURCE_TREE")?;
        for source in [&source_sha, &source_tree] {
            require(
                source.len() == 40 && source.bytes().all(|b| b.is_ascii_hexdigit()),
                "SOURCE_ID",
            )?;
        }
        fs::create_dir(&root)?;
        fs::create_dir(root.join("proofs"))?;
        fs::create_dir(root.join("packets"))?;
        let mut planned=Vec::new();
        for label in labels {
            for case in cases {
                planned.push(format!("{run_id}:{label}:{case}"));
            }
        }
        let plan = json!({
            "schema":"sp27-01-node-credit-plan-v1",
            "run_id":run_id, "mode":mode,
            "source_sha":source_sha, "source_tree":source_tree,
            "source_binding":"controller-asserted; supervisor must verify source and binary",
            "planned_operation_ids":planned,
            "strategies":labels, "max_attempts":MAX_ATTEMPTS,
            "task_profile":continuity_v1::PROFILE,
            "evaluation_policy":"native-public-evaluation-dev-v1",
            "node_workers":1, "genesis_timestamp":1,
            "timestamps":"1 + 10 * height", "transactions_per_block":0,
            "kernel":"pon_work::PreparedTask::prove_with_progress",
            "preparation_policy":"retain across searches vs recreate at each search boundary",
            "fixture_preparation":"prepare_from_matrices includes an additional native preparation; separately observed and retained in total execution cost",
            "cost_scope":"all child process costs belong to supervisor inclusive rusage; exclusive stage clocks are diagnostic and must not be added to inclusive costs",
            "performance_qualified":false, "independent_business_demand":false,
            "production_activation":false
        });
        let plan_bytes = serde_json::to_vec_pretty(&plan)?;
        write_new(&root.join("plan.json"), &plan_bytes)?;
        let file = OpenOptions::new().write(true).create_new(true).open(root.join("events.jsonl"))?;
        Ok(Self {
            root, file, run_id:run_id.clone(),
            process_epoch:format!("{run_id}:process:{}", std::process::id()),
            clock:Instant::now(), next_event:0, next_span:0, active_span:None,
            completed_attempts:0, target_hits:0, target_misses:0, cancelled_attempts:0,
            plan_sha256:sha(&plan_bytes), plan,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self, context: &Context, actor: &str, stage: &str, scope: &str,
        kind: &str, span_id: Option<&str>, attempt_id: Option<&str>,
        status: &str, cpu_ns: Option<u64>, wall_ns: Option<u64>,
        started_ns: Option<u64>, ended_ns: Option<u64>, mut payload: Value,
    ) -> ExperimentResult<()> {
        let object = payload.as_object_mut().ok_or("PAYLOAD_OBJECT")?;
        object.insert("chain_instance_id".into(), json!(context.chain_instance_id));
        object.insert("pair_id".into(), json!(context.pair_id));
        let row = json!({
            "schema":EVENT_SCHEMA, "seq":self.next_event,
            "event_id":format!("{}:event:{}",self.run_id,self.next_event),
            "run_id":self.run_id, "operation_id":context.operation_id,
            "process_epoch":self.process_epoch, "strategy":context.strategy,
            "type":kind, "stage":stage, "span_id":span_id, "attempt_id":attempt_id,
            "at_ns":u64::try_from(self.clock.elapsed().as_nanos()).ok(),
            "clock_id":format!("{}:monotonic",self.process_epoch),
            "actor_id":actor, "owner_id":format!("{actor}:{}",context.strategy),
            "scope":scope, "inclusive":false, "coverage":"diagnostic",
            "status":status, "cpu_ns":cpu_ns, "cpu_clock":"thread-cpu",
            "wall_ns":wall_ns, "started_ns":started_ns,"ended_ns":ended_ns,"payload":payload
        });
        serde_json::to_writer(&mut self.file, &row)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        self.next_event += 1;
        Ok(())
    }

    fn begin(
        &mut self, context: &Context, actor: &'static str, stage: &'static str,
        scope: &'static str, attempt_id: Option<String>, payload: Value,
    ) -> ExperimentResult<Span> {
        require(self.active_span.is_none(), "OVERLAPPING_EXCLUSIVE_SPAN")?;
        let span = Span {
            id:format!("{}:span:{}",self.run_id,self.next_span), context:context.clone(),
            actor, stage, scope, attempt_id,
            started_ns:u64::try_from(self.clock.elapsed().as_nanos()).ok(),cpu:thread_cpu_ns(),
        };
        self.next_span += 1;
        self.emit(
            context, actor, stage, scope, "begin", Some(&span.id),
            span.attempt_id.as_deref(), "started", None, None, None, None, payload,
        )?;
        self.active_span = Some(span.id.clone());
        Ok(span)
    }

    fn end(&mut self, span: Span, status: &str, payload: Value) -> ExperimentResult<()> {
        require(self.active_span.as_deref() == Some(span.id.as_str()), "SPAN_OWNER")?;
        let cpu = span.cpu.and_then(|start| thread_cpu_ns()?.checked_sub(start));
        let ended_ns=u64::try_from(self.clock.elapsed().as_nanos()).ok();
        let wall = span.started_ns.and_then(|start|ended_ns?.checked_sub(start));
        self.emit(
            &span.context, span.actor, span.stage, span.scope, "end", Some(&span.id),
            span.attempt_id.as_deref(), status, cpu, wall, span.started_ns,ended_ns,payload,
        )?;
        self.active_span = None;
        Ok(())
    }

    fn observe(&mut self, context: &Context, stage: &str, payload: Value) -> ExperimentResult<()> {
        self.emit(context,"observer",stage,"window","observation",None,None,
                  "observed",None,None,None,None,payload)
    }

    fn finish(&mut self, mut summary: Value) -> ExperimentResult<()> {
        require(self.active_span.is_none(), "UNFINISHED_SPAN")?;
        summary["schema"] = json!("sp27-01-node-credit-summary-v1");
        summary["run_id"] = json!(self.run_id);
        summary["process_epoch"] = json!(self.process_epoch);
        summary["plan_sha256"] = json!(self.plan_sha256);
        summary["planned_operation_ids"] = self.plan["planned_operation_ids"].clone();
        summary["event_count"] = json!(self.next_event);
        summary["completed_attempts_all_cohorts"] = json!(self.completed_attempts);
        summary["target_hits_all_cohorts"] = json!(self.target_hits);
        summary["target_misses_all_cohorts"] = json!(self.target_misses);
        summary["cancelled_attempts"] = json!(self.cancelled_attempts);
        summary["cost_qualification"] = json!({
            "performance_qualified":false,"exclusive_host_ownership":false,
            "stage_cpu_clock":"calling-thread only; unknown remains null",
            "stage_clocks":"diagnostic; include begin-journal IO and exclude end-journal IO",
            "whole_process_cost":"supervisor inclusive rusage is separate, not added to stage costs",
            "fixture_cost":"header preparation included as separately owned actual work",
            "real_independent_business_demand":false,
            "market_reward_or_profit":false,"production_activation":false
        });
        self.file.sync_all()?;
        summary["events_sha256"] = json!(sha(&fs::read(self.root.join("events.jsonl"))?));
        write_new(&self.root.join("summary.json"), &serde_json::to_vec_pretty(&summary)?)
    }
}

struct Arm {
    label: &'static str,
    path: PathBuf,
    node: Option<Node>,
    cache: Option<PreparedTask>,
}

impl Arm {
    fn context(&self, journal: &Journal, case: &str, control: bool) -> Context {
        Context {
            operation_id:format!("{}:{}:{case}",journal.run_id,self.label),
            strategy:if control {"control"} else {self.label}.into(),
            chain_instance_id:format!("{}:node:{}",journal.run_id,self.label),
            pair_id:case.into(),
        }
    }

    fn node(&self) -> ExperimentResult<&Node> { self.node.as_ref().ok_or_else(||"NODE_CLOSED".into()) }
    fn node_mut(&mut self) -> ExperimentResult<&mut Node> { self.node.as_mut().ok_or_else(||"NODE_CLOSED".into()) }
}

fn settings() -> ExperimentResult<Settings> {
    Ok(Settings::development_with_profiles(Some(1),"native-public-evaluation-dev-v1",continuity_v1::PROFILE)?)
}

fn open_arm(journal: &mut Journal, label: &'static str) -> ExperimentResult<Arm> {
    let mut arm = Arm {label,path:journal.root.join(format!("node-{label}")),node:None,cache:None};
    let context = arm.context(journal,"open",label=="control");
    let span = journal.begin(&context,"receiver","node_open","setup",None,json!({"path":format!("node-{label}")}))?;
    arm.node = Some(Node::open(&arm.path,settings()?,1)?);
    journal.end(span,"completed",json!({"genesis":hex::encode(arm.node()?.settings().genesis())}))?;
    Ok(arm)
}

fn release(journal: &mut Journal, arm: &mut Arm, context: &Context) -> ExperimentResult<()> {
    if arm.cache.is_some() {
        let span=journal.begin(context,"producer","cache_release","window",None,json!({"cache":"one exact maintenance task"}))?;
        arm.cache=None;
        journal.end(span,"completed",json!({"released":true}))?;
    }
    Ok(())
}

fn prepare(journal: &mut Journal, arm: &mut Arm, context: &Context, a: &[u32], b: &[u32]) -> ExperimentResult<()> {
    if arm.cache.is_none() {
        let span=journal.begin(context,"producer","prepare","setup",None,json!({"task":hex::encode(pon_work::task_id(a,b).map_err(|e|format!("TASK:{e:?}"))?)}))?;
        arm.cache=Some(PreparedTask::new(a,b).map_err(|e|format!("PREPARE:{e:?}"))?);
        journal.end(span,"completed",json!({"product_sha256":sha(arm.cache.as_ref().ok_or("CACHE")?.product_bytes()),"physical_bytes_unknown":true}))?;
    } else {
        journal.observe(context,"cache_reuse",json!({"task":hex::encode(pon_work::task_id(a,b).map_err(|e|format!("TASK:{e:?}"))?)}))?;
    }
    Ok(())
}

fn header(
    journal: &mut Journal, arm: &Arm, context: &Context, parent: Hash,
    miner: Hash, a: &[u32], b: &[u32],
) -> ExperimentResult<Header> {
    let height=arm.node()?.parent_height(parent)?+1;
    let span=journal.begin(context,"fixture","header_prepare","setup",None,json!({"parent_id":hex::encode(parent),"height":height,"includes_native_prepared_task":true}))?;
    let candidate=arm.node()?.prepare_from_matrices(parent,vec![],miner,1+10*height,a,b)?;
    let header=candidate.header;
    drop(candidate.prepared);
    require(candidate.transactions.is_empty(),"MAINTENANCE_TRANSACTIONS")?;
    journal.end(span,"completed",json!({"header_sha256":sha(&header.encode()),"target":hex::encode(header.target),"height":height}))?;
    Ok(header)
}

#[derive(PartialEq,Eq)]
struct Trial {
    nonce:u64,
    challenge:String,
    proof_sha256:String,
    ticket:String,
    hit:bool,
}

fn proof_metadata(header:&Header, cohort:&str) -> Value {
    json!({"cohort":cohort,"parent_id":hex::encode(header.parent),"height":header.height,
        "nonce":header.nonce,"header_nonce":header.nonce,"task":hex::encode(header.work_task),
        "challenge":hex::encode(header.challenge()),"target":hex::encode(header.target)})
}

fn generate(
    journal:&mut Journal,arm:&mut Arm,context:&Context,mut header:Header,
    a:&[u32],b:&[u32],cohort:&str,
) -> ExperimentResult<(Packet,Vec<Trial>)> {
    prepare(journal,arm,context,a,b)?;
    let mut trials=Vec::new();
    for nonce in 0..MAX_ATTEMPTS {
        header.nonce=nonce;
        let attempt=format!("{}/attempt/{nonce}",context.operation_id);
        let span=journal.begin(context,"producer","producer_attempt","window",Some(attempt),proof_metadata(&header,cohort))?;
        let mut tiles=0_u64;
        let result=arm.cache.as_ref().ok_or("CACHE")?.prove_with_progress(header.challenge(),|point| {
            if matches!(point,PreparedGenerationProgress::TranscriptTile {..}) {tiles+=1;}
            Ok::<_,String>(())
        });
        let proof=match result {
            Ok(proof)=>proof,
            Err(error)=> {
                journal.end(span,"failed",json!({"reason":format!("{error:?}"),"cohort":cohort}))?;
                return Err(format!("PROOF:{error:?}").into());
            }
        };
        let trace=&proof[proof.len()-32..];
        let ticket=pon_work::hash(b"ticket",&[&header.challenge(),trace]);
        let hit=ticket<=header.target;
        let mut result=proof_metadata(&header,cohort);
        result["hit"]=json!(hit);
        result["proof_sha256"]=json!(sha(&proof));
        result["ticket"]=json!(hex::encode(ticket));
        result["trace"]=json!(hex::encode(trace));
        result["transcript_tiles"]=json!(tiles);
        result["complete_proof_bytes"]=json!(proof.len());
        journal.end(span,"completed",result)?;
        journal.completed_attempts+=1;
        if hit {journal.target_hits+=1;} else {journal.target_misses+=1;}
        require(tiles==512,"TRANSCRIPT_TILE_COVERAGE")?;
        let relative=format!("proofs/{}-{}-{nonce:04}.bin",arm.label,context.pair_id);
        let span=journal.begin(context,"producer","proof_archive","window",None,json!({"path":relative,"nonce":nonce}))?;
        write_new(&journal.root.join(&relative),&proof)?;
        journal.end(span,"completed",json!({"path":relative,"proof_sha256":sha(&proof),"bytes":proof.len(),"nonce":nonce}))?;
        trials.push(Trial{nonce,challenge:hex::encode(header.challenge()),proof_sha256:sha(&proof),ticket:hex::encode(ticket),hit});
        if hit {
            let packet=Packet{header,transactions:vec![],proof};
            let relative=format!("packets/{}-{}.bin",arm.label,context.pair_id);
            let span=journal.begin(context,"producer","packet_archive","window",None,json!({"path":relative}))?;
            let bytes=packet.encode()?;
            write_new(&journal.root.join(&relative),&bytes)?;
            journal.end(span,"completed",json!({"path":relative,"packet_sha256":sha(&bytes),"block_id":hex::encode(packet.id()?),"bytes":bytes.len()}))?;
            if arm.label=="recreate" {release(journal,arm,context)?;}
            journal.observe(context,"search_result",json!({"status":"winner","cohort":cohort,"attempts":trials.len(),"block_id":hex::encode(packet.id()?)}))?;
            return Ok((packet,trials));
        }
    }
    if arm.label=="recreate" {release(journal,arm,context)?;}
    journal.observe(context,"search_result",json!({"status":"exhausted","cohort":cohort,"attempts":trials.len()}))?;
    Err("DECLARED_SEARCH_EXHAUSTED".into())
}

fn project_state(state:&State) -> ExperimentResult<Value> {
    let mut balances=BTreeMap::new();
    let mut accounts=BTreeMap::new();
    for index in [7,8,9] {
        let who=hex::encode(development_public(index)?);
        let account=state.get(&format!("account:{who}"));
        let balance=match account {Some(row)=>row["balance"].as_u64().ok_or("BALANCE")?,None=>0};
        balances.insert(who.clone(),balance);
        accounts.insert(who,account.cloned());
    }
    let rewards:BTreeMap<_,_>=state.iter().filter(|(key,_)|key.starts_with("reward:")).map(|(key,value)|(key.clone(),value.clone())).collect();
    Ok(json!({"balances":balances,"accounts":accounts,"rewards":rewards,"issued":state.get("meta:issued")}))
}

fn snapshot(
    journal:&mut Journal,arm:&Arm,context:&Context,action:&str,point:&str,
    packet:Option<&Packet>,branch:Option<Hash>,
) -> ExperimentResult<Value> {
    let span=journal.begin(context,"receiver","node_observation","window",None,json!({"action":action,"point":point}))?;
    let (tip,generation,state)=arm.node()?.read_active()?;
    let mut result=project_state(&state)?;
    result["action"]=json!(action);
    result["point"]=json!(point);
    result["stats"]=arm.node()?.stats()?;
    result["packet"]=match packet {
        Some(packet)=>arm.node()?.exact_packet_observation(packet)?,
        None=>Value::Null,
    };
    result["packet_header"]=match packet {
        Some(packet)=>json!({"parent":hex::encode(packet.header.parent),"height":packet.header.height,
            "target":hex::encode(packet.header.target),"nonce":packet.header.nonce,
            "task":hex::encode(packet.header.work_task),"challenge":hex::encode(packet.header.challenge())}),
        None=>Value::Null,
    };
    result["state_root"]=json!(hex::encode(arm.node()?.settings().state_root(&state)?));
    result["active_tip"]=json!(hex::encode(tip));
    result["generation"]=json!(generation);
    if let Some(branch)=branch {
        result["branch_id"]=json!(hex::encode(branch));
        result["branch_state"]=project_state(&arm.node()?.state_at(branch)?)?;
    }
    journal.end(span,"completed",json!({"action":action,"point":point,"readback_complete":true}))?;
    journal.observe(context,"node_observation",result.clone())?;
    Ok(result)
}

fn state_unchanged(before:&Value,after:&Value) -> bool {
    ["stats","balances","accounts","rewards","state_root","issued"].iter().all(|key|before[*key]==after[*key])
}

fn balance(snapshot:&Value,miner:u64) -> ExperimentResult<u64> {
    snapshot["balances"][hex::encode(development_public(miner)?)].as_u64().ok_or_else(||"BALANCE_READBACK".into())
}

fn admit(journal:&mut Journal,arm:&mut Arm,context:&Context,packet:&Packet,action:&str) -> ExperimentResult<Value> {
    snapshot(journal,arm,context,action,"before",Some(packet),None)?;
    let span=journal.begin(context,"receiver","admission","window",None,json!({"block_id":hex::encode(packet.id()?),"packet_sha256":sha(&packet.encode()?)}))?;
    let result=arm.node_mut()?.admit(packet,100_000);
    match result {
        Ok(id)=>journal.end(span,"completed",json!({"admitted":true,"block_id":hex::encode(id)}))?,
        Err(error)=> {
            journal.end(span,"rejected",json!({"admitted":false,"reason":error.to_string()}))?;
            return Err(error.into());
        }
    }
    let after=snapshot(journal,arm,context,action,"after",Some(packet),Some(packet.id()?))?;
    require(after["packet"]["stored_exact"]==true,"ADMISSION_EXACT_READBACK")?;
    Ok(after)
}

fn activate(journal:&mut Journal,arm:&mut Arm,context:&Context,packet:&Packet,action:&str) -> ExperimentResult<Value> {
    snapshot(journal,arm,context,action,"before",Some(packet),None)?;
    let span=journal.begin(context,"receiver","activation","window",None,json!({"requested_tip":hex::encode(packet.id()?)}))?;
    let selected=arm.node_mut()?.activate_observed(packet.id()?,100_000)?;
    journal.end(span,"completed",json!({"selected_tip":hex::encode(selected)}))?;
    snapshot(journal,arm,context,action,"after",Some(packet),Some(packet.id()?))
}

fn duplicate(journal:&mut Journal,arm:&mut Arm,case:&str,packet:&Packet) -> ExperimentResult<Value> {
    let context=arm.context(journal,case,false);
    let before=snapshot(journal,arm,&context,"duplicate","before",Some(packet),None)?;
    let span=journal.begin(&context,"receiver","admission","window",None,json!({"duplicate":true,"block_id":hex::encode(packet.id()?)}))?;
    let id=arm.node_mut()?.admit(packet,100_000)?;
    journal.end(span,"completed",json!({"admitted":true,"existing_id":hex::encode(id)}))?;
    let after=snapshot(journal,arm,&context,"duplicate","after",Some(packet),None)?;
    require(state_unchanged(&before,&after),"DUPLICATE_CHANGED_LEDGER")?;
    Ok(after)
}

fn root_negative(journal:&mut Journal,arm:&mut Arm,a:&[u32],b:&[u32]) -> ExperimentResult<Value> {
    let context=arm.context(journal,"root-negative",true);
    let parent=arm.node()?.active()?.0;
    let mut header=header(journal,arm,&context,parent,development_public(9)?,a,b)?;
    header.state[0]^=1;
    let (packet,_)=generate(journal,arm,&context,header,a,b,"root-negative-control")?;
    let span=journal.begin(&context,"receiver","control_full_verification","window",None,json!({"challenge_rebound":true}))?;
    pon_work::verify(packet.header.challenge(),packet.header.work_task,packet.header.target,&packet.proof).map_err(|e|format!("NEGATIVE_NOT_VALID_WORK:{e:?}"))?;
    journal.end(span,"completed",json!({"complete_work_valid":true,"target_hit":true}))?;
    let before=snapshot(journal,arm,&context,"root_negative","before",Some(&packet),None)?;
    let span=journal.begin(&context,"receiver","admission","window",None,json!({"block_id":hex::encode(packet.id()?),"expected_error":"ROOT"}))?;
    let result=arm.node_mut()?.admit(&packet,100_000);
    let error=match result {
        Err(error)=>error.to_string(),
        Ok(id)=> {
            journal.end(span,"completed",json!({"unexpected_admission":hex::encode(id)}))?;
            return Err("INVALID_ROOT_ACCEPTED".into());
        }
    };
    journal.end(span,"rejected",json!({"admitted":false,"reason":error}))?;
    let after=snapshot(journal,arm,&context,"root_negative","after",Some(&packet),None)?;
    require(error=="ROOT","ROOT_NEGATIVE_WRONG_GATE")?;
    require(state_unchanged(&before,&after),"ROOT_REJECTION_CHANGED_LEDGER")?;
    require(after["packet"]["stored_exact"]==false,"ROOT_NEGATIVE_PERSISTED")?;
    Ok(json!({"error":error,"before":before,"after":after,"packet_sha256":sha(&packet.encode()?)}))
}

fn reopen(journal:&mut Journal,arm:&mut Arm,packet:&Packet) -> ExperimentResult<Value> {
    let context=arm.context(journal,"reopen",false);
    let before=snapshot(journal,arm,&context,"reopen","before",Some(packet),None)?;
    release(journal,arm,&context)?;
    let span=journal.begin(&context,"receiver","node_close","recovery",None,json!({}))?;
    arm.node=None;
    journal.end(span,"completed",json!({"closed":true}))?;
    let span=journal.begin(&context,"receiver","node_open","recovery",None,json!({"same_chain_instance":true}))?;
    arm.node=Some(Node::open(&arm.path,settings()?,1)?);
    journal.end(span,"completed",json!({"reopened":true}))?;
    let after=snapshot(journal,arm,&context,"reopen","after",Some(packet),None)?;
    require(state_unchanged(&before,&after),"REOPEN_CHANGED_LEDGER")?;
    Ok(after)
}

fn close(journal:&mut Journal,arm:&mut Arm) -> ExperimentResult<()> {
    let context=arm.context(journal,"close",arm.label=="control");
    release(journal,arm,&context)?;
    let span=journal.begin(&context,"receiver","node_close","recovery",None,json!({}))?;
    arm.node=None;
    journal.end(span,"completed",json!({"closed":true}))
}

#[allow(clippy::too_many_arguments)]
fn paired_block(
    journal:&mut Journal,arms:&mut [Arm;2],case:&str,parent:Hash,miner:u64,
    action:Option<&str>,a:&[u32],b:&[u32],
) -> ExperimentResult<(Packet,Value)> {
    let mut packets=Vec::new();
    let mut histories=Vec::new();
    let mut observations=Vec::new();
    for arm in arms.iter_mut() {
        let context=arm.context(journal,case,false);
        let header=header(journal,arm,&context,parent,development_public(miner)?,a,b)?;
        let (packet,trials)=generate(journal,arm,&context,header,a,b,"legal-workload")?;
        let admitted=admit(journal,arm,&context,&packet,"admission")?;
        let observation=if let Some(action)=action {activate(journal,arm,&context,&packet,action)?} else {admitted};
        packets.push(packet);
        histories.push(trials);
        observations.push(observation);
    }
    require(histories[0]==histories[1],"PAIRED_ATTEMPT_HISTORY")?;
    require(packets[0].encode()?==packets[1].encode()?,"PAIRED_PACKET_BYTES")?;
    require(observations[0]==observations[1],"PAIRED_NATIVE_READBACK")?;
    let pair=json!({"pair_id":case,"packet_sha256":sha(&packets[0].encode()?),"block_id":hex::encode(packets[0].id()?),
        "nonce":packets[0].header.nonce,"attempts_per_arm":histories[0].len(),
        "attempt_stream_equal":true,"packet_bytes_equal":true,"native_readback_equal":true,
        "retain_observation":observations[0],"recreate_observation":observations[1]});
    Ok((packets.remove(0),pair))
}

fn full_cases() -> Vec<String> {
    let mut cases=vec!["open".into(),"a01".into(),"duplicate-b01".into()];
    cases.extend((1..=21).map(|h|format!("b{h:02}")));
    cases.extend((1..=22).map(|h|format!("c{h:02}")));
    cases.extend(["root-negative","reopen","duplicate-reopened","close"].map(str::to_owned));
    cases
}

fn run_full() -> ExperimentResult<()> {
    let mut journal=Journal::new("full",&full_cases(),&["retain","recreate"])?;
    let mut arms=[open_arm(&mut journal,"retain")?,open_arm(&mut journal,"recreate")?];
    let (_,_,a,b)=arms[0].node()?.settings().consensus_maintenance_material()?;
    let genesis=arms[0].node()?.settings().genesis();
    let mut pairs=Vec::new();
    let (first,pair)=paired_block(&mut journal,&mut arms,"a01",genesis,7,Some("activation"),&a,&b)?;
    pairs.push(pair);
    let first_id=first.id()?;
    let mut branch_b=genesis;
    let mut b_first=None;
    let mut mature_b=None;
    for height in 1..=21 {
        let action=if height==1 {"equal_work_fork"} else if height==2 {"heavier_fork"} else if height==21 {"maturity"} else {"activation"};
        let case=format!("b{height:02}");
        let (packet,pair)=paired_block(&mut journal,&mut arms,&case,branch_b,8,Some(action),&a,&b)?;
        branch_b=packet.id()?;
        if height==1 {
            require(pair["retain_observation"]["stats"]["tip"]==hex::encode(first_id),"EQUAL_WORK_SWITCHED")?;
            require(pair["retain_observation"]["packet"]["active_chain_member"]==false,"EQUAL_WORK_ACTIVE")?;
            b_first=Some(packet.clone());
            for arm in &mut arms {duplicate(&mut journal,arm,"duplicate-b01",&packet)?;}
        } else {
            require(pair["retain_observation"]["stats"]["tip"]==hex::encode(branch_b),"HEAVIER_NOT_SELECTED")?;
        }
        if height==21 {
            require(balance(&pair["retain_observation"],8)?==1000,"MATURITY_BALANCE")?;
            mature_b=Some(pair["retain_observation"].clone());
        }
        pairs.push(pair);
    }
    let mut branch_c=genesis;
    let mut final_packet=None;
    let mut reorg=None;
    for height in 1..=22 {
        let case=format!("c{height:02}");
        let action=(height==22).then_some("reorganization");
        let (packet,pair)=paired_block(&mut journal,&mut arms,&case,branch_c,9,action,&a,&b)?;
        branch_c=packet.id()?;
        if height<22 {
            require(pair["retain_observation"]["stats"]["tip"]==hex::encode(branch_b),"ADMISSION_ACTIVATED_FORK")?;
            require(pair["retain_observation"]["packet"]["active_chain_member"]==false,"UNACTIVATED_FORK_ACTIVE")?;
        } else {
            require(balance(&pair["retain_observation"],8)?==0,"DETACHED_REWARD_RETAINED")?;
            require(balance(&pair["retain_observation"],9)?==2000,"CANONICAL_REWARD_MISSING")?;
            require(pair["retain_observation"]["stats"]["tip"]==hex::encode(branch_c),"REORG_NOT_SELECTED")?;
            reorg=Some(pair["retain_observation"].clone());
            final_packet=Some(packet);
        }
        pairs.push(pair);
    }
    let packet=final_packet.ok_or("FINAL_PACKET")?;
    let mut negatives=Vec::new();
    let mut reopens=Vec::new();
    for arm in &mut arms {
        negatives.push(root_negative(&mut journal,arm,&a,&b)?);
        reopens.push(reopen(&mut journal,arm,&packet)?);
        duplicate(&mut journal,arm,"duplicate-reopened",&packet)?;
        close(&mut journal,arm)?;
    }
    journal.finish(json!({"mode":"full","result":"PASS","paired_blocks":pairs.len(),"pairs":pairs,
        "maturity_readback":mature_b,"reorganization_readback":reorg,
        "root_negative_controls":negatives,"reopen_readbacks":reopens,
        "initial_side_fork":hex::encode(b_first.ok_or("SIDE_PACKET")?.id()?),
        "native_consensus_weight":"read from actual Node; no CPU interpretation",
        "native_reward":"actual development ledger test-units; no market/economic claim",
        "independent_security_result":false,"recommended_disposition":"INTEGRATE"}))
}

fn run_control(mode:&str) -> ExperimentResult<()> {
    let probe=if mode=="fail" {"root-negative"} else {"probe"};
    let cases=["open",probe,"close"].map(str::to_owned);
    let mut journal=Journal::new(mode,&cases,&["control"])?;
    let mut arm=open_arm(&mut journal,"control")?;
    let (_,_,a,b)=arm.node()?.settings().consensus_maintenance_material()?;
    if mode=="fail" {
        let negative=root_negative(&mut journal,&mut arm,&a,&b)?;
        close(&mut journal,&mut arm)?;
        return journal.finish(json!({"mode":mode,"result":"PASS","root_negative_control":negative,"meaning":"expected native ROOT refusal, not a child-process failure"}));
    }
    let context=arm.context(&journal,"probe",true);
    let parent=arm.node()?.settings().genesis();
    let header=header(&mut journal,&arm,&context,parent,development_public(7)?,&a,&b)?;
    let before=snapshot(&mut journal,&arm,&context,"cancel","before",None,None)?;
    prepare(&mut journal,&mut arm,&context,&a,&b)?;
    let attempt=format!("{}/attempt/0",context.operation_id);
    let span=journal.begin(&context,"producer","producer_attempt","window",Some(attempt),proof_metadata(&header,"partial-generation-control"))?;
    let mut tiles=0_u64;
    let marker=journal.root.join("unfinished.ready");
    let result=arm.cache.as_ref().ok_or("CACHE")?.prove_with_progress(header.challenge(),|point| {
        if matches!(point,PreparedGenerationProgress::TranscriptTile {..}) {
            tiles+=1;
            if tiles==32 {
                if mode=="unfinished" {
                    let marker_bytes=serde_json::to_vec(&json!({"run_id":journal.run_id,"operation_id":context.operation_id,
                        "pid":std::process::id(),"native_checkpoint":"TranscriptTile","checkpoint_ordinal":tiles,
                        "attempt_begin_synced":true,"status":"waiting-for-supervisor-termination"})).map_err(|e|e.to_string())?;
                    write_new(&marker,&marker_bytes).map_err(|e|e.to_string())?;
                    loop {std::thread::park();}
                }
                return Err("REQUESTED_CANCELLATION_AT_NATIVE_TILE_32".to_owned());
            }
        }
        Ok(())
    });
    match result {
        Err(PreparedGenerationError::Cancelled(reason))=> {
            let mut payload=proof_metadata(&header,"partial-generation-control");
            payload["reason"]=json!(reason);
            payload["hit"]=Value::Null;
            payload["proof_sha256"]=Value::Null;
            payload["transcript_tile_checkpoints"]=json!(tiles);
            payload["complete_proof"]=json!(false);
            journal.end(span,"cancelled",payload)?;
            journal.cancelled_attempts+=1;
        }
        other=> {
            journal.end(span,"failed",json!({"reason":format!("unexpected control result: {other:?}")}))?;
            return Err("CANCELLATION_CONTROL".into());
        }
    }
    let after=snapshot(&mut journal,&arm,&context,"cancel","after",None,None)?;
    require(state_unchanged(&before,&after),"CANCELLATION_CHANGED_LEDGER")?;
    close(&mut journal,&mut arm)?;
    journal.finish(json!({"mode":mode,"result":"PASS","before":before,"after":after,"actual_native_cancellation":true,
        "readback_unchanged":true,"complete_attempts":0,"no_admission_called":true}))
}

#[test]
#[ignore = "explicit SP27 research experiment: requires fresh output directory and source-bound supervisor"]
fn native_credit_observer() {
    let mode=env::var("TRNM_SP27_COST_MODE").unwrap_or_else(|_|"full".into());
    let result=match mode.as_str() {
        "full"=>run_full(),
        "cancel"|"unfinished"|"fail"=>run_control(&mode),
        _=>Err("MODE_MUST_BE_full_cancel_unfinished_or_fail".into()),
    };
    result.unwrap();
}
