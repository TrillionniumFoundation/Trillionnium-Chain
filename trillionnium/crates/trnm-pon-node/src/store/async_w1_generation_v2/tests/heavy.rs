//! Explicit, ignored, resource-heavy research entry. No fixture verifier is
//! reachable here. All files survive completion, failure and cold reconciliation.
//! A valid fresh proof with unknown resource accounting remains funded Pending.
use super::{balance, configuration, mine, open, public, signed};
use crate::store::async_w1_generation_v2::*;
use crate::store::StateBackend;
use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use trnm_service_settlement::native_generation_budget_v2::{
    DispatchDecisionV2, GenerationLaneV2, NativeGenerationStoreV2, OriginalDeadlineV2,
};

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| owner_error(format!("missing string field {key}")))
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| owner_error(format!("missing integer field {key}")))
}
fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    check(path.is_absolute(), "HEAVY_ABSOLUTE_PATH")?;
    check(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "HEAVY_SYMLINK",
    )?;
    let mut out = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut out)?;
    check(out.len() as u64 <= limit, "HEAVY_FILE_BOUND")?;
    Ok(out)
}
fn value(path: &Path) -> Result<Value> {
    serde_json::from_slice(&bytes(path, 8 * 1024 * 1024)?).map_err(owner_error)
}
fn write_new(path: &Path, v: &Value) -> Result<()> {
    let mut f = OpenOptions::new().create_new(true).write(true).open(path)?;
    f.write_all(&serde_json::to_vec_pretty(v).map_err(owner_error)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(path.parent().ok_or(error("HEAVY_PARENT"))?)?.sync_all()?;
    Ok(())
}
fn pin(v: &Value) -> Result<PathBuf> {
    let p = PathBuf::from(text(v, "path")?);
    let expected = json_hash(v, "sha256")?;
    // Executables may be large; hash in a bounded-memory streaming read.
    use sha2::{Digest, Sha256};
    check(
        p.is_absolute() && !fs::symlink_metadata(&p)?.file_type().is_symlink(),
        "HEAVY_PIN_PATH",
    )?;
    let mut f = File::open(&p)?;
    let mut h = Sha256::new();
    let mut chunk = [0u8; 65536];
    loop {
        let n = f.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        h.update(&chunk[..n]);
    }
    check(<Hash>::from(h.finalize()) == expected, "HEAVY_PIN_CHANGED")?;
    Ok(p)
}
fn now_ns() -> Result<u64> {
    let t =
        clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic)).map_err(owner_error)?;
    let sec = u64::try_from(t.tv_sec).map_err(owner_error)?;
    let nanos = u64::try_from(t.tv_nsec).map_err(owner_error)?;
    sec.checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or(error("HEAVY_CLOCK_OVERFLOW"))
}
fn original(c: &Value) -> Result<u64> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    check(
        boot.trim() == text(c, "original_boot_id")?,
        "HEAVY_ORIGINAL_BOOT",
    )?;
    let now = now_ns()?;
    check(
        now < number(c, "original_deadline_ns")?,
        "HEAVY_ORIGINAL_DEADLINE",
    )?;
    Ok(now)
}
fn clock_domain(c: &Value) -> Result<Hash> {
    // Exact canonical object used by the real local target, not a remote clock.
    Ok(sha256(
        &serde_json::to_vec(&json!({
            "schema":"trnm-w1-generation-posix-target-v2",
            "target_instance":text(c,"target_instance")?,
            "linux_boot_id":text(c,"original_boot_id")?
        }))
        .map_err(owner_error)?,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProofPlan {
    segment_workers: u64,
    compression_mode: &'static str,
    compression_workers: u64,
    rayon_threads: u64,
}
impl ProofPlan {
    fn parse(c: &Value) -> Result<Self> {
        let Some(v) = c.get("proof_plan") else {
            return Ok(Self {
                segment_workers: 2,
                compression_mode: "balanced",
                compression_workers: 2,
                rayon_threads: 4,
            });
        };
        let map = v.as_object().ok_or(error("HEAVY_PROOF_PLAN_OBJECT"))?;
        check(
            map.len() == 4
                && [
                    "segment_workers",
                    "compression_mode",
                    "compression_workers",
                    "rayon_threads",
                ]
                .iter()
                .all(|key| map.contains_key(*key)),
            "HEAVY_PROOF_PLAN_FIELDS",
        )?;
        let segment_workers = number(v, "segment_workers")?;
        let compression_workers = number(v, "compression_workers")?;
        let rayon_threads = number(v, "rayon_threads")?;
        let compression_mode = match text(v, "compression_mode")? {
            "balanced" => "balanced",
            "sequential" => "sequential",
            _ => return Err(error("HEAVY_PROOF_PLAN_MODE")),
        };
        check(
            (1..=4).contains(&segment_workers)
                && (1..=4).contains(&compression_workers)
                && (1..=8).contains(&rayon_threads)
                && segment_workers
                    .checked_mul(rayon_threads)
                    .is_some_and(|n| n <= 8)
                && compression_workers
                    .checked_mul(rayon_threads)
                    .is_some_and(|n| n <= 8)
                && (compression_mode != "sequential" || compression_workers == 1),
            "HEAVY_PROOF_PLAN_BUDGET",
        )?;
        Ok(Self {
            segment_workers,
            compression_mode,
            compression_workers,
            rayon_threads,
        })
    }
    fn argv(&self) -> Vec<String> {
        vec![
            "--segment-workers".into(),
            self.segment_workers.to_string(),
            "--compression-mode".into(),
            self.compression_mode.into(),
            "--compression-workers".into(),
            self.compression_workers.to_string(),
            "--rayon-threads".into(),
            self.rayon_threads.to_string(),
        ]
    }
    fn report(&self) -> Value {
        json!({"segment_workers":self.segment_workers,"compression_mode":self.compression_mode,
            "compression_workers":self.compression_workers,"rayon_threads":self.rayon_threads})
    }
}

#[test]
fn local_proof_plan_defaults_and_both_fresh_trial_argv_are_exact() {
    let balanced = ProofPlan::parse(&json!({})).unwrap();
    assert_eq!(
        balanced.report(),
        json!({"segment_workers":2,"compression_mode":"balanced","compression_workers":2,"rayon_threads":4})
    );
    assert_eq!(
        balanced.argv(),
        [
            "--segment-workers",
            "2",
            "--compression-mode",
            "balanced",
            "--compression-workers",
            "2",
            "--rayon-threads",
            "4"
        ]
    );
    let sequential = ProofPlan::parse(&json!({"proof_plan":{
        "segment_workers":1,"compression_mode":"sequential","compression_workers":1,"rayon_threads":8}})).unwrap();
    assert_eq!(
        sequential.argv(),
        [
            "--segment-workers",
            "1",
            "--compression-mode",
            "sequential",
            "--compression-workers",
            "1",
            "--rayon-threads",
            "8"
        ]
    );
    assert_ne!(balanced.report(), sequential.report());
}

#[test]
fn local_proof_plan_refuses_nonintegers_missing_fields_and_resource_overcommit() {
    let valid = json!({"segment_workers":2,"compression_mode":"balanced","compression_workers":2,"rayon_threads":4});
    for (key, bad) in [
        ("segment_workers", json!(true)),
        ("segment_workers", json!(2.0)),
        ("segment_workers", json!("2")),
        ("segment_workers", json!(-1)),
        ("segment_workers", json!(0)),
        ("segment_workers", json!(5)),
        ("compression_workers", json!(3)),
        ("rayon_threads", json!(5)),
        ("rayon_threads", json!(0)),
        ("rayon_threads", json!(9)),
        ("compression_mode", json!("sequential")),
        ("compression_mode", json!("unknown")),
    ] {
        let mut plan = valid.clone();
        plan[key] = bad;
        assert!(ProofPlan::parse(&json!({"proof_plan":plan})).is_err());
    }
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("rayon_threads");
    assert!(ProofPlan::parse(&json!({"proof_plan":missing})).is_err());
    let mut extra = valid;
    extra["renewed_deadline"] = json!(7200);
    assert!(ProofPlan::parse(&json!({"proof_plan":extra})).is_err());
    assert!(ProofPlan::parse(&json!({"proof_plan":null})).is_err());
}
// This research Node is written by one sequential owner at a time. Choosing a
// new output directory does not create permission to reuse an existing task.
fn research_funding(c: &Value, out: &Path) -> Result<(PathBuf, u64)> {
    let path = match c.get("research_node_path") {
        Some(v) => PathBuf::from(v.as_str().ok_or(error("HEAVY_RESEARCH_NODE_PATH"))?),
        None => out.join("research-node"),
    };
    check(path.is_absolute(), "HEAVY_RESEARCH_NODE_ABSOLUTE")?;
    if path.exists() {
        check(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "HEAVY_RESEARCH_NODE_SYMLINK",
        )?;
    }
    let nonce = if c.get("reserve_nonce").is_some() {
        number(c, "reserve_nonce")?
    } else {
        1
    };
    check(nonce > 0 && nonce < u64::MAX, "HEAVY_RESERVE_NONCE")?;
    Ok((path, nonce))
}
fn research_reserve(settings: &crate::Settings, nonce: u64) -> (Hash, Vec<u8>) {
    use trnm_protocol::pon_wire::hash;
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &nonce.to_le_bytes(),
            &public(1),
            &1000u64.to_le_bytes(),
            &20u64.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(1));
    payload.extend(1000u64.to_le_bytes());
    payload.extend(20u64.to_le_bytes());
    (task, signed(settings, 0, nonce, 2, payload))
}

#[test]
fn shared_research_node_uses_declared_reserve_nonce_and_rejects_old_nonce_after_cold_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("shared-research-node");
    let c = json!({"research_node_path":path,"reserve_nonce":1});
    assert_eq!(research_funding(&c, tmp.path()).unwrap(), (path.clone(), 1));
    for bad in [
        json!(0),
        json!(true),
        json!("2"),
        json!(2.0),
        json!(u64::MAX),
    ] {
        let mut wrong = c.clone();
        wrong["reserve_nonce"] = bad;
        assert!(research_funding(&wrong, tmp.path()).is_err());
    }
    let backend = StateBackend::PermanentAccountGrowthV2;
    let mut node = open(&path, backend);
    let settings = node.settings.clone();
    let (task1, wire1) = research_reserve(&settings, 1);
    let parent = node.active().unwrap().0;
    let tip1 = mine(&mut node, parent, vec![wire1.clone()]);
    drop(node);
    let mut node = open(&path, backend);
    assert_eq!(node.active().unwrap().0, tip1);
    super::reject(&mut node, tip1, wire1);
    let (task2, wire2) = research_reserve(&settings, 2);
    assert_ne!(task1, task2);
    mine(&mut node, tip1, vec![wire2]);
    for task in [task1, task2] {
        let funding = node
            .native_funding_observation(NativeFundingSourceV1::Task(task))
            .unwrap();
        let row = funding.row.unwrap();
        assert_eq!(row["status"], "reserved");
        assert_eq!(row["remaining"], 1000);
    }
}

fn phase(
    config_path: &Path,
    c: &Value,
    expected_config: Hash,
    name: &str,
    request: Option<&Path>,
) -> Result<Value> {
    check(
        sha256(&bytes(config_path, 131072)?) == expected_config,
        "HEAVY_CONFIG_CHANGED",
    )?;
    original(c)?;
    let python = pin(&c["python"])?;
    let helper = pin(&c["runtime"])?;
    let out = PathBuf::from(text(c, "out")?);
    let stdout = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join(format!("{name}-owner-stdout.log")))?;
    let stderr = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join(format!("{name}-owner-stderr.log")))?;
    let mut command = Command::new(&python);
    command
        .arg(&helper)
        .arg(name)
        .arg("--config")
        .arg(config_path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .current_dir(text(c, "repo")?);
    if let Some(path) = request {
        command.arg("--request").arg(path);
    }
    let started = now_ns()?;
    let mut child = command.spawn()?;
    write_new(
        &out.join(format!("{name}-owner-process.json")),
        &json!({
            "schema":"TRNM-W1-FUNDED-OWNER-PROCESS2", "phase":name,"pid":child.id(),
            "started_monotonic_ns":started,"original_deadline_ns":number(c,"original_deadline_ns")?,
            "boot_id":text(c,"original_boot_id")?,"python":c["python"],"runtime":c["runtime"],
            "config_sha256":hex::encode(expected_config),"renewed_deadline":false
        }),
    )?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if now_ns()? >= number(c, "original_deadline_ns")?.saturating_add(10_000_000_000) {
            // Eligibility already ended at the ORIGINAL deadline. The helper's
            // bounded cleanup should have completed; otherwise retain UNKNOWN.
            let _ = child.kill();
            let _ = child.wait();
            write_new(
                &out.join(format!("{name}-owner-cleanup-unknown.json")),
                &json!({
                    "schema":"TRNM-W1-FUNDED-OWNER-CLEANUP2","all_owned_descendants_terminal":false,
                    "may_release_resources":false,"can_authorize_payment":false,
                    "original_deadline_ns":number(c,"original_deadline_ns")?
                }),
            )?;
            return Err(error("HEAVY_CLEANUP_UNKNOWN"));
        }
        thread::sleep(Duration::from_millis(100));
    };
    check(status.success(), "HEAVY_OWNED_PROCESS_FAILED")?;
    original(c)?;
    pin(&c["python"])?;
    pin(&c["runtime"])?;
    check(
        sha256(&bytes(config_path, 131072)?) == expected_config,
        "HEAVY_CONFIG_CHANGED",
    )?;
    let result = value(&out.join(format!("{name}-runtime-result.json")))?;
    check(
        result["schema"] == "TRNM-W1-OWNED-GENERATION-RUNTIME2"
            && result["phase"] == name
            && result["operation_complete"] == true
            && result["config_sha256"] == hex::encode(expected_config)
            && result["original_deadline_ns"] == c["original_deadline_ns"]
            && result["boot_id"] == c["original_boot_id"],
        "HEAVY_OWNED_RESULT",
    )?;
    Ok(result)
}

struct LocalRuntime {
    config_path: PathBuf,
    config: Value,
    config_hash: Hash,
    generation: Option<Value>,
    evidence_digest: Hash,
}
impl LocalRuntime {
    fn costs(v: &Value, receipt_bytes: u64) -> Result<GenerationResourcesV2> {
        check(
            v["scope_complete_for_local_processes"] == true,
            "HEAVY_PROCESS_SCOPE_UNKNOWN",
        )?;
        // Null is not zero. The currently reviewed r0vm has no complete GPU
        // accounting provenance, so real runs preserve funded Pending here.
        check(
            v["gpu_accounting_qualified"] == true,
            "HEAVY_GPU_ACCOUNTING_UNKNOWN",
        )?;
        Ok(GenerationResourcesV2 {
            cpu_ns: number(v, "cpu_ns")?,
            gpu_ns: number(v, "gpu_ns")?,
            memory_peak_upper_bound_bytes: number(v, "memory_peak_upper_bound_bytes")?,
            receipt_bytes,
        })
    }
}
impl OwnedGenerationRuntimeV2 for LocalRuntime {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        Ok(ClockCheckpointV2 {
            clock_domain: clock_domain(&self.config)?,
            now_ns: original(&self.config)?,
        })
    }
    fn reconcile_fresh_execution(
        &mut self,
        s: &GenerationStatementV2,
        job: &ProviderJobV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2> {
        let v = self
            .generation
            .as_ref()
            .ok_or(error("HEAVY_NO_ACTUAL_GENERATION"))?;
        check(
            v["fresh_trial_count"] == 1
                && v["reused_segments"] == false
                && text(&v["target_job"], "job_id")? == job.job_id
                && json_hash(v, "receipt_sha256")? == sha256(e.receipt)
                && e.owned_execution_evidence == self.evidence_digest
                && s.execution_source_commitment == self.config_hash,
            "HEAVY_FRESH_EXECUTION_BINDING",
        )?;
        let resources = Self::costs(&v["scope"], e.receipt.len() as u64)?;
        Ok(OwnedFullGenerationV2 {
            job: job.clone(),
            execution_source_commitment: self.config_hash,
            input_sha256: s.input_sha256,
            guest_sha256: json_hash(&self.config["guest"], "sha256")?,
            evidence_digest: self.evidence_digest,
            receipt_sha256: sha256(e.receipt),
            resources,
            controller_received: self.clock_checkpoint()?,
        })
    }
    fn run_independent_verifier(
        &mut self,
        _s: &GenerationStatementV2,
        _e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2> {
        let v = phase(
            &self.config_path,
            &self.config,
            self.config_hash,
            "verify",
            None,
        )?;
        let out = PathBuf::from(text(&self.config, "out")?);
        Ok(OwnedVerifierRunV2 {
            executable_sha256: json_hash(&self.config["verifier"], "sha256")?,
            successful_exit: v["process"]["returncode"] == 0,
            stdout: bytes(&out.join("node-independent-verifier/stdout.log"), 16384)?,
            resources: Self::costs(&v["scope"], 0)?,
            finished: self.clock_checkpoint()?,
        })
    }
}

fn execute(config_path: &Path) -> Result<()> {
    let raw = bytes(config_path, 131072)?;
    let c: Value = serde_json::from_slice(&raw).map_err(owner_error)?;
    check(
        c["schema"] == "TRNM-W1-FUNDED-HEAVY-CONFIG2"
            && c["profile_id"] == PROFILE
            && c["chain_deadline"] == 20,
        "HEAVY_EXPLICIT_DECLARATION",
    )?;
    let proof_plan = ProofPlan::parse(&c)?;
    let started = original(&c)?;
    check(
        number(&c, "original_deadline_ns")? - started <= 7_200_000_000_000,
        "HEAVY_ORIGINAL_BUDGET_BOUND",
    )?;
    let out = PathBuf::from(text(&c, "out")?);
    let (node_path, reserve_nonce) = research_funding(&c, &out)?;
    check(
        out.is_absolute() && !out.exists(),
        "HEAVY_FRESH_EXTERNAL_OUTPUT_REQUIRED",
    )?;
    fs::create_dir(&out)?;
    let own = std::env::current_exe()?;
    pin(&json!({"path":own,"sha256":text(&c,"owner_test_binary_sha256")?}))?;
    let config_hash = sha256(&raw);
    write_new(
        &out.join("owner-declaration.json"),
        &json!({
            "schema":"TRNM-W1-FUNDED-OWNER2","config_sha256":hex::encode(config_hash),
            "owner_test_binary":own,"owner_test_binary_sha256":text(&c,"owner_test_binary_sha256")?,
            "original_deadline_ns":number(&c,"original_deadline_ns")?,"boot_id":text(&c,"original_boot_id")?,
            "started_monotonic_ns":started,"research_genesis_only":true,"public_chain_transactions_sent":false,
            "native_obligation_units":1000,"native_chain_deadline":20,
            "research_node_path":node_path,"reserve_nonce":reserve_nonce,"provider_receipt_nonce":1,
            "research_node_write_scope":"one sequential owner for the complete operation; no concurrent writer qualification",
            "payment_scope":"requires unchanged Reserve tip; fixed provider Receipt nonce 1; no intervening owner operation",
            "local_proof_plan":(c["provider"]["kind"] != "kaggle-cli").then(||proof_plan.report())
        }),
    )?;
    let winner = phase(config_path, &c, config_hash, "winner", None)?;
    let n = &winner["native"];
    let winner_ns = number(&winner["winner"], "native_winner_monotonic_ns")?;
    let backend = StateBackend::PermanentAccountGrowthV2;
    let mut node = open(&node_path, backend);
    let cfg = configuration(&node);
    let settings = node.settings.clone();
    let reserve_parent = node.active().map_err(owner_error)?.0;
    let (task, wire) = research_reserve(&settings, reserve_nonce);
    // No retry or nonce reselection: the actual native owner must accept this
    // exact signed Reserve on the currently active research chain.
    let reserve_tip = mine(&mut node, reserve_parent, vec![wire]);
    let journal_path = out.join("native-generation-v2.sqlite");
    let mut store = NativeGenerationStoreV2::open(&journal_path, cfg.clone())?;
    let mut runtime = LocalRuntime {
        config_path: config_path.into(),
        config: c.clone(),
        config_hash,
        generation: None,
        evidence_digest: [0; 32],
    };
    let member = fs::read_to_string("/proc/self/cgroup")?;
    check(
        member.lines().count() == 1 && member.starts_with("0::/"),
        "HEAVY_CGROUP_IDENTITY",
    )?;
    let cg = Path::new("/sys/fs/cgroup").join(member.trim()[3..].trim_start_matches('/'));
    let operation = json_hash(&c, "provider_operation")?;
    let task_scope = sha256(
        &[
            b"native-task-provider-fence-v2".as_slice(),
            &settings.network(),
            &settings.parameters(),
            &task,
        ]
        .concat(),
    );
    let provider_namespace = sha256(text(&c, "target_instance")?.as_bytes());
    let kaggle = c["provider"]["kind"] == "kaggle-cli";
    let mut request = if kaggle {
        let selection = &winner["provider_selection"];
        check(
            selection["request_id"] == c["provider"]["request_id"],
            "HEAVY_PROVIDER_REQUEST_CHANGED",
        )?;
        json!({"source":text(selection,"source")?,"binding":{
            "schema":"trnm-w1-kaggle-generation-target-v2",
            "request_id":selection["request_id"],"task_scope":hex::encode(task_scope),
            "journal_identity":hex::encode(store.journal_identity()),"operation":hex::encode(operation),
            "provider_namespace":hex::encode(provider_namespace),
            "account_username":text(&c["provider"],"account_username")?,
            "intent":selection["intent"],"input_digest":selection["input_digest"],
            "original_controller_deadline":{"clock_domain":hex::encode(clock_domain(&c)?),
                "winner_ns":winner_ns,"deadline_ns":number(&c,"original_deadline_ns")?}
        }})
    } else {
        let mut pins = serde_json::Map::new();
        for name in [
            "python", "target", "runtime", "runner", "r0vm", "verifier", "guest",
        ] {
            let path = pin(&c[name])?;
            pins.insert(
                path.to_string_lossy().into_owned(),
                c[name]["sha256"].clone(),
            );
        }
        let repo = PathBuf::from(text(&c, "repo")?);
        for (path, digest) in c["source_files"]
            .as_object()
            .ok_or(error("HEAVY_SOURCE_PINS"))?
        {
            pins.insert(
                repo.join(path).to_string_lossy().into_owned(),
                digest.clone(),
            );
        }
        let mut argv = vec![
            text(&c["python"], "path")?.to_string(),
            repo.join("scripts/run_w1_postwin_proof.py")
                .display()
                .to_string(),
            "--winner-dir".into(),
            out.join("native-winner").display().to_string(),
            "--runner".into(),
            text(&c["runner"], "path")?.into(),
            "--runner-sha256".into(),
            text(&c["runner"], "sha256")?.into(),
            "--r0vm".into(),
            text(&c["r0vm"], "path")?.into(),
            "--r0vm-sha256".into(),
            text(&c["r0vm"], "sha256")?.into(),
            "--verifier".into(),
            text(&c["verifier"], "path")?.into(),
            "--verifier-sha256".into(),
            text(&c["verifier"], "sha256")?.into(),
            "--out".into(),
            out.join("proof").display().to_string(),
        ];
        argv.extend(proof_plan.argv());
        json!({
            "schema":"trnm-w1-generation-posix-target-v2","target_instance":text(&c,"target_instance")?,
            "operation":hex::encode(operation),"task_scope":hex::encode(task_scope),
            "provider_namespace":hex::encode(provider_namespace),"execution_source_commitment":hex::encode(config_hash),
            "target_backend_sha256":c["target"]["sha256"],"clock_domain":hex::encode(clock_domain(&c)?),
            "winner_monotonic_ns":winner_ns,"deadline_monotonic_ns":number(&c,"original_deadline_ns")?,
            "cwd":repo,"argv":argv,"proof_plan":proof_plan.report(),
            "file_pins":pins,"environment":{"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C",
                "RAYON_NUM_THREADS":"8","PYTHONDONTWRITEBYTECODE":"1"},
            "cpus":c["cpus"],"total_threads":8,"containment":"cgroup-v2","cgroup_parent":cg,
            "cleanup_grace_ns":5_000_000_000u64
        })
    };
    // The normalized dispatch core excludes statement ID to avoid a hash fixed
    // point. Full target request bytes additionally bind the resulting ID, and
    // the actual target stores/verifies its distinct canonical request SHA256.
    let request_digest = if kaggle {
        json_hash(&winner["provider_selection"], "input_digest")?
    } else {
        sha256(&serde_json::to_vec(&request).map_err(owner_error)?)
    };
    let cap = &c["resource_cap"];
    let statement = GenerationStatementV2 {
        lane: GenerationLaneV2::FullW1ProofGeneration,
        task,
        owner: public(0),
        provider: public(1),
        input_sha256: json_hash(n, "input_sha256")?,
        header_sha256: json_hash(n, "header_sha256")?,
        expected_artifacts_sha256: json_hash(n, "expected_artifacts_sha256")?,
        expected_journal_sha256: json_hash(n, "journal_sha256")?,
        expected_work_id: json_hash(n, "work_id")?,
        image_id: serde_json::from_value(c["image_id"].clone()).map_err(owner_error)?,
        guest_sha256: json_hash(&c["guest"], "sha256")?,
        verifier_binary_sha256: json_hash(&c["verifier"], "sha256")?,
        execution_source_commitment: config_hash,
        original_deadline: OriginalDeadlineV2 {
            clock_domain: clock_domain(&c)?,
            winner_ns,
            deadline_ns: number(&c, "original_deadline_ns")?,
        },
        chain_deadline: 20,
        provider_namespace,
        provider_operation: operation,
        request_digest,
        resource_cap: GenerationResourcesV2 {
            cpu_ns: number(cap, "cpu_ns")?,
            gpu_ns: number(cap, "gpu_ns")?,
            memory_peak_upper_bound_bytes: number(cap, "memory_peak_upper_bound_bytes")?,
            receipt_bytes: number(cap, "receipt_bytes")?,
        },
    };
    let id = {
        let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut runtime)?;
        let id = store.prepare(&mut owner, statement.clone())?;
        check(
            matches!(store.begin(&mut owner, id)?, DispatchDecisionV2::New),
            "HEAVY_RECONCILE_ONLY",
        )?;
        id
    };
    if kaggle {
        request["binding"]["statement"] = json!(hex::encode(id));
    } else {
        request["statement"] = json!(hex::encode(id));
    }
    let request_path = out.join("target-request.json");
    write_new(&request_path, &request)?;
    write_new(
        &out.join("native-funded-intent.json"),
        &json!({
            "schema":"TRNM-W1-FUNDED-DISPATCH2","task":hex::encode(task),"statement":hex::encode(id),
            "journal_identity":hex::encode(store.journal_identity()),"provider_operation":hex::encode(operation),
            "normalized_request_digest":hex::encode(request_digest),"target_request_sha256":hex::encode(sha256(&serde_json::to_vec(&request).map_err(owner_error)?)),
            "native_reserve_tip":hex::encode(reserve_tip),"native_reserve_parent":hex::encode(reserve_parent),
            "research_node_path":node_path,"reserve_nonce":reserve_nonce,"native_obligation_units":1000,
            "winner_monotonic_ns":winner_ns,"original_deadline_ns":number(&c,"original_deadline_ns")?,
            "can_authorize_payment":false,"research_genesis_only":true,
            "local_proof_plan":(!kaggle).then(||proof_plan.report())
        }),
    )?;
    // The actual expensive process is launched only after both real native
    // Reserve and the M12 durable Intent above. There is no verifier fixture.
    let generated = phase(
        config_path,
        &c,
        config_hash,
        "generate",
        Some(&request_path),
    )?;
    let evidence_hash = sha256(&bytes(
        &out.join("generate-runtime-result.json"),
        8 * 1024 * 1024,
    )?);
    runtime.evidence_digest = evidence_hash;
    runtime.generation = Some(generated.clone());
    let job = ProviderJobV2 {
        provider_namespace,
        operation,
        request_digest,
        job_id: text(&generated["target_job"], "job_id")?.into(),
    };
    store.bind_job(id, job)?;
    let receipt = bytes(&out.join("proof/checkpoint/succinct.bin"), 64 * 1024 * 1024)?;
    let header = bytes(&out.join("native-winner/header.bin"), 318)?;
    let expected = bytes(&out.join("native-winner/expected-artifacts.bin"), 64)?;
    let evidence = GenerationEvidenceV2 {
        receipt: &receipt,
        header: &header,
        expected_artifacts: &expected,
        owned_execution_evidence: evidence_hash,
    };
    let resources_complete = generated["scope"]["gpu_accounting_qualified"] == true;
    if !resources_complete {
        // Full cryptographic fact is still measured independently. Resource
        // uncertainty does not block funded execution and cannot create Positive.
        let verified = phase(config_path, &c, config_hash, "verify", None)?;
        let parent_observed_verifier_ns = original(&c)?;
        check(
            verified["full_proof_verified"] == true,
            "HEAVY_ACTUAL_FULL_VERIFIER",
        )?;
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut runtime)?;
            check(
                store.verify(&mut owner, id, &evidence).is_err(),
                "HEAVY_UNKNOWN_RESOURCE_POSITIVE",
            )?;
        }
        let before = store.readback(id)?;
        check(
            before.verified.is_none()
                && before.historical_payment.is_none()
                && before.dispatch_intent,
            "HEAVY_PENDING_REQUIRED",
        )?;
        check(
            before.resource_charge == statement.resource_cap,
            "HEAVY_RESERVATION_RETAINED",
        )?;
        let funding = node
            .native_funding_observation(NativeFundingSourceV1::Task(task))
            .map_err(owner_error)?;
        let row = funding
            .row
            .ok_or(error("HEAVY_NATIVE_RESERVATION_MISSING"))?;
        check(
            row["status"] == "reserved" && row["remaining"] == 1000,
            "HEAVY_NATIVE_RESERVATION_CHANGED",
        )?;
        drop(store);
        drop(node);
        let mut node = open(&node_path, backend);
        let mut store = NativeGenerationStoreV2::open(&journal_path, cfg)?;
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut runtime)?;
            check(
                matches!(store.begin(&mut owner, id)?, DispatchDecisionV2::Pending),
                "HEAVY_COLD_REDISPATCH",
            )?;
        }
        check(store.readback(id)? == before, "HEAVY_COLD_PENDING_CHANGED")?;
        write_new(
            &out.join("funded-result.json"),
            &json!({
                "schema":"TRNM-W1-FUNDED-FRESH-RESULT2","fresh_proof_trials":1,"full_proof_verified":true,
                "receipt_sha256":hex::encode(sha256(&receipt)),"native_task":hex::encode(task),"statement":hex::encode(id),
                "winner_to_independent_verifier_ns":parent_observed_verifier_ns.checked_sub(winner_ns),
                "parent_observed_verifier_monotonic_ns":parent_observed_verifier_ns,
                "verifier_helper_completed_monotonic_ns":number(&verified,"verified_monotonic_ns")?,
                "latency_scope":"original owner clock: native ticket hit through parent-observed independent verifier helper exit and result binding",
                "original_deadline_ns":number(&c,"original_deadline_ns")?,"boot_id":text(&c,"original_boot_id")?,
                "funded_generation":"Pending","resource_accounting":"GPU_UNKNOWN",
                "native_remaining_units":1000,"resource_reservation_retained":true,"cold_replay_dispatch":"Pending",
                "research_node_path":node_path,"reserve_nonce":reserve_nonce,
                "node_positive":false,"payment_observed":false,"can_authorize_payment":false,
                "production_qualified":false,"public_chain_transactions_sent":false,
                "local_proof_plan":(!kaggle).then(||proof_plan.report())
            }),
        )?;
        return Ok(());
    }
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut runtime)?;
        store.verify(&mut owner, id, &evidence)?;
    }
    let proof_verified_ns = original(&c)?;
    // This ignored research entry qualifies only one sequential writer for the
    // complete operation. Refuse an intervening chain operation rather than
    // silently branching from the old Reserve or choosing another Settle nonce.
    check(
        node.active().map_err(owner_error)?.0 == reserve_tip,
        "HEAVY_INTERVENING_NATIVE_OPERATION",
    )?;
    let mut payload = task.to_vec();
    payload.extend(id);
    let receipt_tip = mine(
        &mut node,
        reserve_tip,
        vec![signed(&settings, 1, 1, 4, payload.clone())],
    );
    let provider_before = balance(&node, public(1));
    let settle_wire = signed(&settings, 0, reserve_nonce + 1, 5, payload);
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut runtime)?;
        check(
            matches!(
                store.prepare_settlement(&mut owner, id, settle_wire.clone())?,
                DispatchDecisionV2::New
            ),
            "HEAVY_SETTLEMENT_REPLAY",
        )?;
    }
    let payment_tip = mine(&mut node, receipt_tip, vec![settle_wire]);
    check(
        balance(&node, public(1)) == provider_before + 1000,
        "HEAVY_NATIVE_PAYMENT",
    )?;
    drop(store);
    drop(node);
    let mut node = open(&node_path, backend);
    let mut store = NativeGenerationStoreV2::open(&journal_path, cfg)?;
    store.record_payment(&mut node, id)?;
    let observed = store.reobserve_payment(&mut node, id)?;
    let paid = store.readback(id)?;
    store.record_payment(&mut node, id)?;
    check(
        store.readback(id)? == paid,
        "HEAVY_DUPLICATE_PAYMENT_HISTORY",
    )?;
    let finished = original(&c)?;
    write_new(
        &out.join("funded-result.json"),
        &json!({
            "schema":"TRNM-W1-FUNDED-FRESH-RESULT2","fresh_proof_trials":1,"full_proof_verified":true,
            "receipt_sha256":hex::encode(sha256(&receipt)),"native_task":hex::encode(task),"statement":hex::encode(id),
            "winner_to_independent_verifier_ns":proof_verified_ns.checked_sub(winner_ns),
            "winner_to_native_payment_observed_ns":finished.checked_sub(winner_ns),
            "original_deadline_ns":number(&c,"original_deadline_ns")?,"boot_id":text(&c,"original_boot_id")?,
            "funded_generation":"historical payment; canonical reobservation passed",
            "node_positive":true,"payment_observed":true,"native_gross_units":1000,
            "research_node_path":node_path,"reserve_nonce":reserve_nonce,"provider_receipt_nonce":1,
            "payment_operation":hex::encode(observed.operation),"payment_tip":hex::encode(payment_tip),
            "production_qualified":false,"public_chain_transactions_sent":false,
            "local_proof_plan":(!kaggle).then(||proof_plan.report())
        }),
    )?;
    Ok(())
}

#[test]
#[ignore = "explicit resource-heavy fresh full-W1 proof; requires clean frozen source and TRNM_W1_FUNDED_CONFIG"]
fn funded_fresh_full_w1_generation() {
    let path = PathBuf::from(std::env::var_os("TRNM_W1_FUNDED_CONFIG").expect(
        "explicit absolute TRNM_W1_FUNDED_CONFIG is required; there is no fixture or skip fallback",
    ));
    execute(&path).expect("funded full-W1 research operation failed; retain original evidence and reconcile, never redispatch");
}
