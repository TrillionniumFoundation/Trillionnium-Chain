//! Explicit native observations, with real signed admission and retained history.
//! Account preallocation is setup, never a substitute for the 65,536 crossing gate.
use super::*;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

const ACCOUNT_COUNTS: [usize; 3] = [64, 1024, 16_384];
const HISTORY_LENGTHS: [usize; 3] = [0, 16, 128];
const MEASURED_BLOCKS: usize = 8;
const COUNTER_NAMES: [&str; 9] = [
    "context_checks",
    "header_ancestors",
    "full_work_checkpoints",
    "execution_checkpoints",
    "cow_account_node_checkpoints",
    "reorg_ancestors",
    "reorg_writes",
    "reorg_readbacks",
    "before_commit_checks",
];

struct ProgressObservation {
    started: Instant,
    counters: [AtomicU64; COUNTER_NAMES.len()],
    before_persistence_ns: AtomicU64,
    before_commit_ns: AtomicU64,
}

impl ProgressObservation {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            before_persistence_ns: AtomicU64::new(0),
            before_commit_ns: AtomicU64::new(0),
        }
    }

    fn progress(&self, point: GrowthProgress) -> Result<()> {
        let counter = match point {
            GrowthProgress::BeforeContext => Some(0),
            GrowthProgress::HeaderAncestor { .. } => Some(1),
            GrowthProgress::Work(_) => Some(2),
            GrowthProgress::Execution(_) => Some(3),
            GrowthProgress::AccountNode => Some(4),
            GrowthProgress::ReorgAncestor { .. } => Some(5),
            GrowthProgress::ReorgWrite { .. } => Some(6),
            GrowthProgress::ReorgReadback { .. } => Some(7),
            GrowthProgress::BeforeCommit => {
                self.before_commit_ns
                    .store(elapsed_ns(self.started), Ordering::Relaxed);
                Some(8)
            }
            GrowthProgress::BeforePersistence => {
                self.before_persistence_ns
                    .store(elapsed_ns(self.started), Ordering::Relaxed);
                None
            }
            _ => None,
        };
        if let Some(index) = counter {
            self.counters[index].fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn finish(&self, wall_ns: u64) -> Value {
        let counters: BTreeMap<_, _> = COUNTER_NAMES
            .iter()
            .zip(&self.counters)
            .map(|(name, counter)| (*name, counter.load(Ordering::Relaxed)))
            .collect();
        let persistence = self.before_persistence_ns.load(Ordering::Relaxed);
        let commit = self.before_commit_ns.load(Ordering::Relaxed);
        json!({
            "wall_ns": wall_ns,
            "checkpoints": counters,
            "before_persistence_offset_ns": (persistence != 0).then_some(persistence),
            "before_commit_offset_ns": (commit != 0).then_some(commit),
            "persistence_and_readback_wall_ns": (persistence != 0 && commit >= persistence).then(|| commit - persistence),
            "final_guard_and_sqlite_commit_wall_ns": (commit != 0 && wall_ns >= commit).then(|| wall_ns - commit),
            "timing_scope": "inclusive wall time; offsets and nested intervals must not be summed"
        })
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap()
}

fn append(file: &mut File, value: &Value) {
    serde_json::to_writer(&mut *file, value).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
    eprintln!("{value}");
}

fn create(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
}

fn fixture(accounts: usize) -> Settings {
    let mut source = base_settings();
    let mut count = archive::accounts(&source.initial).unwrap().len();
    assert!(count <= accounts);
    let mut index = 0u64;
    while count < accounts {
        let owner = hash(
            b"native-growth-fixed-owners-observation-v1",
            &[&index.to_le_bytes()],
        );
        let previous = source.initial.insert(
            format!("account:{}", hex::encode(owner)),
            json!({"balance":0,"nonce":7}),
        );
        assert!(previous.is_none());
        index += 1;
        count += 1;
    }
    source
        .with_permanent_account_growth_v2("native-growth-fixed-owners-observation-v1")
        .unwrap()
}

fn sql_counts(node: &Node) -> BTreeMap<&'static str, u64> {
    [
        "blocks",
        "growth_states",
        "archive_nodes",
        "deltas",
        "events",
        "steps",
    ]
    .into_iter()
    .map(|table| {
        let count = node
            .db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        (table, count)
    })
    .collect()
}

fn disk_sample(path: &Path) -> Value {
    let sizes: BTreeMap<_, _> = ["native.sqlite", "native.sqlite-wal", "native.sqlite-shm"]
        .into_iter()
        .map(|name| {
            let bytes = match fs::metadata(path.join(name)) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(error) => panic!("disk observation failed: {error}"),
            };
            (name, bytes)
        })
        .collect();
    json!({"file_bytes":sizes,"scope":"point sample; not peak disk, WAL, RSS or device memory"})
}

fn working_observation(state: &State) -> Value {
    let mandatory = limits::mandatory_owners(state).unwrap();
    let categories: BTreeMap<_, _> = ["reward:", "task:", "quota:", "escrow:"]
        .into_iter()
        .map(|prefix| {
            (
                prefix,
                state.keys().filter(|key| key.starts_with(prefix)).count(),
            )
        })
        .collect();
    json!({
        "keys": state.len(),
        "canonical_bytes": canonical(state).unwrap().len(),
        "mandatory_owner_count": mandatory.len(),
        "mandatory_owners": mandatory,
        "obligation_rows_by_prefix": categories
    })
}

fn verify_complete_reference(node: &Node, id: Hash, expected: &State, accounts: usize) {
    let observation = node.growth_observe(id).unwrap();
    assert_eq!(observation.permanent_accounts, accounts as u64);
    assert_eq!(
        observation.commitment,
        *growth_commitment_from_complete_state_v2(node.settings(), expected)
            .unwrap()
            .observation()
    );
    assert_eq!(node.growth_working(id).unwrap(), working(expected));
    // Full-root equality above covers all accounts, liabilities and issued
    // supply. These independent point queries additionally cover live nonces.
    for owner in [public(0), public(1), public(3)] {
        let value = &expected[&format!("account:{}", hex::encode(owner))];
        assert_eq!(
            node.growth_account(id, owner).unwrap(),
            Some(Account {
                balance: value["balance"].as_u64().unwrap(),
                nonce: value["nonce"].as_u64().unwrap(),
            })
        );
    }
}

#[test]
#[ignore = "explicit native A/H observation: full State reference, real W1/signed admission, atomic cancellation and cold reopen"]
fn native_growth_v2_fixed_owner_account_history_scale_observation() {
    let output = std::env::var_os("TRNM_GROWTH_SCALE_OBSERVATION_DIR").expect(
        "explicit observation requires TRNM_GROWTH_SCALE_OBSERVATION_DIR to name a new directory",
    );
    let output = Path::new(&output);
    // Atomic, create-only run directory: preserve incomplete and failed attempts.
    fs::create_dir(output).unwrap();
    let mut manifest = create(&output.join("run.jsonl"));
    append(
        &mut manifest,
        &json!({
            "schema":"native-growth-fixed-owner-scale-observation-v1",
            "event":"run_started",
            "accounts":ACCOUNT_COUNTS,
            "warmup_history_blocks":HISTORY_LENGTHS,
            "measured_blocks_per_cohort":MEASURED_BLOCKS,
            "transaction":"one signed sender 0 to existing recipient 1, amount 1, consecutive nonce; miner 3",
            "declared_transaction_owners":[hex::encode(public(0)),hex::encode(public(1)),hex::encode(public(3))],
            "workers":1,
            "work_search_attempt_limit":4096,
            "fixture_scope":"preallocated dormant accounts; real empty maintenance warmup history; original 65,536 signed growth gate remains separate",
            "measurement_scope":"direct native Node only; no WAN, client confirmation, public admission qualification or throughput claim",
            "setup_reference_diagnostics_and_cancellation_excluded_from_native_stage_timings":true,
            "p99_ns":null,
            "wall_time_acceptance_gate":false,
            "completed":false
        }),
    );
    let mut all_owner_sets = BTreeSet::new();
    for accounts in ACCOUNT_COUNTS {
        for history in HISTORY_LENGTHS {
            let mut report = create(&output.join(format!("cohort-a{accounts}-h{history}.jsonl")));
            append(
                &mut report,
                &json!({"event":"cohort_started","accounts":accounts,"warmup_history_blocks":history,"planned_measurements":MEASURED_BLOCKS}),
            );
            let setup_started = Instant::now();
            let settings = fixture(accounts);
            let dir = tempfile::tempdir().unwrap();
            let mut node =
                Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
            let setup_ns = elapsed_ns(setup_started);
            let mut full = settings.initial.clone();
            let mut parent = settings.genesis();
            let mut warmup_native_ns = 0u64;
            let mut warmup_reference_ns = 0u64;
            for index in 0..history {
                append(
                    &mut report,
                    &json!({"event":"warmup_started","index":index,"parent":hex::encode(parent)}),
                );
                let started = Instant::now();
                let packet = make(&node, parent, Vec::new());
                parent = admit(&mut node, &packet);
                warmup_native_ns += elapsed_ns(started);
                let started = Instant::now();
                full = reference(&settings, &full, &packet);
                warmup_reference_ns += elapsed_ns(started);
            }
            verify_complete_reference(&node, parent, &full, accounts);
            append(
                &mut report,
                &json!({
                    "event":"warmup_completed","setup_wall_ns":setup_ns,
                    "native_warmup_wall_ns":warmup_native_ns,"full_reference_warmup_wall_ns":warmup_reference_ns,
                    "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
                    "genesis":hex::encode(settings.genesis()),"sql_rows":sql_counts(&node),
                    "working":working_observation(&node.growth_working(parent).unwrap()),"disk_sample":disk_sample(dir.path())
                }),
            );
            let mut admission_times = Vec::new();
            for sample in 0..MEASURED_BLOCKS {
                let parent_height = node.record(parent).unwrap().height;
                assert_eq!(parent_height, (history + sample) as u64);
                append(
                    &mut report,
                    &json!({"event":"measurement_started","sample":sample,"parent":hex::encode(parent),"history_blocks_before":parent_height}),
                );
                let before = sql_counts(&node);
                let parent_working = working_observation(&node.growth_working(parent).unwrap());
                let started = Instant::now();
                let packet = make(
                    &node,
                    parent,
                    vec![transfer(&settings, 0, (sample + 1) as u64, public(1), 1)],
                );
                let make_ns = elapsed_ns(started);
                let owners: BTreeSet<_> = packet
                    .accounts
                    .accounts
                    .iter()
                    .map(|account| hex::encode(account.owner))
                    .collect();
                all_owner_sets.insert(owners.clone());
                let changes_before = node.db.total_changes();
                let admission = ProgressObservation::new();
                let id = node
                    .admit_growth_with_progress(&packet, 100_000, &|point| {
                        admission.progress(point)
                    })
                    .unwrap();
                let admission_ns = elapsed_ns(admission.started);
                let admission_changes = node.db.total_changes() - changes_before;
                let changes_before = node.db.total_changes();
                let activation = ProgressObservation::new();
                assert_eq!(
                    node.growth_activate_with_progress(id, &|point| activation.progress(point))
                        .unwrap(),
                    id
                );
                let activation_ns = elapsed_ns(activation.started);
                let activation_changes = node.db.total_changes() - changes_before;
                admission_times.push(admission_ns);
                let started = Instant::now();
                full = reference(&settings, &full, &packet);
                verify_complete_reference(&node, id, &full, accounts);
                let reference_ns = elapsed_ns(started);
                assert_eq!(node.next_nonce(public(0)).unwrap(), (sample + 2) as u64);
                let after = sql_counts(&node);
                assert_eq!(after["blocks"], before["blocks"] + 1);
                assert_eq!(after["growth_states"], before["growth_states"] + 1);
                assert_eq!(after["events"], before["events"] + 1);
                let query_owners: Vec<_> = packet
                    .accounts
                    .accounts
                    .iter()
                    .map(|account| account.owner)
                    .collect();
                let (_, query, reads) = node.growth_account_multiproof(id, &query_owners).unwrap();
                assert_eq!(reads.expanded_witnesses_allocated, 0);
                append(
                    &mut report,
                    &json!({
                        "event":"measurement_completed","sample":sample,"block":hex::encode(id),
                        "accounts":accounts,"history_blocks_before":parent_height,"history_blocks_after":parent_height + 1,
                        "actual_witness_accounts":owners.len(),"actual_witness_owners":owners,
                        "witness_bytes":packet.accounts.encoded_len().unwrap(),"witness_frontier_nodes":packet.accounts.frontier.len(),
                        "packet_bytes":packet.encode().unwrap().len(),"full_work_proof_bytes":packet.proof.len(),
                        "make_signed_packet_and_full_work_wall_ns":make_ns,
                        "native_admission":admission.finish(admission_ns),"native_activation":activation.finish(activation_ns),
                        "admission_sql_total_changes":admission_changes,"activation_sql_total_changes":activation_changes,
                        "retained_cow_nodes_added":after["archive_nodes"] - before["archive_nodes"],
                        "retained_delta_rows_added":after["deltas"] - before["deltas"],
                        "sql_rows_before":before,"sql_rows_after":after,
                        "parent_working":parent_working,"successor_working":working_observation(&node.growth_working(id).unwrap()),
                        "separate_successor_query":{"point_reads":reads.archive_point_reads,"witness_bytes":query.encoded_len().unwrap(),"expanded_witnesses_allocated":reads.expanded_witnesses_allocated},
                        "complete_state_reference_and_diagnostics_wall_ns":reference_ns,
                        "complete_state_reference_equal":true,"active_generation":node.active().unwrap().1,
                        "disk_sample":disk_sample(dir.path()),"p99_ns":null
                    }),
                );
                parent = id;
            }
            // One extra attempted block is deliberately cancelled before the
            // durable commit. Its full row comparison is outside measurements.
            append(&mut report, &json!({"event":"atomic_cancellation_started"}));
            let packet = make(
                &node,
                parent,
                vec![transfer(
                    &settings,
                    0,
                    (MEASURED_BLOCKS + 1) as u64,
                    public(1),
                    1,
                )],
            );
            let before_rows = rows(&node.db);
            let active = node.active().unwrap();
            let error = node
                .admit_growth_with_progress(&packet, 100_000, &|point| {
                    if point == GrowthProgress::BeforeCommit {
                        return Err("SCALE_OBSERVATION_BEFORE_COMMIT_CANCEL".into());
                    }
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.to_string(), "SCALE_OBSERVATION_BEFORE_COMMIT_CANCEL");
            assert_eq!(rows(&node.db), before_rows);
            assert_eq!(node.active().unwrap(), active);
            assert_eq!(
                node.next_nonce(public(0)).unwrap(),
                (MEASURED_BLOCKS + 1) as u64
            );
            drop(before_rows);
            append(
                &mut report,
                &json!({"event":"atomic_cancellation_completed","error":error.to_string(),"all_sql_rows_equal":true,"active_generation_equal":true}),
            );
            let rows_before_reopen = sql_counts(&node);
            let before_close = disk_sample(dir.path());
            drop(node);
            append(&mut report, &json!({"event":"cold_reopen_started"}));
            let started = Instant::now();
            let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
            let reopen_ns = elapsed_ns(started);
            assert_eq!(node.active().unwrap(), active);
            assert_eq!(sql_counts(&node), rows_before_reopen);
            verify_complete_reference(&node, parent, &full, accounts);
            assert_eq!(
                node.next_nonce(public(0)).unwrap(),
                (MEASURED_BLOCKS + 1) as u64
            );
            let started = Instant::now();
            let read = node.db.unchecked_transaction().unwrap();
            let journal = compare_cold_journal(&node).unwrap();
            read.rollback().unwrap();
            let separate_journal_ns = elapsed_ns(started);
            assert_eq!(journal.typed_events, (history + MEASURED_BLOCKS) as u64);
            assert_eq!(journal.semantic_events, journal.typed_events);
            admission_times.sort_unstable();
            append(
                &mut report,
                &json!({
                    "event":"cohort_completed","accounts":accounts,"warmup_history_blocks":history,
                    "measured_blocks":MEASURED_BLOCKS,"successful_native_admissions":history + MEASURED_BLOCKS,
                    "deliberately_cancelled_admissions":1,"failed_unexpected_admissions":0,
                    "cold_reopens":1,"cold_reopen_wall_ns":reopen_ns,"cold_complete_reference_equal":true,
                    "separate_post_open_journal_differential":{"wall_ns":separate_journal_ns,"typed_events":journal.typed_events,"semantic_events":journal.semantic_events,"latest_steps":journal.latest_steps,"latest_events":journal.latest_events,"peak_event_rows":journal.peak_event_rows},
                    "admission_median_interval_ns":[admission_times[MEASURED_BLOCKS / 2 - 1],admission_times[MEASURED_BLOCKS / 2]],
                    "admission_max_ns":admission_times.last().unwrap(),"p99_ns":null,
                    "disk_before_close":before_close,"disk_after_reopen":disk_sample(dir.path()),
                    "production_qualified":false
                }),
            );
        }
    }
    append(
        &mut manifest,
        &json!({
            "event":"run_completed","completed_cohorts":ACCOUNT_COUNTS.len() * HISTORY_LENGTHS.len(),
            "completed_measurements":ACCOUNT_COUNTS.len() * HISTORY_LENGTHS.len() * MEASURED_BLOCKS,
            "actual_distinct_witness_owner_sets":all_owner_sets,
            "fixed_witness_owner_set_observed":all_owner_sets.len() == 1,
            "p99_ns":null,"throughput_claim":false,"production_qualified":false
        }),
    );
}
