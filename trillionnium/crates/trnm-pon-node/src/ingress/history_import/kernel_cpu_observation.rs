//! Optional fixed-parent CPU counters at existing local History phase edges.
//! This sidecar grants no Host, Work, budget, deadline or consensus authority.
use super::observation::{
    HistoryImportObservationSnapshot, MAX_HISTORY_IMPORT_OBSERVATION_PACKETS,
};
use crate::host_kernel_parent::{
    HostKernelBudget, KernelCpuStatIdentity, KernelCpuStatObservation,
};
use crate::ingress::public_v3::request_observation::{
    PhaseBoundaryObserver, TaskObservation, ThreadCpuStamp,
};
use crate::ingress::public_v3::SubmitPhase;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::Instant;

// The original reader also bounds cpu.stat at 2048 bytes. These are diagnostic
// storage bounds, not a replacement for any original Host or CPU-credit limit.
const MAX_CPU_STAT_BYTES: usize = 2048;
const SELECTED: [SubmitPhase; 3] = [
    SubmitPhase::Work,
    SubmitPhase::AdmissionPrepare,
    SubmitPhase::CpuWait,
];
const TASKS: usize = MAX_HISTORY_IMPORT_OBSERVATION_PACKETS + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct CpuCounters {
    usage_usec: u64,
    user_usec: u64,
    system_usec: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_usec: u64,
}
impl CpuCounters {
    fn checked_delta(self, before: Self) -> Result<Self, &'static str> {
        let sub =
            |after: u64, before: u64| after.checked_sub(before).ok_or("counter_rewind_or_reset");
        Ok(Self {
            usage_usec: sub(self.usage_usec, before.usage_usec)?,
            user_usec: sub(self.user_usec, before.user_usec)?,
            system_usec: sub(self.system_usec, before.system_usec)?,
            nr_periods: sub(self.nr_periods, before.nr_periods)?,
            nr_throttled: sub(self.nr_throttled, before.nr_throttled)?,
            throttled_usec: sub(self.throttled_usec, before.throttled_usec)?,
        })
    }
}

fn parse_cpu_stat(text: &str) -> Result<CpuCounters, &'static str> {
    if text.len() > MAX_CPU_STAT_BYTES {
        return Err("cpu_stat_too_large");
    }
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        let key = words.next().ok_or("malformed_cpu_stat")?;
        let raw = words.next().ok_or("malformed_cpu_stat")?;
        // Linux emits this exact dotted counter under CONFIG_SCHED_CORE.
        // Other dotted spellings remain malformed rather than being ignored.
        if words.next().is_some()
            || !(key == "core_sched.force_idle_usec"
                || key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
            || !raw.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("malformed_cpu_stat");
        }
        let value = raw
            .parse::<u64>()
            .map_err(|_| "cpu_stat_counter_overflow")?;
        if fields.insert(key, value).is_some() {
            return Err("duplicate_cpu_stat_counter");
        }
    }
    // Additional well-formed kernel keys remain in the complete raw text.
    // No missing required field, sign, float, overflow or duplicate is zeroed.
    let get = |key| fields.get(key).copied().ok_or("missing_cpu_stat_counter");
    Ok(CpuCounters {
        usage_usec: get("usage_usec")?,
        user_usec: get("user_usec")?,
        system_usec: get("system_usec")?,
        nr_periods: get("nr_periods")?,
        nr_throttled: get("nr_throttled")?,
        throttled_usec: get("throttled_usec")?,
    })
}

#[derive(Clone, Debug, Serialize)]
struct BoundarySample {
    sample_started_ns: Option<u64>,
    sample_ended_ns: Option<u64>,
    sample_wall_ns: Option<u64>,
    sample_calling_thread_cpu_ns: Option<u64>,
    expected_parent_identity: Option<KernelCpuStatIdentity>,
    raw_cpu_stat: Option<String>,
    counters: Option<CpuCounters>,
    observation_error: Option<&'static str>,
    original_read_error_code: Option<&'static str>,
}

fn ns_since(epoch: Instant, now: Instant) -> Option<u64> {
    now.checked_duration_since(epoch)
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
}

struct Shared {
    epoch: Instant,
    // This reader holds only a copy of the SAME native handle's immutable
    // expected identity/limits. It retains no FD, text or authorization verdict.
    reader: OnceLock<HostKernelBudget>,
    failures: AtomicU64,
}
impl Shared {
    fn fail(&self) {
        let _ = self
            .failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }

    fn sample(&self) -> BoundarySample {
        let start = Instant::now();
        let cpu = ThreadCpuStamp::start();
        let mut sample = BoundarySample {
            sample_started_ns: ns_since(self.epoch, start),
            sample_ended_ns: None,
            sample_wall_ns: None,
            sample_calling_thread_cpu_ns: None,
            expected_parent_identity: None,
            raw_cpu_stat: None,
            counters: None,
            observation_error: None,
            original_read_error_code: None,
        };
        match self.reader.get() {
            None => sample.observation_error = Some("native_parent_not_bound"),
            Some(reader) => match reader.cpu_stat_for_observation() {
                Ok(KernelCpuStatObservation { identity, cpu_stat }) => {
                    sample.expected_parent_identity = Some(identity);
                    match parse_cpu_stat(&cpu_stat) {
                        Ok(counters) => sample.counters = Some(counters),
                        Err(error) => sample.observation_error = Some(error),
                    }
                    sample.raw_cpu_stat = Some(cpu_stat);
                }
                Err(error) => {
                    sample.observation_error = Some("parent_or_cpu_stat_unavailable");
                    sample.original_read_error_code = error.code().map(crate::ErrorCode::as_str);
                }
            },
        }
        let end = Instant::now();
        sample.sample_ended_ns = ns_since(self.epoch, end);
        sample.sample_wall_ns = end
            .checked_duration_since(start)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        sample.sample_calling_thread_cpu_ns = cpu.and_then(ThreadCpuStamp::finish);
        if sample.sample_started_ns.is_none()
            || sample.sample_ended_ns.is_none()
            || sample.sample_wall_ns.is_none()
            || sample.sample_calling_thread_cpu_ns.is_none()
        {
            sample
                .observation_error
                .get_or_insert("sample_clock_unavailable");
        }
        if sample.observation_error.is_some() {
            self.fail();
        }
        sample
    }
}

#[derive(Clone, Default)]
struct Interval {
    started: bool,
    finished: bool,
    native_returned: bool,
    native_accepted: Option<bool>,
    before: Option<BoundarySample>,
    after: Option<BoundarySample>,
}

#[derive(Clone, Debug, Serialize)]
struct GroupDelta {
    counters: CpuCounters,
    // The actual cumulative-counter read occurs within each sample bracket.
    // There is no invented exact instant or per-thread/call CPU attribution.
    minimum_elapsed_ns: u64,
    maximum_elapsed_ns: u64,
}

fn qualified_delta(row: &Interval) -> Result<GroupDelta, &'static str> {
    if !row.started || !row.finished || !row.native_returned {
        return Err("phase_unfinished_or_unwound");
    }
    let before = row.before.as_ref().ok_or("start_sample_missing")?;
    let after = row.after.as_ref().ok_or("end_sample_missing")?;
    if before.observation_error.is_some() || after.observation_error.is_some() {
        return Err("boundary_sample_unqualified");
    }
    match (
        &before.expected_parent_identity,
        &after.expected_parent_identity,
    ) {
        (Some(left), Some(right)) if left == right => {}
        _ => return Err("parent_identity_changed_or_missing"),
    }
    let before_start = before.sample_started_ns.ok_or("sample_clock_unavailable")?;
    let before_end = before.sample_ended_ns.ok_or("sample_clock_unavailable")?;
    let after_start = after.sample_started_ns.ok_or("sample_clock_unavailable")?;
    let after_end = after.sample_ended_ns.ok_or("sample_clock_unavailable")?;
    if before_start > before_end || before_end > after_start || after_start > after_end {
        return Err("sample_clock_order");
    }
    let counters = after
        .counters
        .ok_or("end_counters_missing")?
        .checked_delta(before.counters.ok_or("start_counters_missing")?)?;
    Ok(GroupDelta {
        counters,
        minimum_elapsed_ns: after_start - before_end,
        maximum_elapsed_ns: after_end - before_start,
    })
}

struct Slot {
    shared: Arc<Shared>,
    rows: Mutex<[Interval; SELECTED.len()]>,
}
impl Slot {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            rows: Mutex::new(std::array::from_fn(|_| Interval::default())),
        }
    }
}
impl PhaseBoundaryObserver for Slot {
    fn begin(&self, phase: SubmitPhase) -> bool {
        let Some(index) = SELECTED.iter().position(|&value| value == phase) else {
            return false;
        };
        match self.rows.try_lock() {
            Ok(mut rows) if !rows[index].started => rows[index].started = true,
            _ => {
                self.shared.fail();
                return false;
            }
        }
        // Never hold a diagnostic mutex over any filesystem operation.
        let sample = self.shared.sample();
        match self.rows.try_lock() {
            Ok(mut rows) => {
                rows[index].before = Some(sample);
                true
            }
            Err(_) => {
                self.shared.fail();
                false
            }
        }
    }

    fn end(&self, phase: SubmitPhase, accepted: Option<bool>) {
        let Some(index) = SELECTED.iter().position(|&value| value == phase) else {
            self.shared.fail();
            return;
        };
        let sample = self.shared.sample();
        match self.rows.try_lock() {
            Ok(mut rows) if rows[index].started && !rows[index].finished => {
                rows[index].after = Some(sample);
                rows[index].finished = true;
                rows[index].native_returned = accepted.is_some();
                rows[index].native_accepted = accepted;
            }
            _ => self.shared.fail(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct KernelPhaseRecord {
    packet_index: Option<usize>,
    phase: SubmitPhase,
    native_returned: bool,
    native_accepted: Option<bool>,
    before: Option<BoundarySample>,
    after: Option<BoundarySample>,
    whole_parent_delta: Option<GroupDelta>,
    qualification_error: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryKernelCpuObservationSnapshot {
    schema: &'static str,
    selected_phases: [SubmitPhase; 3],
    native_parent_identity_bound: bool,
    interval_capacity: usize,
    sample_capacity: usize,
    raw_cpu_stat_capacity_bytes: usize,
    records: Vec<KernelPhaseRecord>,
    measurement_failures: u64,
    original_phase_measurement_failures: u64,
    native_phase_snapshot_coherent: bool,
    all_observed_intervals_qualified: bool,
    has_control_authority: bool,
    clock_scope: &'static str,
    counter_scope: &'static str,
    cost_scope: &'static str,
}

fn index_of_phase(phase: SubmitPhase) -> usize {
    // The original fixed phase recorder uses this exact enum index.
    phase as usize
}

pub(super) struct KernelCpuSidecar {
    shared: Arc<Shared>,
    slots: [Arc<Slot>; TASKS],
}
impl KernelCpuSidecar {
    pub(super) fn new(epoch: Instant) -> Self {
        let shared = Arc::new(Shared {
            epoch,
            reader: OnceLock::new(),
            failures: AtomicU64::new(0),
        });
        Self {
            slots: std::array::from_fn(|_| Arc::new(Slot::new(shared.clone()))),
            shared,
        }
    }

    pub(super) fn attach(
        &self,
        page: &TaskObservation,
        packets: &[TaskObservation; MAX_HISTORY_IMPORT_OBSERVATION_PACKETS],
    ) {
        if !page.set_boundary_observer(self.slots[0].clone()) {
            self.shared.fail();
        }
        for (index, packet) in packets.iter().enumerate() {
            if !packet.set_boundary_observer(self.slots[index + 1].clone()) {
                self.shared.fail();
            }
        }
    }

    pub(super) fn bind(&self, native: &HostKernelBudget) {
        // Called only after the wrapper's original initial verify succeeded.
        // The copy has the identical expected boot/device/inode/path/limits,
        // and each sample independently reopens/rechecks before and after read.
        if self
            .shared
            .reader
            .set(native.reader_for_observation())
            .is_err()
        {
            self.shared.fail();
        }
    }

    pub(super) fn snapshot(
        &self,
        native: &HistoryImportObservationSnapshot,
    ) -> HistoryKernelCpuObservationSnapshot {
        let original_phase_measurement_failures = native.measurement_failures;
        let mut coherent = true;
        let expected_intervals = native
            .phases
            .iter()
            .chain(
                native
                    .packets
                    .iter()
                    .flat_map(|packet| packet.phases.iter()),
            )
            .filter(|phase| phase.started && SELECTED.contains(&phase.phase))
            .count();
        let mut records = Vec::new();
        for (slot_index, slot) in self.slots.iter().enumerate() {
            let rows = match slot.rows.try_lock() {
                Ok(rows) => rows.clone(),
                Err(_) => {
                    self.shared.fail();
                    continue;
                }
            };
            for (index, row) in rows.into_iter().enumerate() {
                if !row.started {
                    continue;
                }
                let native_phase = if slot_index == 0 {
                    Some(&native.phases[index_of_phase(SELECTED[index])])
                } else {
                    native
                        .packets
                        .iter()
                        .find(|packet| packet.packet_index == slot_index - 1)
                        .map(|packet| &packet.phases[index_of_phase(SELECTED[index])])
                };
                // Original phase rows and this sidecar are copied separately.
                // A live/contended snapshot can be incomplete; never qualify
                // newer counters against an older or missing native phase.
                let matches_native = native_phase.is_some_and(|phase| {
                    phase.started
                        && phase.completed == row.native_returned
                        && phase.accepted == row.native_accepted
                        && match (phase.started_ns, phase.ended_ns) {
                            (Some(start), Some(end)) => {
                                row.before.iter().chain(row.after.iter()).all(|sample| {
                                    match (sample.sample_started_ns, sample.sample_ended_ns) {
                                        (Some(before), Some(after)) => {
                                            start <= before && after <= end
                                        }
                                        _ => false,
                                    }
                                })
                            }
                            _ => false,
                        }
                });
                coherent &= matches_native;
                let (whole_parent_delta, qualification_error) = if matches_native {
                    match qualified_delta(&row) {
                        Ok(delta) => (Some(delta), None),
                        Err(error) => (None, Some(error)),
                    }
                } else {
                    (None, Some("native_phase_snapshot_incomplete"))
                };
                records.push(KernelPhaseRecord {
                    packet_index: slot_index.checked_sub(1),
                    phase: SELECTED[index],
                    native_returned: row.native_returned,
                    native_accepted: row.native_accepted,
                    before: row.before,
                    after: row.after,
                    whole_parent_delta,
                    qualification_error,
                });
            }
        }
        coherent &= records.len() == expected_intervals;
        let failures = self.shared.failures.load(Ordering::Acquire);
        let bound = self.shared.reader.get().is_some();
        let qualified = bound
            && coherent
            && failures == 0
            && original_phase_measurement_failures == 0
            && !records.is_empty()
            && records.iter().all(|row| row.whole_parent_delta.is_some());
        HistoryKernelCpuObservationSnapshot {
            schema: "pon-local-history-kernel-cpu-phase-observation-v1",
            selected_phases: SELECTED,
            native_parent_identity_bound: bound,
            interval_capacity: TASKS * SELECTED.len(),
            sample_capacity: TASKS * SELECTED.len() * 2,
            raw_cpu_stat_capacity_bytes: MAX_CPU_STAT_BYTES,
            records,
            measurement_failures: failures,
            original_phase_measurement_failures,
            native_phase_snapshot_coherent: coherent,
            all_observed_intervals_qualified: qualified,
            has_control_authority: false,
            clock_scope: "same History observer-local monotonic epoch; every counter read is bracketed by sample start/end; missing or reversed clocks never become zero elapsed",
            counter_scope: "raw cumulative cpu.stat for the entire original fixed parent and all descendant processes, including attack and honest work; group deltas are not importer-thread CPU, per-worker CPU, exclusive phase costs, or causal proof of a particular delay; selected intervals may overlap other observations and must not be summed",
            cost_scope: "each optional sample performs fresh Host validation before and after a fresh cpu.stat open/full EOF read; all sampling/parsing/bookkeeping remains inside the original phase and business clocks; original 4s deadline, CPU reserve/rate, workers, work callbacks and gates remain unchanged",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU: &str = "usage_usec 600\nuser_usec 400\nsystem_usec 200\nnr_periods 16\nnr_throttled 4\nthrottled_usec 150\nnr_bursts 0\n";
    const REQUIRED: [&str; 6] = [
        "usage_usec",
        "user_usec",
        "system_usec",
        "nr_periods",
        "nr_throttled",
        "throttled_usec",
    ];

    fn identity() -> KernelCpuStatIdentity {
        KernelCpuStatIdentity {
            parent: "/sys/fs/cgroup/trnmponpublic.slice".into(),
            device: 7,
            inode: 11,
            uid: 0,
            boot_id: "fixture-boot".into(),
            cpu_quota_us: 25_000,
            cpu_period_us: 100_000,
            memory_max_bytes: 2 * 1024 * 1024 * 1024,
            pids_max: 256,
        }
    }

    fn sample(text: &str, started: u64, ended: u64) -> BoundarySample {
        BoundarySample {
            sample_started_ns: Some(started),
            sample_ended_ns: Some(ended),
            sample_wall_ns: ended.checked_sub(started),
            sample_calling_thread_cpu_ns: Some(1),
            expected_parent_identity: Some(identity()),
            raw_cpu_stat: Some(text.into()),
            counters: parse_cpu_stat(text).ok(),
            observation_error: parse_cpu_stat(text).err(),
            original_read_error_code: None,
        }
    }

    fn interval() -> Interval {
        Interval {
            started: true,
            finished: true,
            native_returned: true,
            native_accepted: Some(true),
            before: Some(sample(CPU, 10, 20)),
            after: Some(sample(&CPU.replace("600", "620"), 90, 100)),
        }
    }

    #[test]
    fn cpu_stat_keeps_complete_kernel_text_and_accepts_future_numeric_keys() {
        let parsed = parse_cpu_stat(CPU).unwrap();
        assert_eq!(parsed.usage_usec, 600);
        assert_eq!(parsed.user_usec, 400);
        assert_eq!(parsed.system_usec, 200);
        assert_eq!(
            parse_cpu_stat(&format!("{CPU}future_counter 2\n")).unwrap(),
            parsed
        );
        let raw = sample(CPU, 1, 2);
        assert_eq!(raw.raw_cpu_stat.as_deref(), Some(CPU));
    }

    #[test]
    fn cpu_stat_accepts_the_observed_linux_core_sched_field() {
        // Original run45757278209 head artifact15090531717, first pressure
        // History page/cpu_wait before sample. This is a parser fixture only.
        let raw = concat!(
            "usage_usec 18393406\n",
            "user_usec 12013212\n",
            "system_usec 6380194\n",
            "nice_usec 0\n",
            "core_sched.force_idle_usec 0\n",
            "nr_periods 749\n",
            "nr_throttled 730\n",
            "throttled_usec 67260306\n",
            "nr_bursts 0\n",
            "burst_usec 0\n",
        );
        assert_eq!(
            parse_cpu_stat(raw).unwrap(),
            CpuCounters {
                usage_usec: 18_393_406,
                user_usec: 12_013_212,
                system_usec: 6_380_194,
                nr_periods: 749,
                nr_throttled: 730,
                throttled_usec: 67_260_306,
            }
        );
        let observed = sample(raw, 1, 2);
        assert_eq!(observed.raw_cpu_stat.as_deref(), Some(raw));
        assert_eq!(observed.observation_error, None);
    }

    #[test]
    fn cpu_stat_rejects_unknown_or_malformed_dotted_field_names() {
        for key in [
            "future.counter",
            ".core_sched.force_idle_usec",
            "core_sched.force_idle_usec.",
            "core_sched..force_idle_usec",
            "core_sched.force.idle_usec",
            "core_sched.force_idle_usec_extra",
            "core_sched.force_idle_usec/",
            "Core_sched.force_idle_usec",
            "core_sched\u{ff0e}force_idle_usec",
            "core_sched.\0force_idle_usec",
        ] {
            assert_eq!(
                parse_cpu_stat(&format!("{CPU}{key} 0\n")),
                Err("malformed_cpu_stat"),
                "{key:?}"
            );
        }
    }

    #[test]
    fn cpu_stat_core_sched_field_preserves_duplicate_and_u64_refusals() {
        let raw = format!("{CPU}core_sched.force_idle_usec 0\n");
        assert_eq!(
            parse_cpu_stat(&format!("{raw}core_sched.force_idle_usec 1\n")),
            Err("duplicate_cpu_stat_counter")
        );
        for value in ["+1", "-1", "1.0", "0x10", "1e3", "١", "1 2"] {
            assert_eq!(
                parse_cpu_stat(&format!("{CPU}core_sched.force_idle_usec {value}\n")),
                Err("malformed_cpu_stat"),
                "{value}"
            );
        }
        assert_eq!(
            parse_cpu_stat(&format!(
                "{CPU}core_sched.force_idle_usec 18446744073709551616\n"
            )),
            Err("cpu_stat_counter_overflow")
        );
        assert_eq!(
            parse_cpu_stat(&format!("{CPU}core_sched.force_idle_usec {}\n", u64::MAX)).unwrap(),
            parse_cpu_stat(CPU).unwrap()
        );
        assert_eq!(
            parse_cpu_stat(&raw.replace("usage_usec 600\n", "")),
            Err("missing_cpu_stat_counter")
        );
    }

    #[test]
    fn every_missing_or_duplicate_required_counter_refuses_observation() {
        for key in REQUIRED {
            let missing = CPU
                .lines()
                .filter(|line| line.split_ascii_whitespace().next() != Some(key))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                parse_cpu_stat(&missing),
                Err("missing_cpu_stat_counter"),
                "{key}"
            );
            assert_eq!(
                parse_cpu_stat(&format!("{CPU}{key} 0\n")),
                Err("duplicate_cpu_stat_counter"),
                "{key}"
            );
        }
        assert_eq!(
            parse_cpu_stat(&format!("{CPU}future 1\nfuture 2\n")),
            Err("duplicate_cpu_stat_counter")
        );
    }

    #[test]
    fn signed_fractional_hex_unicode_overflow_and_extra_fields_are_rejected() {
        for value in [
            "+1",
            "-1",
            "1.0",
            "0x10",
            "1e3",
            "١",
            "18446744073709551616",
            "1 2",
        ] {
            assert!(
                parse_cpu_stat(&CPU.replace("usage_usec 600", &format!("usage_usec {value}")))
                    .is_err(),
                "{value}"
            );
        }
        for suffix in ["\n", "missing\n", "bad-key 1\n", "bad\0key 1\n", "λ 1\n"] {
            assert!(
                parse_cpu_stat(&format!("{CPU}{suffix}")).is_err(),
                "{suffix:?}"
            );
        }
        assert!(parse_cpu_stat("").is_err());
    }

    #[test]
    fn complete_text_limit_is_exact_and_never_truncates_into_valid_input() {
        let padding = MAX_CPU_STAT_BYTES - CPU.len() - "future 0\n".len();
        let exact = format!("{CPU}future{} 0\n", "x".repeat(padding));
        assert_eq!(exact.len(), MAX_CPU_STAT_BYTES);
        assert!(parse_cpu_stat(&exact).is_ok());
        assert_eq!(parse_cpu_stat(&(exact + " ")), Err("cpu_stat_too_large"));
    }

    #[test]
    fn group_delta_preserves_microseconds_and_brackets_the_unknown_read_instants() {
        let delta = qualified_delta(&interval()).unwrap();
        assert_eq!(delta.counters.usage_usec, 20);
        assert_eq!(delta.counters.user_usec, 0);
        assert_eq!(delta.minimum_elapsed_ns, 70);
        assert_eq!(delta.maximum_elapsed_ns, 90);
    }

    #[test]
    fn any_required_counter_rewind_or_reset_refuses_the_delta() {
        for key in REQUIRED {
            let before = CPU
                .lines()
                .map(|line| {
                    if line.split_ascii_whitespace().next() == Some(key) {
                        format!("{key} 0")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let mut row = interval();
            row.after = Some(sample(&before, 90, 100));
            assert_eq!(
                qualified_delta(&row).unwrap_err(),
                "counter_rewind_or_reset",
                "{key}"
            );
        }
    }

    #[test]
    fn changed_boot_inode_ownership_path_or_limits_never_qualify() {
        for change in 0..10 {
            let mut row = interval();
            let id = row
                .after
                .as_mut()
                .unwrap()
                .expected_parent_identity
                .as_mut()
                .unwrap();
            match change {
                0 => id.parent.push_str("/other"),
                1 => id.device += 1,
                2 => id.inode += 1,
                3 => id.uid += 1,
                4 => id.boot_id.push('x'),
                5 => id.cpu_quota_us += 1,
                6 => id.cpu_period_us += 1,
                7 => id.memory_max_bytes += 1,
                8 => id.pids_max += 1,
                _ => row.after.as_mut().unwrap().expected_parent_identity = None,
            }
            assert_eq!(
                qualified_delta(&row).unwrap_err(),
                "parent_identity_changed_or_missing"
            );
        }
    }

    #[test]
    fn missing_reversed_or_overlapping_sample_clocks_never_zero_fill() {
        for change in 0..4 {
            let mut row = interval();
            match change {
                0 => row.before.as_mut().unwrap().sample_started_ns = None,
                1 => row.before.as_mut().unwrap().sample_ended_ns = Some(5),
                2 => row.after.as_mut().unwrap().sample_started_ns = Some(19),
                _ => row.after.as_mut().unwrap().sample_ended_ns = Some(89),
            }
            assert!(qualified_delta(&row).is_err());
        }
    }

    #[test]
    fn missing_failed_or_unfinished_captures_remain_unqualified() {
        for change in 0..5 {
            let mut row = interval();
            match change {
                0 => row.before = None,
                1 => row.after = None,
                2 => {
                    row.after.as_mut().unwrap().observation_error =
                        Some("parent_or_cpu_stat_unavailable")
                }
                3 => row.native_returned = false,
                _ => row.finished = false,
            }
            assert!(qualified_delta(&row).is_err());
        }
    }

    #[test]
    fn failed_native_action_can_have_valid_group_counters_without_service_authority() {
        let mut row = interval();
        row.native_accepted = Some(false);
        assert!(qualified_delta(&row).is_ok());
        assert_eq!(row.native_accepted, Some(false));
    }

    #[test]
    fn unbound_sampling_keeps_the_original_error_and_never_retries_an_action() {
        let observer =
            super::super::observation::HistoryImportObserver::new_with_kernel_cpu_observation();
        let packet = observer.packet(0).unwrap();
        let guard = packet.phase(SubmitPhase::Work);
        let mut actions = 0;
        let original: crate::Result<()> = {
            actions += 1;
            Err("PUBLIC_REQUEST_DEADLINE".into())
        };
        guard.finish_result(&original);
        assert_eq!(actions, 1);
        assert_eq!(original.unwrap_err().to_string(), "PUBLIC_REQUEST_DEADLINE");
        let snapshot = observer.snapshot();
        let kernel = snapshot.kernel_cpu_observation.unwrap();
        assert!(!kernel.all_observed_intervals_qualified);
        assert!(kernel.measurement_failures > 0);
        assert_eq!(kernel.records[0].native_accepted, Some(false));
        assert!(kernel.records[0].whole_parent_delta.is_none());
    }

    #[test]
    fn default_history_observer_has_no_kernel_sidecar_or_serialized_extension() {
        let observer = super::super::observation::HistoryImportObserver::new();
        let encoded = serde_json::to_value(observer.snapshot()).unwrap();
        assert!(encoded.get("kernel_cpu_observation").is_none());
    }

    #[test]
    fn live_native_snapshot_is_explicitly_unqualified_without_changing_its_action() {
        let observer =
            super::super::observation::HistoryImportObserver::new_with_kernel_cpu_observation();
        let packet = observer.packet(0).unwrap();
        let action = packet.phase(SubmitPhase::Work);
        let snapshot = observer.snapshot().kernel_cpu_observation.unwrap();
        assert!(!snapshot.native_phase_snapshot_coherent);
        assert!(!snapshot.all_observed_intervals_qualified);
        assert_eq!(
            snapshot.records[0].qualification_error,
            Some("native_phase_snapshot_incomplete")
        );
        action.finish(false);
    }

    #[test]
    fn diagnostic_contention_and_reuse_never_replace_prior_data_or_results() {
        let sidecar = KernelCpuSidecar::new(Instant::now());
        let slot = &sidecar.slots[0];
        {
            let _held = slot.rows.lock().unwrap();
            assert!(!slot.begin(SubmitPhase::Work));
        }
        assert!(slot.begin(SubmitPhase::Work));
        assert!(!slot.begin(SubmitPhase::Work));
        slot.end(SubmitPhase::Work, Some(false));
        let native = super::super::observation::HistoryImportObserver::new();
        let original = native.page().phase(SubmitPhase::Work);
        original.finish(false);
        let snapshot = sidecar.snapshot(&native.snapshot());
        assert!(!snapshot.all_observed_intervals_qualified);
        assert!(snapshot.measurement_failures >= 3);
        assert_eq!(snapshot.records.len(), 1);
        assert_eq!(snapshot.records[0].native_accepted, Some(false));
    }
}
