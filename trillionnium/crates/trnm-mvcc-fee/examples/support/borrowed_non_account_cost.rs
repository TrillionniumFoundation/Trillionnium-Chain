//! Exact shared fixtures and algorithms for separate wall/allocation binaries.
#![forbid(unsafe_code)]

use serde::Serialize;
use serde_json::{json, Value};
use std::io::{self, Write};
use trnm_mvcc_fee::pon_executor::{self, BorrowedNonAccountState, State};
use trnm_protocol::pon_wire::{Hash, StateRootArithmetic, StateRootArithmeticObservation};

pub const RETAINED_BYTES: usize = 2 * 1024 * 1024;
pub const ROUNDS: usize = 16;
pub const COHORTS: [(usize, usize); 4] = [(64, 64), (1024, 64), (2100, 64), (64, 2100)];
pub const ORDER: [Arm; 4] = [Arm::Owned, Arm::Borrowed, Arm::Borrowed, Arm::Owned];

#[derive(Clone, Copy)]
pub enum Arm {
    Owned,
    Borrowed,
}

impl Arm {
    pub fn index(self) -> usize {
        match self {
            Self::Owned => 0,
            Self::Borrowed => 1,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Owned => "original_owned_partition",
            Self::Borrowed => "borrowed_partition",
        }
    }
    pub fn calculate(
        self,
        state: &State,
        arithmetic: &mut StateRootArithmetic,
    ) -> pon_executor::Result<Hash> {
        match self {
            Self::Owned => pon_executor::root_with_arithmetic(&owned_partition(state), arithmetic),
            Self::Borrowed => BorrowedNonAccountState::new(state).root_with_arithmetic(arithmetic),
        }
    }
}

fn owned_partition(state: &State) -> State {
    state
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn emit(value: &Value) -> Result<(), String> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value).map_err(|error| error.to_string())?;
    out.write_all(b"\n").map_err(|error| error.to_string())?;
    out.flush().map_err(|error| error.to_string())
}

pub fn arithmetic_json(observation: StateRootArithmeticObservation) -> Value {
    let StateRootArithmeticObservation {
        input_keys,
        leaf_hashes_computed,
        exact_string_hits,
        string_encodings_reused,
        reused_partitions,
        computed_partitions,
        retained_payload_bytes,
        retained_string_entries,
        retained_string_charge_bytes,
        retention_refused,
    } = observation;
    json!({"input_keys":input_keys,"leaf_hashes_computed":leaf_hashes_computed,
        "exact_string_hits":exact_string_hits,"string_encodings_reused":string_encodings_reused,
        "reused_partitions":reused_partitions,"computed_partitions":computed_partitions,
        "retained_payload_bytes":retained_payload_bytes,"retained_string_entries":retained_string_entries,
        "retained_string_charge_bytes":retained_string_charge_bytes,"retention_refused":retention_refused})
}

pub fn require_argument(argument: &str) -> Result<(), String> {
    if std::env::args().skip(1).collect::<Vec<_>>() == [argument] {
        Ok(())
    } else {
        Err(format!("required sole argument: {argument}"))
    }
}

pub fn start(mode: &str) -> Result<(), String> {
    let sample_count = match mode {
        "wall" => COHORTS.len() * 2 * ROUNDS * ORDER.len(),
        "allocations" => COHORTS.len() * 2 * ORDER.len(),
        _ => return Err("unregistered observation mode".into()),
    };
    let planned: Vec<_> = COHORTS.into_iter().flat_map(|(cells, accounts)| {
        [false, true].into_iter().map(move |warm| json!({
            "id":cohort_id(cells,accounts,warm),"payload_cells":cells,"account_rows":accounts,"warm":warm
        }))
    }).collect();
    emit(
        &json!({"record":"campaign_started","schema":"borrowed-non-account-component-cost-v2",
        "mode":mode,"planned_cohorts":planned,"planned_samples":sample_count,
        "component_scope":"non-account partition construction, complete grammar and root; excludes account root, liabilities, Host, I/O and service paths",
        "comparison":"same input and arithmetic algorithm; original owned projection versus borrowed descriptors",
        "input_rule":{"payload":"4080 ASCII x bytes per cell","payload_key":"fixture-large-parent:{index:04}",
            "account_key":"account:{index:064x}","account_balance":1,"account_nonce":"index",
            "meta_issued":"account_rows","model_current":"hex of 32 zero bytes"},
        "retained_payload_limit_bytes":RETAINED_BYTES,"order":"ABBA","wall_rounds":ROUNDS,
        "allocation_samples_per_cohort":ORDER.len(),"allocation_requested_bytes_minimum_reduction_fraction":0.05,
        "allocation_samples_must_be_deterministic":true,"overflow_invalidates_sample":true,
        "wall_nonregression_maximum_paired_median_ratio":1.0,"wall_maximum_p95_ratio":1.10,
        "separate_wall_improvement_maximum_paired_median_ratio":0.95,
        "all_eight_cohorts_required":true,"p99":null,
        "raw_capture":"sample_started and sample_completed JSONL flushed outside measurement; missing completion is unfinished",
        "binary_identity":"capturing runner must bind both binaries and exact shared source",
        "service_cpu_gate_qualified":false,"host_qualified":false,"public_throughput_claim":false}),
    )
}

fn cohort_id(cells: usize, accounts: usize, warm: bool) -> String {
    format!(
        "payload-{cells}-accounts-{accounts}-{}",
        if warm { "warm" } else { "cold" }
    )
}

pub struct Cohort {
    pub id: String,
    pub state: State,
    expected: Hash,
    warm: bool,
}

impl Cohort {
    pub fn new(cells: usize, accounts: usize, warm: bool) -> Result<Self, String> {
        let id = cohort_id(cells, accounts, warm);
        emit(
            &json!({"record":"cohort_started","cohort":id,"payload_cells":cells,
            "account_rows":accounts,"warm":warm}),
        )?;
        let mut state: State = (0..cells)
            .map(|index| {
                (
                    format!("fixture-large-parent:{index:04}"),
                    json!("x".repeat(4080)),
                )
            })
            .collect();
        for index in 0..accounts {
            state.insert(
                format!("account:{index:064x}"),
                json!({"balance":1,"nonce":index}),
            );
        }
        state.insert("meta:issued".into(), json!(accounts));
        state.insert("model:current".into(), json!(hex::encode([0; 32])));
        let reference = owned_partition(&state);
        let expected = pon_executor::root(&reference).map_err(str::to_owned)?;
        let payload: usize = reference
            .iter()
            .map(|(key, value)| {
                key.len()
                    + serde_json::to_vec(value)
                        .expect("fixed canonical fixture")
                        .len()
            })
            .sum();
        emit(
            &json!({"record":"cohort_prepared","cohort":id,"actual_non_account_rows":reference.len(),
            "canonical_non_account_payload_bytes":payload,"reference_root":hex::encode(expected),
            "source_state_rows":state.len()}),
        )?;
        Ok(Self {
            id,
            state,
            expected,
            warm,
        })
    }

    pub fn reset_if_cold(&self, cache: &mut StateRootArithmetic) {
        if !self.warm {
            *cache = StateRootArithmetic::new(RETAINED_BYTES);
        }
    }

    pub fn caches(&self) -> Result<[StateRootArithmetic; 2], String> {
        let mut caches = std::array::from_fn(|_| StateRootArithmetic::new(RETAINED_BYTES));
        if self.warm {
            for arm in [Arm::Owned, Arm::Borrowed] {
                emit(&json!({"record":"warmup_started","cohort":self.id,"arm":arm.name()}))?;
                let actual = arm.calculate(&self.state, &mut caches[arm.index()]);
                let check = self.check(&actual, &caches[arm.index()]);
                emit(
                    &json!({"record":"warmup_completed","cohort":self.id,"arm":arm.name(),"check":check}),
                )?;
                check.require_valid()?;
            }
        }
        Ok(caches)
    }

    pub fn check(
        &self,
        actual: &pon_executor::Result<Hash>,
        cache: &StateRootArithmetic,
    ) -> SampleCheck {
        SampleCheck {
            root_matches_independent_original: actual
                .as_ref()
                .is_ok_and(|root| *root == self.expected),
            actual_root: actual.as_ref().ok().map(hex::encode),
            error: actual.as_ref().err().copied(),
            retained_payload_bytes: cache.retained_payload_bytes(),
            retention_within_original_cap: cache.retained_payload_bytes() <= RETAINED_BYTES,
        }
    }
}

#[derive(Serialize)]
pub struct SampleCheck {
    root_matches_independent_original: bool,
    actual_root: Option<String>,
    error: Option<&'static str>,
    retained_payload_bytes: usize,
    retention_within_original_cap: bool,
}

impl SampleCheck {
    pub fn require_valid(&self) -> Result<(), String> {
        if self.root_matches_independent_original && self.retention_within_original_cap {
            Ok(())
        } else {
            Err(
                "incorrect/error root or retained payload exceeded original cap; see raw sample"
                    .into(),
            )
        }
    }
}
