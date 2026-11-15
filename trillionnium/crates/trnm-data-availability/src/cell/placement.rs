//! Bounded analysis of one chunk's declared provider and failure-domain map.
//!
//! This pure function does not read bytes, contact providers, authenticate an
//! operator, or establish independent administration. Its inputs are claims.
//! A recovery observer must separately bind the version/chunk, verify the actual
//! parts under its original budget, and pass only those observed placements.
//! Distinct identity labels, including `domain_evidence`, prove no independence.

use super::{require, CellDigestV1, CellErrorV1, CellResultV1};

pub const MAX_CELL_RECOVERY_PROVIDERS_V1: usize = 16;
pub const MAX_CELL_RECOVERY_PLACEMENTS_V1: usize = MAX_CELL_RECOVERY_PROVIDERS_V1 * 7;
pub const MAX_CELL_RECOVERY_FAULT_EVENTS_V1: usize = MAX_CELL_RECOVERY_PROVIDERS_V1 * 3;
pub const MAX_CELL_RECOVERY_FAULT_SCENARIOS_V1: u64 = 1_177;

const SHARD_BITS: u8 = 0b0011_1111;
const WHOLE_CHUNK_BIT: u8 = 0b0100_0000;

/// An independently pinned declaration. Repeated operator, administrator, or
/// domain identities intentionally describe correlated failure; only provider
/// IDs must be unique. None of these fields authenticates its named subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellRecoveryProviderPinV1 {
    pub provider_id: CellDigestV1,
    pub operator: CellDigestV1,
    pub administrator: CellDigestV1,
    pub failure_domain: CellDigestV1,
    pub domain_evidence: CellDigestV1,
}

/// Canonical order is Operator, Administrator, then FailureDomain. Identities
/// in different axes are separate typed events even when their bytes match.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CellRecoveryFaultAxisV1 {
    Operator,
    Administrator,
    FailureDomain,
}

impl CellRecoveryFaultAxisV1 {
    fn identity(self, provider: &CellRecoveryProviderPinV1) -> CellDigestV1 {
        match self {
            Self::Operator => provider.operator,
            Self::Administrator => provider.administrator,
            Self::FailureDomain => provider.failure_domain,
        }
    }
}

/// All combinations of at most `maximum_lost_events` across the selected axes
/// are checked together. Thus two losses with Operator and FailureDomain
/// selected include mixed operator/domain losses, not merely separate audits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRecoveryFaultPolicyV1 {
    /// Strictly increasing, without duplicate axes. Empty is allowed only when
    /// the caller explicitly requests the zero-loss policy.
    pub axes: Vec<CellRecoveryFaultAxisV1>,
    pub maximum_lost_events: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CellRecoveryFaultEventV1 {
    pub axis: CellRecoveryFaultAxisV1,
    pub identity: CellDigestV1,
}

/// Canonical placement order puts a whole chunk before RS indices 0 through 5.
/// A repeated RS index on another provider may improve survival but never
/// increases the number of distinct rows available for RS reconstruction.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CellRecoveryPartV1 {
    WholeChunk,
    Rs46(u8),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CellRecoveryPlacementV1 {
    pub provider_id: CellDigestV1,
    pub part: CellRecoveryPartV1,
}

/// Conditional placement analysis only. In particular, `recoverable_now`
/// assumes that every supplied part is currently obtainable and correct for
/// the same original chunk. The pure evaluator cannot establish that premise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRecoveryPlacementReportV1 {
    recoverable_now: bool,
    survives_declared_faults: bool,
    worst_case_events: Vec<CellRecoveryFaultEventV1>,
    minimum_distinct_shards: u8,
    worst_case_distinct_shards: u8,
    worst_case_whole_chunk_survives: bool,
    scenarios: u64,
    steps: u64,
}

impl CellRecoveryPlacementReportV1 {
    pub fn recoverable_now(&self) -> bool {
        self.recoverable_now
    }

    pub fn survives_declared_faults(&self) -> bool {
        self.survives_declared_faults
    }

    /// A least-supported scenario: no surviving whole copy ranks below any
    /// surviving whole copy, then fewer distinct shards rank below more. Ties
    /// retain the first scenario in cardinality, then canonical event order.
    /// Any failing scenario therefore ranks below every successful scenario.
    pub fn worst_case_events(&self) -> &[CellRecoveryFaultEventV1] {
        &self.worst_case_events
    }

    /// Minimum distinct RS indices across every checked scenario. Whole copies
    /// do not manufacture shard indices, so this may be zero even on success.
    pub fn minimum_distinct_shards(&self) -> u8 {
        self.minimum_distinct_shards
    }

    pub fn worst_case_distinct_shards(&self) -> u8 {
        self.worst_case_distinct_shards
    }

    pub fn worst_case_whole_chunk_survives(&self) -> bool {
        self.worst_case_whole_chunk_survives
    }

    pub fn scenarios(&self) -> u64 {
        self.scenarios
    }

    /// Exact metered work: one provider/event membership check for each event,
    /// one provider-mask inspection per scenario, and one summary per scenario.
    /// Fixed-bound validation/sorting and instruction-level CPU are not steps.
    /// No successful or failed scenario short-circuits this work accounting.
    pub fn steps(&self) -> u64 {
        self.steps
    }
}

/// Evaluate declared placement of one already selected chunk. This function
/// supplies no byte, network, freshness, lease, funding or independence proof.
/// Provider and placement rosters must be strictly canonical; missing parts
/// are represented by absent placements, including an entirely empty roster.
///
/// Input cardinalities are checked before walking the inputs. At most 48 typed
/// events and 1,177 scenarios can arise. Exact metered work is reserved before
/// constructing event masks or enumerating scenarios. The caller must retain
/// and debit this original allowance across chunks and retries.
pub fn evaluate_recovery_placement(
    providers: &[CellRecoveryProviderPinV1],
    placements: &[CellRecoveryPlacementV1],
    policy: &CellRecoveryFaultPolicyV1,
    maximum_steps: u64,
) -> CellResultV1<CellRecoveryPlacementReportV1> {
    require(
        (1..=MAX_CELL_RECOVERY_PROVIDERS_V1).contains(&providers.len())
            && placements.len() <= MAX_CELL_RECOVERY_PLACEMENTS_V1
            && policy.axes.len() <= 3
            && policy.maximum_lost_events <= 2,
        "recovery placement bounds",
    )?;
    require(
        policy.axes.windows(2).all(|pair| pair[0] < pair[1])
            && (policy.maximum_lost_events == 0 || !policy.axes.is_empty()),
        "recovery fault axes",
    )?;
    require(
        providers
            .windows(2)
            .all(|pair| pair[0].provider_id < pair[1].provider_id),
        "recovery provider order/duplicates",
    )?;
    for provider in providers {
        require(
            [
                provider.provider_id,
                provider.operator,
                provider.administrator,
                provider.failure_domain,
                provider.domain_evidence,
            ]
            .iter()
            .all(|id| *id != [0; 32]),
            "recovery provider identity",
        )?;
    }
    require(
        placements.windows(2).all(|pair| pair[0] < pair[1]),
        "recovery placement order/duplicates",
    )?;
    let mut provider_parts = [0_u8; MAX_CELL_RECOVERY_PROVIDERS_V1];
    for placement in placements {
        let bit = match placement.part {
            CellRecoveryPartV1::WholeChunk => WHOLE_CHUNK_BIT,
            CellRecoveryPartV1::Rs46(index) => {
                require(index < 6, "recovery RS46 shard index")?;
                1_u8 << index
            }
        };
        let index = providers
            .binary_search_by_key(&placement.provider_id, |pin| pin.provider_id)
            .map_err(|_| CellErrorV1::Invalid("recovery unknown provider"))?;
        provider_parts[index] |= bit;
    }

    let mut events = Vec::with_capacity(MAX_CELL_RECOVERY_FAULT_EVENTS_V1);
    if policy.maximum_lost_events > 0 {
        for axis in &policy.axes {
            for provider in providers {
                events.push(CellRecoveryFaultEventV1 {
                    axis: *axis,
                    identity: axis.identity(provider),
                });
            }
        }
        events.sort_unstable();
        events.dedup();
    }
    let event_count = events.len() as u64;
    let scenario_count = 1
        + event_count
        + if policy.maximum_lost_events == 2 {
            event_count * event_count.saturating_sub(1) / 2
        } else {
            0
        };
    require(
        scenario_count <= MAX_CELL_RECOVERY_FAULT_SCENARIOS_V1,
        "recovery fault scenario bound",
    )?;
    // Arithmetic operands are independently bounded above (16/48/1,177), but
    // use checked arithmetic so changing a bound cannot silently wrap a debit.
    let provider_count = providers.len() as u64;
    let required_steps = event_count
        .checked_mul(provider_count)
        .and_then(|setup| {
            scenario_count
                .checked_mul(provider_count + 1)
                .and_then(|evaluation| setup.checked_add(evaluation))
        })
        .ok_or(CellErrorV1::Invalid("recovery placement step overflow"))?;
    require(
        required_steps <= maximum_steps,
        "recovery placement evaluation budget",
    )?;

    let mut report = CellRecoveryPlacementReportV1 {
        recoverable_now: false,
        survives_declared_faults: true,
        worst_case_events: Vec::new(),
        minimum_distinct_shards: 6,
        worst_case_distinct_shards: 6,
        worst_case_whole_chunk_survives: true,
        scenarios: 0,
        steps: 0,
    };
    let mut masks = Vec::with_capacity(events.len());
    for event in &events {
        let mut mask = 0_u16;
        for (index, provider) in providers.iter().enumerate() {
            report.steps += 1;
            if event.axis.identity(provider) == event.identity {
                mask |= 1_u16 << index;
            }
        }
        masks.push(mask);
    }

    let parts = &provider_parts[..providers.len()];
    let mut worst_support = (true, 7);
    observe_scenario(&mut report, &mut worst_support, parts, 0, &[]);
    for (index, event) in events.iter().enumerate() {
        observe_scenario(
            &mut report,
            &mut worst_support,
            parts,
            masks[index],
            &[*event],
        );
    }
    if policy.maximum_lost_events == 2 {
        for first in 0..events.len() {
            for second in first + 1..events.len() {
                observe_scenario(
                    &mut report,
                    &mut worst_support,
                    parts,
                    masks[first] | masks[second],
                    &[events[first], events[second]],
                );
            }
        }
    }
    require(
        report.steps == required_steps && report.scenarios == scenario_count,
        "recovery placement accounting",
    )?;
    Ok(report)
}

fn observe_scenario(
    report: &mut CellRecoveryPlacementReportV1,
    worst_support: &mut (bool, u8),
    provider_parts: &[u8],
    failed_providers: u16,
    events: &[CellRecoveryFaultEventV1],
) {
    let mut parts = 0_u8;
    for (index, provider) in provider_parts.iter().enumerate() {
        report.steps += 1;
        if failed_providers & (1_u16 << index) == 0 {
            parts |= provider;
        }
    }
    let distinct_shards = (parts & SHARD_BITS).count_ones() as u8;
    let whole_chunk = parts & WHOLE_CHUNK_BIT != 0;
    let recoverable = whole_chunk || distinct_shards >= 4;
    if report.scenarios == 0 {
        report.recoverable_now = recoverable;
    }
    report.survives_declared_faults &= recoverable;
    report.minimum_distinct_shards = report.minimum_distinct_shards.min(distinct_shards);
    let support = (whole_chunk, distinct_shards);
    if support < *worst_support {
        *worst_support = support;
        report.worst_case_events = events.to_vec();
        report.worst_case_distinct_shards = distinct_shards;
        report.worst_case_whole_chunk_survives = whole_chunk;
    }
    report.scenarios += 1;
    report.steps += 1;
}

#[cfg(test)]
mod tests;
