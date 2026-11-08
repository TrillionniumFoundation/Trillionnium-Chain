//! Bounded, opt-in work-schedule research. No admission or activation owner.
//!
//! A checked schedule is an arithmetic statement about one complete parent
//! path. It is not proof of application execution, storage authenticity, a
//! cheapest-work bound, or permission to install these rules in a Node.
//! Existing PNH1/PGH2 header domains and all Node policies stay unchanged.
use crate::{
    consensus, ensure, sequence_root, Error, GrowthPacket, Node, Packet, Result, Settings,
};
use consensus::Work;
use std::collections::BTreeSet;
use trnm_crypto_primitives::pon_work::{self, VerificationError};
use trnm_protocol::pon_wire::{hash, Hash, Header, HEADER_BYTES};

pub const SCHEMA: &str = "pon-branch-work-schedule-research-v1";
pub const MAX_RESEARCH_HEIGHT: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeWire {
    Pnh1,
    Pgh2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Fixed from this research genesis through the entire bounded window.
    /// This is not merely the legacy interval between two retargets.
    FixedTarget,
    /// The activation block is still checked under the old target/time rules.
    /// Its own target and its parent's time anchor every subsequent target.
    AnchoredAsert {
        activation_height: u64,
        half_life_seconds: u64,
    },
}

/// Independently chosen inputs, not fields to infer from a peer's claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileInputs {
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub genesis_time: u64,
    pub initial_target: Hash,
    pub pow_limit: Hash,
    pub legacy_interval: u64,
    pub spacing_seconds: u64,
    pub future_skew_seconds: u64,
    pub wire: NativeWire,
    pub policy: Policy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    inputs: ProfileInputs,
    id: Hash,
}

impl Profile {
    pub fn new(inputs: ProfileInputs) -> Result<Self> {
        ensure(
            inputs.initial_target != [0; 32]
                && inputs.initial_target <= inputs.pow_limit
                && (16..=MAX_RESEARCH_HEIGHT).contains(&inputs.legacy_interval)
                && inputs.spacing_seconds > 0,
            "SCHEDULE_PARAMETERS",
        )?;
        (inputs.legacy_interval - 1)
            .checked_mul(inputs.spacing_seconds)
            .and_then(|value| value.checked_mul(4))
            .ok_or("SCHEDULE_PARAMETERS")?;
        if let Policy::AnchoredAsert {
            activation_height,
            half_life_seconds,
        } = inputs.policy
        {
            ensure(
                (1..MAX_RESEARCH_HEIGHT).contains(&activation_height) && half_life_seconds > 0,
                "SCHEDULE_PARAMETERS",
            )?;
        }
        let mut encoding = Vec::new();
        for value in [
            inputs.network,
            inputs.parameters,
            inputs.genesis,
            inputs.initial_target,
            inputs.pow_limit,
        ] {
            encoding.extend(value);
        }
        for value in [
            inputs.genesis_time,
            inputs.legacy_interval,
            inputs.spacing_seconds,
            inputs.future_skew_seconds,
            MAX_RESEARCH_HEIGHT,
        ] {
            encoding.extend(value.to_le_bytes());
        }
        encoding.push(match inputs.wire {
            NativeWire::Pnh1 => 1,
            NativeWire::Pgh2 => 2,
        });
        match inputs.policy {
            Policy::FixedTarget => encoding.push(0),
            Policy::AnchoredAsert {
                activation_height,
                half_life_seconds,
            } => {
                encoding.push(1);
                encoding.extend(activation_height.to_le_bytes());
                encoding.extend(half_life_seconds.to_le_bytes());
            }
        }
        let id = hash(SCHEMA.as_bytes(), &[&encoding]);
        Ok(Self { inputs, id })
    }

    /// Bind a research proposal to an existing Node's actual source settings.
    /// This does not modify the settings or make the new policy an on-wire rule.
    pub fn for_node(settings: &Settings, policy: Policy) -> Result<Self> {
        let wire = if settings.is_permanent_account_growth_v2() {
            NativeWire::Pgh2
        } else {
            ensure(
                settings.packet_header_length() == HEADER_BYTES,
                "SCHEDULE_UNSUPPORTED_WIRE",
            )?;
            NativeWire::Pnh1
        };
        Self::new(ProfileInputs {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
            genesis_time: settings.genesis_time(),
            initial_target: settings.target("initial_target_hex")?,
            pow_limit: settings.target("pow_limit_hex")?,
            legacy_interval: settings.limit("retarget_interval")?,
            spacing_seconds: settings.limit("target_spacing_seconds")?,
            future_skew_seconds: settings.limit("future_skew_seconds")?,
            wire,
            policy,
        })
    }

    pub fn id(&self) -> Hash {
        self.id
    }

    pub fn inputs(&self) -> &ProfileInputs {
        &self.inputs
    }
}

/// Public arithmetic input. Supplying this struct asserts no native validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryHeader {
    pub block: Hash,
    pub header: Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorKey {
    pub profile: Hash,
    pub block: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    key: AnchorKey,
    height: u64,
    target: Hash,
    parent_time: u64,
}

impl Anchor {
    pub fn key(&self) -> AnchorKey {
        self.key
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn target(&self) -> Hash {
        self.target
    }
    pub fn parent_time(&self) -> u64 {
        self.parent_time
    }
}

#[derive(Clone, Copy)]
struct Point {
    block: Hash,
    height: u64,
    timestamp: u64,
    target: Hash,
}

/// Private construction prevents skipping this component's schedule checks.
/// It does not turn caller-provided arithmetic history into authenticated data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBranchSchedule {
    profile: Profile,
    parent: Hash,
    parent_height: u64,
    parent_time: u64,
    median: u64,
    required_target: Hash,
    cumulative_work: Work,
    anchor: Option<Anchor>,
}

impl CheckedBranchSchedule {
    /// Reconstruct a whole genesis-to-parent schedule from parent-first input.
    /// There is no supplied anchor, cumulative-work claim, or checkpoint reset.
    pub fn from_parent_first(
        profile: &Profile,
        expected_parent: Hash,
        parent_first: &[HistoryHeader],
    ) -> Result<Self> {
        ensure(
            parent_first.len() < MAX_RESEARCH_HEIGHT as usize,
            "SCHEDULE_HORIZON",
        )?;
        let config = &profile.inputs;
        let mut points = vec![Point {
            block: config.genesis,
            height: 0,
            timestamp: config.genesis_time,
            target: config.initial_target,
        }];
        let mut seen = BTreeSet::from([config.genesis]);
        let mut cumulative_work = Work::default();
        for row in parent_first.iter().rev() {
            let parent = *points.last().ok_or("SCHEDULE_HISTORY")?;
            check_link(config, &row.header, parent)?;
            ensure(seen.insert(row.block), "SCHEDULE_DUPLICATE_BLOCK")?;
            let expected = required(profile, &points)?;
            ensure(row.header.target == expected, "SCHEDULE_TARGET")?;
            check_historical_time(config, &row.header, parent, median(&points))?;
            cumulative_work = cumulative_work.checked_add(consensus::required_work(expected)?)?;
            points.push(Point {
                block: row.block,
                height: row.header.height,
                timestamp: row.header.timestamp,
                target: row.header.target,
            });
        }
        let parent = *points.last().ok_or("SCHEDULE_HISTORY")?;
        ensure(parent.block == expected_parent, "SCHEDULE_EXPECTED_PARENT")?;
        Ok(Self {
            profile: profile.clone(),
            parent: parent.block,
            parent_height: parent.height,
            parent_time: parent.timestamp,
            median: median(&points),
            required_target: required(profile, &points)?,
            cumulative_work,
            anchor: branch_anchor(profile, &points)?,
        })
    }

    /// Pure historical result: no candidate timestamp, peer work, or wall clock.
    pub fn required_target(&self) -> Hash {
        self.required_target
    }
    pub fn profile_id(&self) -> Hash {
        self.profile.id
    }
    pub fn parent(&self) -> Hash {
        self.parent
    }
    pub fn cumulative_work(&self) -> Work {
        self.cumulative_work
    }
    pub fn anchor(&self) -> Option<Anchor> {
        self.anchor
    }

    /// A retained anchor hint is never allowed to replace this branch's anchor.
    pub fn check_anchor_hint(&self, hint: Anchor) -> Result<()> {
        ensure(self.anchor == Some(hint), "SCHEDULE_ANCHOR_MISMATCH")
    }

    pub fn check_historical_header(&self, header: &Header) -> Result<HistoricalCheck> {
        let parent = Point {
            block: self.parent,
            height: self.parent_height,
            timestamp: self.parent_time,
            target: self.required_target,
        };
        check_link(&self.profile.inputs, header, parent)?;
        ensure(header.target == self.required_target, "SCHEDULE_TARGET")?;
        check_historical_time(&self.profile.inputs, header, parent, self.median)?;
        let block_work = consensus::required_work(self.required_target)?;
        Ok(HistoricalCheck {
            profile: self.profile.id,
            statement: hash(
                b"pon-research-schedule-statement-v1",
                &[&self.profile.id, &header.encode()],
            ),
            required_target: self.required_target,
            block_work,
            cumulative_work: self.cumulative_work.checked_add(block_work)?,
            eligible_at: header
                .timestamp
                .saturating_sub(self.profile.inputs.future_skew_seconds),
        })
    }

    /// Check the actual PNH1 challenge and complete PNW1 relation after schedule
    /// preflight. State, receipts, task authorization and native admission are
    /// deliberately not claimed by this research result.
    pub fn check_pnh1_packet(
        &self,
        packet: &Packet,
        progress: &mut impl FnMut() -> Result<()>,
    ) -> Result<FullWorkCheck> {
        ensure(
            self.profile.inputs.wire == NativeWire::Pnh1,
            "SCHEDULE_WIRE",
        )?;
        let historical = self.check_historical_header(&packet.header)?;
        packet.encode()?;
        ensure(
            packet.header.transactions == sequence_root("transactions", &packet.transactions),
            "SCHEDULE_TRANSACTIONS",
        )?;
        replay(
            packet.header.challenge(),
            &packet.header,
            &packet.proof,
            progress,
        )?;
        Ok(FullWorkCheck {
            historical,
            block: packet.id()?,
            wire: NativeWire::Pnh1,
        })
    }

    /// Uses the PGH2 challenge, including its account-witness commitment; it
    /// never substitutes the PNH1 challenge of the nested ledger header.
    pub fn check_pgh2_packet(
        &self,
        packet: &GrowthPacket,
        progress: &mut impl FnMut() -> Result<()>,
    ) -> Result<FullWorkCheck> {
        ensure(
            self.profile.inputs.wire == NativeWire::Pgh2,
            "SCHEDULE_WIRE",
        )?;
        let historical = self.check_historical_header(&packet.header.ledger)?;
        packet.encode()?;
        ensure(
            packet.header.ledger.transactions
                == sequence_root("transactions", &packet.transactions),
            "SCHEDULE_TRANSACTIONS",
        )?;
        replay(
            packet.header.challenge(),
            &packet.header.ledger,
            &packet.proof,
            progress,
        )?;
        Ok(FullWorkCheck {
            historical,
            block: packet.id()?,
            wire: NativeWire::Pgh2,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalCheck {
    profile: Hash,
    statement: Hash,
    required_target: Hash,
    block_work: Work,
    cumulative_work: Work,
    eligible_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockEligibility {
    Eligible,
    DeferredUntil(u64),
}

impl HistoricalCheck {
    pub fn profile_id(&self) -> Hash {
        self.profile
    }
    pub fn statement(&self) -> Hash {
        self.statement
    }
    pub fn required_target(&self) -> Hash {
        self.required_target
    }
    pub fn block_work(&self) -> Work {
        self.block_work
    }
    pub fn cumulative_work(&self) -> Work {
        self.cumulative_work
    }
    /// The local clock controls only present eligibility. It cannot alter any
    /// previously computed target, statement, or historical work contribution.
    pub fn clock_eligibility(&self, now: u64) -> ClockEligibility {
        if now >= self.eligible_at {
            ClockEligibility::Eligible
        } else {
            ClockEligibility::DeferredUntil(self.eligible_at)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullWorkCheck {
    historical: HistoricalCheck,
    block: Hash,
    wire: NativeWire,
}

impl FullWorkCheck {
    pub fn historical(&self) -> &HistoricalCheck {
        &self.historical
    }
    pub fn block(&self) -> Hash {
        self.block
    }
    pub fn wire(&self) -> NativeWire {
        self.wire
    }
}

fn check_link(config: &ProfileInputs, header: &Header, parent: Point) -> Result<()> {
    ensure(
        header.network == config.network && header.parameters == config.parameters,
        "SCHEDULE_NAMESPACE",
    )?;
    ensure(header.parent == parent.block, "SCHEDULE_PARENT")?;
    ensure(
        parent.height.checked_add(1) == Some(header.height) && header.height <= MAX_RESEARCH_HEIGHT,
        "SCHEDULE_HEIGHT",
    )
}

fn median(points: &[Point]) -> u64 {
    let mut times: Vec<_> = points.iter().rev().take(11).map(|p| p.timestamp).collect();
    times.sort_unstable();
    times[times.len() / 2]
}

fn check_historical_time(
    config: &ProfileInputs,
    header: &Header,
    parent: Point,
    median: u64,
) -> Result<()> {
    let new_rule = match config.policy {
        Policy::FixedTarget => true,
        Policy::AnchoredAsert {
            activation_height, ..
        } => header.height > activation_height,
    };
    if new_rule {
        ensure(
            header.timestamp >= parent.timestamp,
            "SCHEDULE_TIME_NONDECREASING",
        )?;
    }
    ensure(header.timestamp > median, "SCHEDULE_TIME_MTP")
}

fn branch_anchor(profile: &Profile, points: &[Point]) -> Result<Option<Anchor>> {
    let Policy::AnchoredAsert {
        activation_height, ..
    } = profile.inputs.policy
    else {
        return Ok(None);
    };
    let height = usize::try_from(activation_height).map_err(|_| "SCHEDULE_PARAMETERS")?;
    let Some(anchor) = points.get(height) else {
        return Ok(None);
    };
    let parent = points.get(height - 1).ok_or("SCHEDULE_ANCHOR_PARENT")?;
    Ok(Some(Anchor {
        key: AnchorKey {
            profile: profile.id,
            block: anchor.block,
        },
        height: anchor.height,
        target: anchor.target,
        parent_time: parent.timestamp,
    }))
}

fn required(profile: &Profile, points: &[Point]) -> Result<Hash> {
    let parent = points.last().ok_or("SCHEDULE_HISTORY")?;
    let height = parent.height.checked_add(1).ok_or("SCHEDULE_HEIGHT")?;
    ensure(height <= MAX_RESEARCH_HEIGHT, "SCHEDULE_HORIZON")?;
    let config = &profile.inputs;
    match config.policy {
        Policy::FixedTarget => Ok(config.initial_target),
        Policy::AnchoredAsert {
            activation_height,
            half_life_seconds,
        } => {
            if height <= activation_height {
                if height % config.legacy_interval != 0 {
                    return Ok(parent.target);
                }
                let index = usize::try_from(height - config.legacy_interval)
                    .map_err(|_| "SCHEDULE_HISTORY")?;
                return consensus::retarget(
                    parent.target,
                    points.get(index).ok_or("SCHEDULE_HISTORY")?.timestamp,
                    parent.timestamp,
                    config.legacy_interval,
                    config.spacing_seconds,
                    config.pow_limit,
                );
            }
            let anchor = branch_anchor(profile, points)?.ok_or("SCHEDULE_ANCHOR")?;
            asert_target(AsertInputs {
                anchor_target: anchor.target,
                time_delta: i128::from(parent.timestamp) - i128::from(anchor.parent_time),
                intervals: height - anchor.height,
                spacing_seconds: config.spacing_seconds,
                half_life_seconds,
                pow_limit: config.pow_limit,
            })
        }
    }
}

/// Integer-only inputs for a full 256-bit target, without BCH nBits rounding.
#[derive(Clone, Copy, Debug)]
pub struct AsertInputs {
    pub anchor_target: Hash,
    pub time_delta: i128,
    pub intervals: u64,
    pub spacing_seconds: u64,
    pub half_life_seconds: u64,
    pub pow_limit: Hash,
}

pub fn asert_target(input: AsertInputs) -> Result<Hash> {
    ensure(
        input.anchor_target != [0; 32]
            && input.anchor_target <= input.pow_limit
            && input.intervals > 0
            && input.spacing_seconds > 0
            && input.half_life_seconds > 0
            && (-i128::from(u64::MAX)..=i128::from(u64::MAX)).contains(&input.time_delta),
        "SCHEDULE_ASERT_PARAMETERS",
    )?;
    let ideal = i128::from(input.spacing_seconds)
        .checked_mul(i128::from(input.intervals))
        .ok_or("SCHEDULE_ASERT_I128_RANGE")?;
    let scaled = input
        .time_delta
        .checked_sub(ideal)
        .and_then(|value| value.checked_mul(65536))
        .ok_or("SCHEDULE_ASERT_I128_RANGE")?;
    // Rust signed division truncates toward zero; decomposition then floors.
    let exponent = scaled / i128::from(input.half_life_seconds);
    let shifts = exponent.div_euclid(65536) - 16;
    let fraction = exponent.rem_euclid(65536) as u128;
    let factor = 65536
        + ((195766423245049 * fraction
            + 971821376 * fraction * fraction
            + 5127 * fraction * fraction * fraction
            + (1_u128 << 47))
            >> 48);
    let one = Work::from_target({
        let mut bytes = [0; 32];
        bytes[31] = 1;
        bytes
    });
    if shifts <= -512 {
        return one.target();
    }
    if shifts >= 256 {
        return Ok(input.pow_limit);
    }
    let value = Work::from_target(input.anchor_target).mul_small(factor as u64)?;
    let Some(adjusted) = shift_work(value, shifts) else {
        return Ok(input.pow_limit);
    };
    adjusted
        .max(one)
        .min(Work::from_target(input.pow_limit))
        .target()
}

// A bounded 512-bit shift, independent of CPU/language oversized-shift rules.
// None means positive overflow, which has the unambiguous pow-limit outcome.
fn shift_work(value: Work, shift: i128) -> Option<Work> {
    let bytes = value.bytes();
    let mut out = [0_u8; 64];
    for bit in 0..512 {
        if bytes[63 - bit / 8] & (1 << (bit % 8)) == 0 {
            continue;
        }
        let destination = bit as i128 + shift;
        if destination >= 512 {
            return None;
        }
        if destination >= 0 {
            let destination = destination as usize;
            out[63 - destination / 8] |= 1 << (destination % 8);
        }
    }
    Some(Work::from_bytes(out))
}

fn replay(
    challenge: Hash,
    header: &Header,
    proof: &[u8],
    progress: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    match pon_work::verify_with_progress(
        challenge,
        header.work_task,
        header.target,
        proof,
        &mut |_| progress(),
    ) {
        Ok(_) => Ok(()),
        Err(VerificationError::Cancelled(error)) => Err(error),
        Err(VerificationError::Relation(error)) => Err(Error::from(format!("WORK:{error:?}"))),
    }
}

/// Read-only bridge from one original native parent path. Every retrieved W1
/// proof is replayed in its actual PNH1/PGH2 domain before schedule reconstruction.
/// This rechecks no State transition and grants no snapshot/transaction authority.
/// A current native history that violates the proposal is an ordinary refusal;
/// its existence must never be hidden by changing the expected profile.
pub fn inspect_retained_branch(
    node: &Node,
    profile: &Profile,
    parent: Hash,
    progress: &mut impl FnMut() -> Result<()>,
) -> Result<CheckedBranchSchedule> {
    ensure(
        Profile::for_node(node.settings(), profile.inputs.policy)? == *profile,
        "SCHEDULE_NODE_CONTEXT",
    )?;
    let mut id = parent;
    let mut rows = Vec::new();
    while id != profile.inputs.genesis {
        progress()?;
        ensure(
            rows.len() < MAX_RESEARCH_HEIGHT as usize - 1,
            "SCHEDULE_HORIZON",
        )?;
        let header = match profile.inputs.wire {
            NativeWire::Pnh1 => {
                let packet = node.packet(id)?;
                replay(
                    packet.header.challenge(),
                    &packet.header,
                    &packet.proof,
                    progress,
                )?;
                packet.header
            }
            NativeWire::Pgh2 => {
                let packet = node.growth_packet(id)?;
                replay(
                    packet.header.challenge(),
                    &packet.header.ledger,
                    &packet.proof,
                    progress,
                )?;
                packet.header.ledger
            }
        };
        ensure(
            node.parent_height(id)? == header.height,
            "SCHEDULE_STORED_HEIGHT",
        )?;
        rows.push(HistoryHeader { block: id, header });
        id = rows.last().ok_or("SCHEDULE_HISTORY")?.header.parent;
    }
    progress()?;
    CheckedBranchSchedule::from_parent_first(profile, parent, &rows)
}
