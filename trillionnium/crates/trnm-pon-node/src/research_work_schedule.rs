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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    max_ancestor_time: u64,
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
            max_ancestor_time: points
                .iter()
                .map(|point| point.timestamp)
                .max()
                .ok_or("SCHEDULE_HISTORY")?,
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

    /// Maximum timestamp of this complete parent path, including genesis.
    /// Legacy prefixes can be nonmonotone, so the tip alone is insufficient.
    pub fn max_ancestor_time(&self) -> u64 {
        self.max_ancestor_time
    }

    pub fn branch_clock_eligibility(&self, now: u64) -> ClockEligibility {
        clock_eligibility_at(
            self.max_ancestor_time
                .saturating_sub(self.profile.inputs.future_skew_seconds),
            now,
        )
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
            branch_eligible_at: self
                .max_ancestor_time
                .max(header.timestamp)
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
    branch_eligible_at: u64,
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
    /// Candidate-only current eligibility, not eligibility of its ancestors.
    /// The local clock cannot alter target, statement or historical credit.
    pub fn clock_eligibility(&self, now: u64) -> ClockEligibility {
        clock_eligibility_at(self.eligible_at, now)
    }

    /// Current eligibility of the complete prefix including this candidate.
    /// A legacy ancestor may be later than the candidate or its parent.
    pub fn branch_clock_eligibility(&self, now: u64) -> ClockEligibility {
        clock_eligibility_at(self.branch_eligible_at, now)
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

fn clock_eligibility_at(eligible_at: u64, now: u64) -> ClockEligibility {
    if now >= eligible_at {
        ClockEligibility::Eligible
    } else {
        ClockEligibility::DeferredUntil(eligible_at)
    }
}

/// Ephemeral research prefix constructed only by complete W1 packet checks.
///
/// Unlike caller-supplied arithmetic history, this private state starts at
/// genesis and advances through full PNH1 or PGH2 verification. Each append
/// replays only its candidate proof. It does not authenticate application State,
/// task authorization, native storage, or production consensus. No checkpoint,
/// peer work claim, deserialization or CheckedBranchSchedule import exists.
///
/// Cloning explicitly branches an already checked research prefix. Its memory
/// remains bounded by MAX_RESEARCH_HEIGHT; cold reconstruction must replay
/// complete packets again. This is not a native Node/storage-epoch cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrementalWorkSchedule {
    profile: Profile,
    points: Vec<Point>,
    seen: BTreeSet<Hash>,
    cumulative_work: Work,
    anchor: Option<Anchor>,
    max_ancestor_time: u64,
}

impl IncrementalWorkSchedule {
    pub fn new(profile: &Profile) -> Self {
        let config = profile.inputs();
        Self {
            profile: profile.clone(),
            points: vec![Point {
                block: config.genesis,
                height: 0,
                timestamp: config.genesis_time,
                target: config.initial_target,
            }],
            seen: BTreeSet::from([config.genesis]),
            cumulative_work: Work::default(),
            anchor: None,
            max_ancestor_time: config.genesis_time,
        }
    }

    pub fn profile_id(&self) -> Hash {
        self.profile.id()
    }

    pub fn tip(&self) -> Hash {
        self.points.last().expect("genesis point is retained").block
    }

    pub fn height(&self) -> u64 {
        self.points
            .last()
            .expect("genesis point is retained")
            .height
    }

    pub fn cumulative_work(&self) -> Work {
        self.cumulative_work
    }

    pub fn anchor(&self) -> Option<Anchor> {
        self.anchor
    }

    pub fn max_ancestor_time(&self) -> u64 {
        self.max_ancestor_time
    }

    pub fn branch_clock_eligibility(&self, now: u64) -> ClockEligibility {
        clock_eligibility_at(
            self.max_ancestor_time
                .saturating_sub(self.profile.inputs.future_skew_seconds),
            now,
        )
    }

    /// Export arithmetic about the next candidate without replaying ancestors.
    /// A terminal prefix at height 4096 is valid, but has no successor context.
    pub fn next_context(&self) -> Result<CheckedBranchSchedule> {
        let parent = self.points.last().ok_or("SCHEDULE_HISTORY")?;
        Ok(CheckedBranchSchedule {
            profile: self.profile.clone(),
            parent: parent.block,
            parent_height: parent.height,
            parent_time: parent.timestamp,
            median: median(&self.points),
            max_ancestor_time: self.max_ancestor_time,
            required_target: required(&self.profile, &self.points)?,
            cumulative_work: self.cumulative_work,
            anchor: self.anchor,
        })
    }

    /// Every ordinary refusal, including a final cancellation, leaves self
    /// unchanged. The returned receipt is published with the prefix once.
    pub fn append_pnh1_packet(
        &mut self,
        packet: &Packet,
        progress: &mut impl FnMut() -> Result<()>,
    ) -> Result<FullWorkCheck> {
        ensure(
            self.profile.inputs.wire == NativeWire::Pnh1,
            "SCHEDULE_WIRE",
        )?;
        let block = packet.id()?;
        ensure(!self.seen.contains(&block), "SCHEDULE_DUPLICATE_BLOCK")?;
        let checked = self.next_context()?.check_pnh1_packet(packet, progress)?;
        self.finish_append(&packet.header, checked, progress)
    }

    /// Uses the actual PGH2 challenge, never the nested PNH1 ledger challenge.
    pub fn append_pgh2_packet(
        &mut self,
        packet: &GrowthPacket,
        progress: &mut impl FnMut() -> Result<()>,
    ) -> Result<FullWorkCheck> {
        ensure(
            self.profile.inputs.wire == NativeWire::Pgh2,
            "SCHEDULE_WIRE",
        )?;
        let block = packet.id()?;
        ensure(!self.seen.contains(&block), "SCHEDULE_DUPLICATE_BLOCK")?;
        let checked = self.next_context()?.check_pgh2_packet(packet, progress)?;
        self.finish_append(&packet.header.ledger, checked, progress)
    }

    // Only the two full-verification methods above may reach this publisher.
    // Derive every fallible value and take the final cancellation checkpoint
    // before modifying any prefix field. No successor target is needed here:
    // accepting the terminal height must not accidentally request height 4097.
    fn finish_append(
        &mut self,
        header: &Header,
        checked: FullWorkCheck,
        progress: &mut impl FnMut() -> Result<()>,
    ) -> Result<FullWorkCheck> {
        let parent = self.points.last().ok_or("SCHEDULE_HISTORY")?;
        let next_anchor = match self.profile.inputs.policy {
            Policy::AnchoredAsert {
                activation_height, ..
            } if header.height == activation_height => Some(Anchor {
                key: AnchorKey {
                    profile: self.profile.id,
                    block: checked.block,
                },
                height: header.height,
                target: header.target,
                parent_time: parent.timestamp,
            }),
            _ => self.anchor,
        };
        let point = Point {
            block: checked.block,
            height: header.height,
            timestamp: header.timestamp,
            target: header.target,
        };
        let next_work = checked.historical.cumulative_work;
        let next_maximum = self.max_ancestor_time.max(header.timestamp);
        progress()?;

        self.points.push(point);
        self.seen.insert(checked.block);
        self.cumulative_work = next_work;
        self.anchor = next_anchor;
        self.max_ancestor_time = next_maximum;
        Ok(checked)
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

#[cfg(test)]
mod incremental_boundary_tests {
    use super::*;

    #[test]
    fn terminal_arithmetic_fixture_accepts_one_complete_w1_then_refuses_successor() {
        let profile = Profile::new(ProfileInputs {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            genesis_time: 1000,
            initial_target: [255; 32],
            pow_limit: [255; 32],
            legacy_interval: 16,
            spacing_seconds: 10,
            future_skew_seconds: 120,
            wire: NativeWire::Pnh1,
            policy: Policy::FixedTarget,
        })
        .unwrap();
        let mut prefix = IncrementalWorkSchedule::new(&profile);

        // Private arithmetic boundary fixture only. These 4095 prefix IDs are
        // synthetic; this test does NOT claim 4096 complete proof executions.
        // There is deliberately no production API for importing this state.
        let work = consensus::required_work([255; 32]).unwrap();
        for height in 1..MAX_RESEARCH_HEIGHT {
            let block = hash(b"incremental-boundary-fixture", &[&height.to_le_bytes()]);
            prefix.points.push(Point {
                block,
                height,
                timestamp: 1000 + height,
                target: [255; 32],
            });
            prefix.seen.insert(block);
            prefix.cumulative_work = prefix.cumulative_work.checked_add(work).unwrap();
            prefix.max_ancestor_time = 1000 + height;
        }
        let before = prefix.cumulative_work();
        let (a, b) = crate::maintenance();
        let header = Header {
            network: profile.inputs.network,
            parameters: profile.inputs.parameters,
            parent: prefix.tip(),
            height: MAX_RESEARCH_HEIGHT,
            timestamp: 1000 + MAX_RESEARCH_HEIGHT,
            target: prefix.next_context().unwrap().required_target(),
            miner: [4; 32],
            transactions: sequence_root("transactions", &[]),
            state: [6; 32],
            receipts: [7; 32],
            work_task: pon_work::task_id(&a, &b).unwrap(),
            nonce: 0,
        };
        let proof = pon_work::prove(header.challenge(), &a, &b).unwrap();
        let packet = Packet {
            header,
            transactions: vec![],
            proof,
        };
        let accepted = prefix.append_pnh1_packet(&packet, &mut || Ok(())).unwrap();
        assert_eq!(prefix.height(), MAX_RESEARCH_HEIGHT);
        assert_eq!(prefix.tip(), accepted.block());
        assert_eq!(prefix.cumulative_work(), before.checked_add(work).unwrap());
        assert_eq!(
            prefix.next_context().unwrap_err().to_string(),
            "SCHEDULE_HORIZON"
        );

        let terminal = prefix.clone();
        let mut successor = packet.clone();
        successor.header.parent = prefix.tip();
        successor.header.height += 1;
        successor.header.timestamp += 1;
        let mut callbacks = 0;
        assert_eq!(
            prefix
                .append_pnh1_packet(&successor, &mut || {
                    callbacks += 1;
                    Ok(())
                })
                .unwrap_err()
                .to_string(),
            "SCHEDULE_HORIZON"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(prefix, terminal);
        assert_eq!(
            prefix
                .append_pnh1_packet(&packet, &mut || Ok(()))
                .unwrap_err()
                .to_string(),
            "SCHEDULE_DUPLICATE_BLOCK"
        );
        assert_eq!(prefix, terminal);
    }
}
