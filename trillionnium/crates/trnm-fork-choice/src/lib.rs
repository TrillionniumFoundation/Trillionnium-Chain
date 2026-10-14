#![forbid(unsafe_code)]
//! Pure PoN branch choice over already persisted validation facts.
//!
//! This module deliberately does not verify headers, work certificates, state roots,
//! availability or persistence. Those facts remain owned by M01/M06/M07/M09. A
//! caller can only make a branch eligible by explicitly supplying both validation
//! and availability premises; this crate has no activation or network authority.

/// A protocol hash used to identify a block tip.
pub type Hash32 = [u8; 32];

/// Big-endian cumulative required work.  The protocol uses 512-bit chainwork;
/// lexicographic comparison is numeric comparison for fixed-width big-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainWork([u8; 64]);

impl ChainWork {
    /// The zero work value, useful for genesis test fixtures.
    pub const ZERO: Self = Self([0; 64]);

    /// Wrap a canonical 512-bit big-endian cumulative-work value.
    pub const fn from_be_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Return the canonical big-endian bytes.
    pub const fn to_be_bytes(self) -> [u8; 64] {
        self.0
    }
}

/// Validation facts required before a tip can participate in fork choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchTip {
    id: Hash32,
    parent: Hash32,
    height: u64,
    chainwork: ChainWork,
    fully_validated: bool,
    available: bool,
}

impl BranchTip {
    /// Construct a tip summary from persisted branch facts.
    ///
    /// This constructor does not validate any bytes or perform I/O; the two boolean
    /// premises must come from the owning admission/availability components.
    pub const fn new(
        id: Hash32,
        parent: Hash32,
        height: u64,
        chainwork: ChainWork,
        fully_validated: bool,
        available: bool,
    ) -> Self {
        Self {
            id,
            parent,
            height,
            chainwork,
            fully_validated,
            available,
        }
    }

    pub const fn id(&self) -> Hash32 {
        self.id
    }

    pub const fn parent(&self) -> Hash32 {
        self.parent
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn chainwork(&self) -> ChainWork {
        self.chainwork
    }

    pub const fn is_fully_validated(&self) -> bool {
        self.fully_validated
    }

    pub const fn is_available(&self) -> bool {
        self.available
    }

    const fn eligible(&self) -> bool {
        self.fully_validated && self.available
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkChoiceError {
    /// The current active tip is not fully validated and available.
    InvalidCurrentTip,
}

/// Select the strictly-heavier eligible branch.
///
/// An invalid candidate is ignored. An invalid current tip is an error because a
/// node must never silently continue from a tip that was not fully validated. Equal
/// work retains the current tip, preserving the protocol's deterministic
/// "same work retains current" rule. With no current tip, the first eligible
/// candidate at the maximum work is selected in input order.
pub fn choose_branch(
    current: Option<&BranchTip>,
    candidates: &[BranchTip],
) -> Result<Option<BranchTip>, ForkChoiceError> {
    if let Some(active) = current {
        if !active.eligible() {
            return Err(ForkChoiceError::InvalidCurrentTip);
        }
    }

    let mut best = current.copied();
    for candidate in candidates {
        if !candidate.eligible() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|active| candidate.chainwork > active.chainwork)
        {
            best = Some(*candidate);
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(byte: u8, work: u8, valid: bool, available: bool) -> BranchTip {
        let mut id = [0; 32];
        id[0] = byte;
        BranchTip::new(
            id,
            [0; 32],
            u64::from(byte),
            ChainWork::from_be_bytes({
                let mut bytes = [0; 64];
                bytes[63] = work;
                bytes
            }),
            valid,
            available,
        )
    }

    #[test]
    fn selects_only_strictly_heavier_fully_validated_available_tip() {
        let current = tip(1, 4, true, true);
        let lower = tip(2, 5, false, true);
        let unavailable = tip(3, 6, true, false);
        let heavier = tip(4, 7, true, true);

        let selected = choose_branch(Some(&current), &[lower, unavailable, heavier]).unwrap();
        assert_eq!(selected.unwrap().id(), heavier.id());
    }

    #[test]
    fn equal_work_retains_current_tip() {
        let current = tip(1, 9, true, true);
        let equal = tip(2, 9, true, true);
        let selected = choose_branch(Some(&current), &[equal]).unwrap().unwrap();
        assert_eq!(selected.id(), current.id());
    }

    #[test]
    fn invalid_current_tip_fails_closed() {
        let current = tip(1, 1, false, true);
        assert_eq!(
            choose_branch(Some(&current), &[]),
            Err(ForkChoiceError::InvalidCurrentTip)
        );
    }

    #[test]
    fn no_current_chooses_first_maximum_work_in_input_order() {
        let first = tip(1, 8, true, true);
        let equal = tip(2, 8, true, true);
        let lower = tip(3, 7, true, true);
        let selected = choose_branch(None, &[lower, first, equal]).unwrap().unwrap();
        assert_eq!(selected.id(), first.id());
    }

    #[test]
    fn fixed_width_chainwork_compares_as_big_endian_number() {
        let mut low = [0; 64];
        low[62] = 1;
        let mut high = [0; 64];
        high[63] = 1;
        assert!(ChainWork::from_be_bytes(low) > ChainWork::ZERO);
        assert!(ChainWork::from_be_bytes(high) > ChainWork::from_be_bytes(low));
    }
}
