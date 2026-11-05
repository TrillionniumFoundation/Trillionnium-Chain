//! M11 order-independent development attestation policy, not objective model truth.
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "closed-round-all-eligible-min-v1";

/// Close only after every frozen eligible evaluator has attested. Missing evaluations
/// never become zero or a passing quorum. The containing candidate's original expiry
/// bounds withholding. This has no consensus fork-weight or production authority.
pub fn complete_score(
    eligible: &BTreeSet<String>,
    votes: &BTreeMap<String, u64>,
    maximum_score: u64,
) -> Result<Option<u64>, &'static str> {
    if !(2..=3).contains(&eligible.len()) {
        return Err("EVALUATOR_ROSTER");
    }
    if votes.keys().any(|signer| !eligible.contains(signer)) {
        return Err("AUTHORITY");
    }
    if votes.values().any(|score| *score > maximum_score) {
        return Err("EVIDENCE");
    }
    if votes.len() != eligible.len() {
        return Ok(None);
    }
    Ok(votes.values().copied().min())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn roster() -> BTreeSet<String> {
        ["a", "b", "c"].into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn every_arrival_order_closes_at_the_same_minimum() {
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for order in orders {
            let mut votes = BTreeMap::new();
            for (n, i) in order.into_iter().enumerate() {
                votes.insert(["a", "b", "c"][i].to_owned(), [10, 100, 100][i]);
                assert_eq!(
                    complete_score(&roster(), &votes, 1000),
                    Ok(if n == 2 { Some(10) } else { None })
                );
            }
        }
    }
    #[test]
    fn missing_or_zero_attestation_cannot_unlock_positive_value() {
        let mut votes = BTreeMap::from([("b".into(), 100), ("c".into(), 100)]);
        assert_eq!(complete_score(&roster(), &votes, 1000), Ok(None));
        votes.insert("a".into(), 0);
        assert_eq!(complete_score(&roster(), &votes, 1000), Ok(Some(0)));
    }
    #[test]
    fn fixed_roster_and_score_range_are_checked() {
        let mut votes = BTreeMap::from([("unknown".into(), 1)]);
        assert_eq!(complete_score(&roster(), &votes, 1000), Err("AUTHORITY"));
        votes = BTreeMap::from([("a".into(), 1001)]);
        assert_eq!(complete_score(&roster(), &votes, 1000), Err("EVIDENCE"));
        assert_eq!(
            complete_score(&BTreeSet::new(), &BTreeMap::new(), 1000),
            Err("EVALUATOR_ROSTER")
        );
    }
    #[test]
    fn author_exclusion_requires_all_remaining_eligible_signers() {
        let eligible = BTreeSet::from(["a".into(), "b".into()]);
        let votes = BTreeMap::from([("a".into(), 10), ("b".into(), 100)]);
        assert_eq!(complete_score(&eligible, &votes, 1000), Ok(Some(10)));
    }
}
