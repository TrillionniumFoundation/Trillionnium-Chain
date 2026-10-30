//! Cheap consistency checks on the claimed statement, never proof authentication.
//!
//! The pinned guest and its complete relation are unchanged. These checks repeat
//! its public header/task/target boundaries before the host opens a receipt.
use anyhow::{anyhow, ensure, Result};
use trnm_w1_guest_relation::full_relation::{self, PublicStatement};

const HEADER_TASK: std::ops::Range<usize> = 278..310;
const HEADER_TARGET: std::ops::Range<usize> = 118..150;

pub(super) fn prepare(input: &[u8]) -> Result<(PublicStatement, Vec<u8>)> {
    ensure!(
        input.len() == full_relation::INPUT_BYTES,
        "fixed W1 input length"
    );
    let statement = PublicStatement::decode(&input[..full_relation::STATEMENT_BYTES])
        .map_err(|error| anyhow!("{error:?}"))?;
    ensure!(
        statement.header_bytes()[HEADER_TASK] == statement.expected_task(),
        "claimed header task differs from expected task"
    );
    ensure!(
        statement.header_bytes()[HEADER_TARGET] == statement.expected_target(),
        "claimed header target differs from expected target"
    );
    ensure!(
        statement.expected_target() != [0; 32],
        "zero expected target"
    );
    let journal =
        full_relation::unverified_claimed_journal(input).map_err(|error| anyhow!("{error:?}"))?;
    Ok((statement, journal))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately false W1 arithmetic. Context consistency cannot authenticate it.
    fn false_input() -> Vec<u8> {
        let mut header = [0; full_relation::HEADER_BYTES];
        header[..4].copy_from_slice(b"PNH1");
        header[4] = 1;
        header[HEADER_TARGET].fill(255);
        header[HEADER_TASK].fill(9);
        let mut witness = vec![0; trnm_w1_guest_relation::PROOF_BYTES];
        witness[..4].copy_from_slice(b"PNW1");
        let statement = PublicStatement::bind(&header, [9; 32], [255; 32], &witness).unwrap();
        let mut input = statement.encode().to_vec();
        input.extend_from_slice(&witness);
        input
    }

    #[test]
    fn consistent_context_does_not_authenticate_false_work() {
        let input = false_input();
        let (_, journal) = prepare(&input).unwrap();
        assert_eq!(journal.len(), 228);
        assert!(full_relation::execute_input(&input).is_err());
    }

    #[test]
    fn mismatching_task_is_refused() {
        let mut input = false_input();
        input[38 + HEADER_TASK.start] ^= 1;
        assert!(prepare(&input)
            .unwrap_err()
            .to_string()
            .contains("header task"));
    }

    #[test]
    fn mismatching_target_is_refused() {
        let mut input = false_input();
        input[38 + HEADER_TARGET.start] ^= 1;
        assert!(prepare(&input)
            .unwrap_err()
            .to_string()
            .contains("header target"));
    }

    #[test]
    fn matching_zero_target_is_refused() {
        let mut input = false_input();
        input[38 + HEADER_TARGET.start..38 + HEADER_TARGET.end].fill(0);
        input[38 + full_relation::HEADER_BYTES + 32..38 + full_relation::HEADER_BYTES + 64].fill(0);
        assert!(prepare(&input)
            .unwrap_err()
            .to_string()
            .contains("zero expected target"));
    }

    #[test]
    fn exact_length_and_header_codec_are_still_required() {
        let input = false_input();
        for n in [0, full_relation::STATEMENT_BYTES - 1, input.len() - 1] {
            assert!(prepare(&input[..n]).is_err());
        }
        let mut extended = input.clone();
        extended.push(0);
        assert!(prepare(&extended).is_err());
        let mut malformed = input;
        malformed[38] ^= 1;
        assert!(prepare(&malformed).is_err());
    }

    #[test]
    fn witness_commitment_is_still_bound() {
        let mut input = false_input();
        input[full_relation::STATEMENT_BYTES + 100] ^= 1;
        assert!(prepare(&input).is_err());
    }
}
