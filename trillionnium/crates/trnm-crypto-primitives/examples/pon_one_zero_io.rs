//! Bounded offline complete-proof bridge. No mining or verification authority.
use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_work::{
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask, structured::StructuredPreparedTask, *,
};

#[derive(Clone, Copy, Debug)]
enum Operation {
    Generic,
    Reference,
    Blocked,
}
impl Operation {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "generic" => Ok(Self::Generic),
            "structured-zero-product-reference" => Ok(Self::Reference),
            "blocked-one-zero-rank-one" => Ok(Self::Blocked),
            _ => Err("OPERATION"),
        }
    }
}

fn produce(operation: Operation, input: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input.len() != 32 + 2 * CELLS * 4 {
        return Err("LENGTH");
    }
    let challenge: Hash = input[..32].try_into().map_err(|_| "LENGTH")?;
    let elements: Vec<_> = input[32..]
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four-byte chunk")))
        .collect();
    let (a, b) = elements.split_at(CELLS);
    // Check all canonical material before deciding support. The reference accepts
    // exactly one zero operand; the blocked path also requires a nonzero rank-one
    // counterpart. Neither selects another kernel for an unsupported operation.
    task_id(a, b).map_err(|_| "WORK")?;
    match operation {
        Operation::Generic => PreparedTask::new(a, b)
            .and_then(|task| task.prove(challenge))
            .map_err(|_| "WORK"),
        Operation::Reference => {
            if a.iter().all(|value| *value == 0) == b.iter().all(|value| *value == 0) {
                return Err("UNSUPPORTED");
            }
            StructuredPreparedTask::new(a, b)
                .map_err(|_| "WORK")?
                .ok_or("UNSUPPORTED")?
                .prove(challenge)
                .map_err(|_| "WORK")
        }
        Operation::Blocked => BlockedOneZeroRankOnePreparedTask::new(a, b)
            .map_err(|_| "WORK")?
            .ok_or("UNSUPPORTED")?
            .prove(challenge)
            .map_err(|_| "WORK"),
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let operation = arguments.next().ok_or("OPERATION")?;
    let operation = Operation::parse(operation.to_str().ok_or("OPERATION")?)?;
    if arguments.next().is_some() {
        return Err("OPERATION");
    }
    let expected = 32 + 2 * CELLS * 4;
    let mut input = Vec::new();
    io::stdin()
        .take(expected as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "IO")?;
    let proof = produce(operation, &input)?;
    io::stdout().write_all(&proof).map_err(|_| "IO")
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(zero_on_left: bool) -> Vec<u8> {
        let mut input = vec![7; 32];
        for matrix in 0..2 {
            for position in 0..CELLS {
                let value = if (matrix == 0) == zero_on_left {
                    0
                } else {
                    ((position / N + 1) * (position % N + 3)) as u32
                };
                input.extend_from_slice(&value.to_le_bytes());
            }
        }
        input
    }

    #[test]
    fn all_three_operations_return_identical_complete_proofs_for_both_directions() {
        for zero_on_left in [true, false] {
            let input = input(zero_on_left);
            let generic = produce(Operation::Generic, &input).unwrap();
            assert_eq!(generic.len(), PROOF_BYTES);
            assert_eq!(produce(Operation::Reference, &input).unwrap(), generic);
            assert_eq!(produce(Operation::Blocked, &input).unwrap(), generic);
        }
    }

    #[test]
    fn exact_extent_and_canonical_bytes_are_required_before_support_decisions() {
        let input = input(true);
        let mut extra = input.clone();
        extra.push(0);
        for operation in [Operation::Generic, Operation::Reference, Operation::Blocked] {
            assert_eq!(produce(operation, &[]), Err("LENGTH"));
            assert_eq!(produce(operation, &input[..input.len() - 1]), Err("LENGTH"));
            assert_eq!(produce(operation, &extra), Err("LENGTH"));
            for offset in [32, 32 + CELLS * 4, input.len() - 4] {
                let mut invalid = input.clone();
                invalid[offset..offset + 4].copy_from_slice(&(Q as u32).to_le_bytes());
                assert_eq!(produce(operation, &invalid), Err("WORK"));
            }
        }
    }

    #[test]
    fn unsupported_inputs_return_no_proof_and_never_substitute_a_generic_kernel() {
        let both_zero = vec![0; 32 + 2 * CELLS * 4];
        let mut both_nonzero = input(true);
        both_nonzero[32] = 1;
        for unsupported in [&both_zero, &both_nonzero] {
            assert!(produce(Operation::Generic, unsupported).is_ok());
            assert_eq!(
                produce(Operation::Reference, unsupported),
                Err("UNSUPPORTED")
            );
            assert_eq!(produce(Operation::Blocked, unsupported), Err("UNSUPPORTED"));
        }
        for zero_on_left in [true, false] {
            let mut higher_rank = input(zero_on_left);
            let nonzero_start = 32 + if zero_on_left { CELLS * 4 } else { 0 };
            higher_rank[nonzero_start + CELLS * 4 - 4] ^= 1;
            assert_eq!(
                produce(Operation::Reference, &higher_rank).unwrap(),
                produce(Operation::Generic, &higher_rank).unwrap()
            );
            assert_eq!(
                produce(Operation::Blocked, &higher_rank),
                Err("UNSUPPORTED")
            );
        }
        for operation in ["scalar", "", "blocked-zero", "structured-zero-reference"] {
            assert!(Operation::parse(operation).is_err());
        }
    }
}
