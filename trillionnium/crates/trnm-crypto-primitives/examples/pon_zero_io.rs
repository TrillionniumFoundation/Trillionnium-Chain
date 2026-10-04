//! Bounded offline complete-proof bridge. No mining or verification authority.
use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_work::{
    blocked_zero::BlockedZeroPreparedTask, structured::StructuredPreparedTask, *,
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
            "structured-zero-reference" => Ok(Self::Reference),
            "blocked-zero" => Ok(Self::Blocked),
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
    // Check canonical material before deciding zero-only support. No alternate
    // structured kernel or generic algorithm substitutes for an unsupported path.
    task_id(a, b).map_err(|_| "WORK")?;
    match operation {
        Operation::Generic => PreparedTask::new(a, b)
            .and_then(|task| task.prove(challenge))
            .map_err(|_| "WORK"),
        Operation::Reference => {
            if elements.iter().any(|value| *value != 0) {
                return Err("UNSUPPORTED");
            }
            StructuredPreparedTask::new(a, b)
                .map_err(|_| "WORK")?
                .ok_or("UNSUPPORTED")?
                .prove(challenge)
                .map_err(|_| "WORK")
        }
        Operation::Blocked => BlockedZeroPreparedTask::new(a, b)
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

    #[test]
    fn all_three_zero_operations_return_the_same_complete_certificate() {
        let mut input = vec![0; 32 + 2 * CELLS * 4];
        input[..32].fill(7);
        let reference = produce(Operation::Generic, &input).unwrap();
        assert_eq!(reference.len(), PROOF_BYTES);
        assert_eq!(produce(Operation::Reference, &input).unwrap(), reference);
        assert_eq!(produce(Operation::Blocked, &input).unwrap(), reference);
    }

    #[test]
    fn exact_input_extent_canonical_values_and_explicit_unsupported_are_checked() {
        let input = vec![0; 32 + 2 * CELLS * 4];
        let mut extra = input.clone();
        extra.push(0);
        for operation in [Operation::Generic, Operation::Reference, Operation::Blocked] {
            assert_eq!(produce(operation, &[]), Err("LENGTH"));
            assert_eq!(produce(operation, &input[..input.len() - 1]), Err("LENGTH"));
            assert_eq!(produce(operation, &extra), Err("LENGTH"));
            let mut invalid = input.clone();
            invalid[32..36].copy_from_slice(&(Q as u32).to_le_bytes());
            assert_eq!(produce(operation, &invalid), Err("WORK"));
        }
        let mut nonzero = input;
        nonzero[32] = 1;
        assert!(produce(Operation::Generic, &nonzero).is_ok());
        assert_eq!(produce(Operation::Reference, &nonzero), Err("UNSUPPORTED"));
        assert_eq!(produce(Operation::Blocked, &nonzero), Err("UNSUPPORTED"));
        assert!(Operation::parse("scalar").is_err());
        assert!(Operation::parse("").is_err());
    }
}
