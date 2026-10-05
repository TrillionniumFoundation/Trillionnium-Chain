//! Shared native regression and libFuzzer checks. Raw untrusted certificates stay
//! raw; a second, bounded mutation of the retained proof reaches late stages
//! without asking the fuzzer to rediscover a cryptographic transcript digest.
use trnm_crypto_primitives::pon_work::{
    self, Hash, VerificationError, VerificationProgress, CELLS, PROOF_BYTES, Q,
};
use trnm_protocol::pon_wire::Header;

#[derive(Debug, PartialEq, Eq)]
pub struct Success {
    challenge: Hash,
    task: Hash,
    ticket: Hash,
    product: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub verdict: Result<Success, VerificationError<usize>>,
    pub points: Vec<VerificationProgress>,
}

#[derive(Clone, Copy)]
enum Cancellation {
    None,
    Index(usize),
    BeforeVerifiedWork,
}

fn statement_task(bytes: &[u8]) -> Hash {
    if bytes.len() != PROOF_BYTES {
        return [0; 32];
    }
    let matrices: Vec<u32> = bytes[4..4 + 2 * CELLS * 4]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte word")))
        .collect();
    pon_work::task_id(&matrices[..CELLS], &matrices[CELLS..]).unwrap_or([0; 32])
}

fn challenge() -> Hash {
    Header::decode(include_bytes!(
        "../../../../formal/pon-nakamoto-v1/vectors/header.bin"
    ))
    .expect("retained canonical header vector")
    .challenge()
}

fn observe(
    kernel: usize,
    challenge: Hash,
    task: Hash,
    target: Hash,
    bytes: &[u8],
    cancellation: Cancellation,
) -> Observation {
    let mut points = Vec::new();
    let mut progress = |point| {
        let index = points.len();
        points.push(point);
        let cancel = match cancellation {
            Cancellation::None => false,
            Cancellation::Index(cut) => index == cut,
            Cancellation::BeforeVerifiedWork => point == VerificationProgress::BeforeVerifiedWork,
        };
        if cancel {
            Err(index)
        } else {
            Ok(())
        }
    };
    let verdict = match kernel {
        0 => pon_work::verify_with_progress(challenge, task, target, bytes, &mut progress),
        1 => {
            pon_work::verify_reference_with_progress(challenge, task, target, bytes, &mut progress)
        }
        2 => pon_work::verify_limb_with_progress(challenge, task, target, bytes, &mut progress),
        _ => unreachable!("three explicit verification kernels"),
    }
    .map(|work| Success {
        challenge: work.challenge(),
        task: work.task(),
        ticket: work.ticket(),
        product: work.product().to_vec(),
    });
    Observation { verdict, points }
}

fn check_statement(
    challenge: Hash,
    task: Hash,
    target: Hash,
    bytes: &[u8],
    cancellation: Cancellation,
) -> Observation {
    let reference = observe(1, challenge, task, target, bytes, cancellation);
    for kernel in [0, 2] {
        let actual = observe(kernel, challenge, task, target, bytes, cancellation);
        assert_eq!(actual, reference, "verdict, exact output or progress differs");
    }
    reference
}

pub fn check_raw(bytes: &[u8]) -> Observation {
    check_statement(
        challenge(),
        statement_task(bytes),
        [255; 32],
        bytes,
        Cancellation::None,
    )
}

fn previous_target(mut target: Hash) -> Hash {
    for byte in target.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            return target;
        }
        *byte = 255;
    }
    [0; 32] // the zero target is explicitly invalid, never wrap to maximum
}

pub fn check_structured(control: &[u8]) -> Observation {
    let mut proof = include_bytes!("../../../../formal/pon-nakamoto-v1/vectors/work.bin").to_vec();
    assert_eq!(proof.len(), PROOF_BYTES);
    let mut challenge = challenge();
    let mut task = statement_task(&proof);
    let mut target = [255; 32];
    let mut cancellation = Cancellation::None;
    let byte = |index: usize| control.get(index).copied().unwrap_or(0);
    let selector = u16::from_le_bytes([byte(1), byte(2)]) as usize;
    match byte(0) % 8 {
        0 => {
            target = pon_work::hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]);
        }
        1 => {
            target = previous_target(pon_work::hash(
                b"ticket",
                &[&challenge, &proof[PROOF_BYTES - 32..]],
            ));
        }
        2 => task[selector % 32] ^= byte(3) | 1,
        3 => challenge[selector % 32] ^= byte(3) | 1,
        4 => {
            let offset = 4 + 8 * CELLS + 4 * (selector % CELLS);
            let old = u32::from_le_bytes(proof[offset..offset + 4].try_into().unwrap());
            let changed = ((u128::from(old) + 1) % Q) as u32;
            proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
        }
        5 => proof[PROOF_BYTES - 32 + selector % 32] ^= byte(3) | 1,
        6 => cancellation = Cancellation::Index(selector % 2048),
        7 => cancellation = Cancellation::BeforeVerifiedWork,
        _ => unreachable!("modulo eight"),
    }
    check_statement(challenge, task, target, &proof, cancellation)
}
