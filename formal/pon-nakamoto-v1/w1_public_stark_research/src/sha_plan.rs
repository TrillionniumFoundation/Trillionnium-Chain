//! Canonical W1 hash messages. Verifier construction performs no SHA operation.

use core::fmt;

use sha2::{Digest, Sha256};

pub const HEADER_BYTES: usize = 318;
pub const MATRIX_BYTES: usize = 64 * 64 * 4;
pub const INPUT_BYTES: usize = HEADER_BYTES + 4 + 3 * MATRIX_BYTES + 32;
pub const PREFIX_BYTES: usize = 8 * MATRIX_BYTES;
pub const NOISE_LABELS: usize = 4;
pub const NOISE_COUNTERS: usize = 128;
pub const HASH_MESSAGES: usize = 7 + NOISE_LABELS * NOISE_COUNTERS;
pub const REAL_COMPRESSIONS: usize = 4114;
pub const PADDED_COMPRESSIONS: usize = 8192;
pub const HASH_DOMAIN: &[u8] = b"TRNM-PON1\0";
pub const TRACE_DOMAIN: &[u8] = b"TRNM-PON-TRACE1\0";

pub type Hash = [u8; 32];

/// These are untrusted public claims, not host-certified SHA outputs.
/// `ShaPlan::from_w1` wires each claim to a constrained final compression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashClaims {
    pub challenge: Hash,
    /// All 128 original counters per label, including those after the native
    /// sampler has obtained its 512th accepted word. Arithmetic constraints
    /// must select the first 512 accepted words, in the original order.
    pub noise: [[Hash; NOISE_COUNTERS]; NOISE_LABELS],
    pub ticket: Hash,
    pub work_id: Hash,
}

#[derive(Clone, Copy)]
pub struct W1ShaPublic<'a> {
    pub raw: &'a [u8],
    pub prefix: &'a [u8],
    pub expected_header: &'a [u8; HEADER_BYTES],
    pub expected_artifacts: &'a [u8; 64],
    pub claims: &'a HashClaims,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    InputLength,
    PrefixLength,
    HeaderVersion,
    ProofMagic,
    IndependentHeader,
    EmptyMessages,
    TooManyMessages,
    TooManyCompressions,
    MessageTooLong,
    LengthOverflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PlanError {}

/// One complete SHA-256 message and its claimed digest. Message bytes include
/// the native W1 framing but exclude SHA padding; padding is added canonically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashMessage {
    pub name: String,
    pub bytes: Vec<u8>,
    pub expected_digest: Hash,
}

#[derive(Clone, Debug)]
pub struct ShaPlan {
    messages: Vec<HashMessage>,
    real_compressions: usize,
    padded_compressions: usize,
}

/// Exact original domain codec: tag length is LE-u16; each part length LE-u32.
pub fn frame(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    assert!(tag.len() <= u16::MAX as usize);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HASH_DOMAIN);
    bytes.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    bytes.extend_from_slice(tag);
    for part in parts {
        assert!(part.len() <= u32::MAX as usize);
        bytes.extend_from_slice(&(part.len() as u32).to_le_bytes());
        bytes.extend_from_slice(part);
    }
    bytes
}

/// SHA-256 padding: 0x80, zero bytes, then the original bit length as BE-u64.
/// The bound covers every W1 message and prevents unbounded allocation.
pub fn padded_blocks(bytes: &[u8]) -> Result<Vec<[u8; 64]>, PlanError> {
    if bytes.len() > TRACE_DOMAIN.len() + 32 + PREFIX_BYTES {
        return Err(PlanError::MessageTooLong);
    }
    let bit_len = u64::try_from(bytes.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(PlanError::LengthOverflow)?;
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    Ok(padded
        .chunks_exact(64)
        .map(|block| block.try_into().expect("exact SHA block"))
        .collect())
}

impl ShaPlan {
    /// Build the only W1 production-of-research-verification plan. This method
    /// does not hash, derive factors, accept a digest based on host computation,
    /// or inspect a proof-supplied verification key.
    pub fn from_w1(input: W1ShaPublic<'_>) -> Result<Self, PlanError> {
        if input.raw.len() != INPUT_BYTES {
            return Err(PlanError::InputLength);
        }
        if input.prefix.len() != PREFIX_BYTES {
            return Err(PlanError::PrefixLength);
        }
        if &input.raw[..6] != b"PNH1\x01\x00" {
            return Err(PlanError::HeaderVersion);
        }
        if &input.raw[HEADER_BYTES..HEADER_BYTES + 4] != b"PNW1" {
            return Err(PlanError::ProofMagic);
        }
        if input.raw[..HEADER_BYTES] != input.expected_header[..] {
            return Err(PlanError::IndependentHeader);
        }
        let a = &input.raw[HEADER_BYTES + 4..HEADER_BYTES + 4 + MATRIX_BYTES];
        let b = &input.raw[HEADER_BYTES + 4 + MATRIX_BYTES..HEADER_BYTES + 4 + 2 * MATRIX_BYTES];
        let trace: Hash = input.raw[INPUT_BYTES - 32..]
            .try_into()
            .expect("fixed trace length");
        let mut messages = Vec::with_capacity(HASH_MESSAGES);
        let mut push = |name: String, bytes: Vec<u8>, expected_digest: Hash| {
            messages.push(HashMessage {
                name,
                bytes,
                expected_digest,
            });
        };
        push(
            "artifact-A".into(),
            frame(b"artifact", &[a]),
            input.expected_artifacts[..32].try_into().unwrap(),
        );
        push(
            "qualified-task-input-B".into(),
            frame(b"qualified-task-input-v1", &[b]),
            input.expected_artifacts[32..].try_into().unwrap(),
        );
        push(
            "task".into(),
            frame(b"task", &[a, b]),
            input.expected_header[278..310].try_into().unwrap(),
        );
        push(
            "challenge".into(),
            frame(b"challenge", &[input.expected_header]),
            input.claims.challenge,
        );
        for label in 0..NOISE_LABELS {
            for counter in 0..NOISE_COUNTERS {
                push(
                    format!("noise-{label}-{counter:03}"),
                    frame(
                        b"noise",
                        &[
                            &input.claims.challenge,
                            &[label as u8],
                            &(counter as u32).to_le_bytes(),
                        ],
                    ),
                    input.claims.noise[label][counter],
                );
            }
        }
        let mut trace_message = Vec::with_capacity(TRACE_DOMAIN.len() + 32 + PREFIX_BYTES);
        trace_message.extend_from_slice(TRACE_DOMAIN);
        trace_message.extend_from_slice(&input.claims.challenge);
        trace_message.extend_from_slice(input.prefix);
        push("trace".into(), trace_message, trace);
        push(
            "ticket".into(),
            frame(b"ticket", &[&input.claims.challenge, &trace]),
            input.claims.ticket,
        );
        push(
            "block".into(),
            frame(b"block", &[input.expected_header, &trace]),
            input.claims.work_id,
        );
        let plan = Self::for_public_messages(messages)?;
        assert_eq!(plan.real_compressions, REAL_COMPRESSIONS);
        assert_eq!(plan.padded_compressions, PADDED_COMPRESSIONS);
        Ok(plan)
    }

    /// General public-message constructor for component tests and reuse.
    /// A top-level W1 verifier must call `from_w1`, not deserialize arbitrary
    /// messages or accept this plan as a prover-selected W1 statement.
    pub fn for_public_messages(messages: Vec<HashMessage>) -> Result<Self, PlanError> {
        if messages.is_empty() {
            return Err(PlanError::EmptyMessages);
        }
        if messages.len() > HASH_MESSAGES {
            return Err(PlanError::TooManyMessages);
        }
        let mut real_compressions = 0usize;
        for message in &messages {
            real_compressions = real_compressions
                .checked_add(padded_blocks(&message.bytes)?.len())
                .ok_or(PlanError::LengthOverflow)?;
            if real_compressions > REAL_COMPRESSIONS {
                return Err(PlanError::TooManyCompressions);
            }
        }
        let padded_compressions = real_compressions
            .checked_next_power_of_two()
            .ok_or(PlanError::LengthOverflow)?;
        Ok(Self {
            messages,
            real_compressions,
            padded_compressions,
        })
    }

    pub fn messages(&self) -> &[HashMessage] {
        &self.messages
    }

    pub fn real_compressions(&self) -> usize {
        self.real_compressions
    }

    pub fn padded_compressions(&self) -> usize {
        self.padded_compressions
    }
}

/// Prover-only helper. Its outputs are merely claims until the SHA AIR proof
/// verifies. Deliberately does not validate a trace digest or matrix product.
pub fn honest_claims(raw: &[u8]) -> Result<HashClaims, PlanError> {
    if raw.len() != INPUT_BYTES {
        return Err(PlanError::InputLength);
    }
    let hash = |message: Vec<u8>| -> Hash { Sha256::digest(message).into() };
    let challenge = hash(frame(b"challenge", &[&raw[..HEADER_BYTES]]));
    let noise = core::array::from_fn(|label| {
        core::array::from_fn(|counter| {
            hash(frame(
                b"noise",
                &[&challenge, &[label as u8], &(counter as u32).to_le_bytes()],
            ))
        })
    });
    let trace = &raw[INPUT_BYTES - 32..];
    Ok(HashClaims {
        challenge,
        noise,
        ticket: hash(frame(b"ticket", &[&challenge, trace])),
        work_id: hash(frame(b"block", &[&raw[..HEADER_BYTES], trace])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_padding_boundaries() {
        for (length, expected_blocks) in [(0, 1), (55, 1), (56, 2), (63, 2), (64, 2), (375, 6)] {
            let bytes = vec![0x42; length];
            let blocks = padded_blocks(&bytes).unwrap();
            assert_eq!(blocks.len(), expected_blocks);
            let flat: Vec<u8> = blocks.into_iter().flatten().collect();
            assert_eq!(&flat[..length], &bytes);
            assert_eq!(flat[length], 0x80);
            assert!(flat[length + 1..flat.len() - 8].iter().all(|&x| x == 0));
            assert_eq!(&flat[flat.len() - 8..], &(8 * length as u64).to_be_bytes());
        }
    }

    #[test]
    fn framing_has_original_lengths_and_endianness() {
        let bytes = frame(b"noise", &[&[9; 32], &[3], &127u32.to_le_bytes()]);
        assert_eq!(bytes.len(), 66);
        assert_eq!(&bytes[..10], b"TRNM-PON1\0");
        assert_eq!(&bytes[10..12], &5u16.to_le_bytes());
        assert_eq!(&bytes[17..21], &32u32.to_le_bytes());
        assert_eq!(&bytes[53..57], &1u32.to_le_bytes());
        assert_eq!(bytes[57], 3);
        assert_eq!(&bytes[58..62], &4u32.to_le_bytes());
        assert_eq!(&bytes[62..66], &127u32.to_le_bytes());
    }

    #[test]
    fn complete_plan_binds_independent_outputs_without_host_hash_checks() {
        // These claims are deliberately not true hashes. Constructing the
        // public plan must not substitute host hash acceptance for the AIR.
        let mut raw = vec![0u8; INPUT_BYTES];
        raw[..6].copy_from_slice(b"PNH1\x01\x00");
        raw[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(b"PNW1");
        let expected_header: [u8; HEADER_BYTES] = raw[..HEADER_BYTES].try_into().unwrap();
        let expected_artifacts = [11u8; 64];
        let prefix = vec![13u8; PREFIX_BYTES];
        let claims = HashClaims {
            challenge: [17; 32],
            noise: [[[19; 32]; NOISE_COUNTERS]; NOISE_LABELS],
            ticket: [23; 32],
            work_id: [29; 32],
        };
        let input = W1ShaPublic {
            raw: &raw,
            prefix: &prefix,
            expected_header: &expected_header,
            expected_artifacts: &expected_artifacts,
            claims: &claims,
        };
        let plan = ShaPlan::from_w1(input).unwrap();
        assert_eq!(plan.messages().len(), HASH_MESSAGES);
        assert_eq!(plan.real_compressions(), REAL_COMPRESSIONS);
        assert_eq!(plan.padded_compressions(), PADDED_COMPRESSIONS);
        assert_eq!(plan.messages()[0].expected_digest, [11; 32]);
        assert_eq!(plan.messages()[1].expected_digest, [11; 32]);
        assert_eq!(plan.messages()[3].expected_digest, claims.challenge);
        let trace = &plan.messages()[HASH_MESSAGES - 3];
        assert_eq!(trace.name, "trace");
        assert_eq!(&trace.bytes[..TRACE_DOMAIN.len()], TRACE_DOMAIN);
        assert_eq!(
            &trace.bytes[TRACE_DOMAIN.len()..TRACE_DOMAIN.len() + 32],
            &claims.challenge
        );
        assert_eq!(&trace.bytes[TRACE_DOMAIN.len() + 32..], &prefix);
        assert_eq!(padded_blocks(&trace.bytes).unwrap().len(), 2049);
        let block = &plan.messages()[HASH_MESSAGES - 1];
        assert_eq!(block.name, "block");
        assert_eq!(block.bytes.len(), 375);
        assert_eq!(padded_blocks(&block.bytes).unwrap().len(), 6);

        let mut mismatched_header = expected_header;
        mismatched_header[42] ^= 1;
        let mismatch = W1ShaPublic {
            expected_header: &mismatched_header,
            ..input
        };
        assert!(matches!(
            ShaPlan::from_w1(mismatch),
            Err(PlanError::IndependentHeader)
        ));
    }
}
