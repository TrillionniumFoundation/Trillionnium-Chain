use crate::{Hash32, RelayAuthEnvelope};
use sha2::{Digest, Sha256};

use super::TranscriptError;

pub fn relay_auth_envelope_hash(env: &RelayAuthEnvelope) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(RelayAuthEnvelope::SIGNING_DOMAIN_V1.as_bytes());
    hasher.update(b"|");
    hasher.update(env.chain_id.as_bytes());
    hasher.update(b"|");
    hasher.update(env.msg_type.as_bytes());
    hasher.update(b"|");
    hasher.update(env.version.as_bytes());
    hasher.update(b"|");
    hasher.update(env.task_id.as_bytes());
    hasher.update(b"|");
    hasher.update(env.session_id.as_bytes());
    hasher.update(b"|");
    hasher.update(env.seq.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(env.timestamp_ms.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(env.from.as_bytes());
    hasher.update(b"|");
    hasher.update(env.to.as_bytes());
    hasher.update(b"|");
    hasher.update(env.nonce.as_bytes());
    hasher.update(b"|");
    hasher.update(env.payload_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(env.sig.as_bytes());
    hasher.finalize().into()
}

pub(super) fn collect_segment_hashes(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
) -> Result<Vec<Hash32>, TranscriptError> {
    if start_seq > end_seq {
        return Err(TranscriptError::InvalidRange { start_seq, end_seq });
    }

    let mut expected_seq = start_seq;
    let mut hashes = Vec::new();

    for env in envelopes {
        if env.seq < start_seq {
            continue;
        }
        if env.seq > end_seq {
            break;
        }
        if env.seq != expected_seq {
            return Err(TranscriptError::OrderMismatch {
                expected_seq,
                got_seq: env.seq,
            });
        }
        hashes.push(relay_auth_envelope_hash(env));
        expected_seq = expected_seq.saturating_add(1);
    }

    if hashes.is_empty() {
        return Err(TranscriptError::EmptySegment);
    }

    if expected_seq <= end_seq {
        return Err(TranscriptError::MissingSequence { expected_seq });
    }

    Ok(hashes)
}
