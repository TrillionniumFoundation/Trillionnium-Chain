//! Test framing for the unchanged original transcript module's nine public APIs.
use std::io::{self, BufRead, Write};
use trnm_types::{
    relay_auth_envelope_hash, transcript_segment_proof, transcript_segment_proofs,
    transcript_segment_root, transcript_segment_tree, verify_proof, MerkleDirection,
    RelayAuthEnvelope, TranscriptError, TranscriptProof,
};

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn record(tag: u64, x: u64, y: u64, z: u64, payload: Vec<u8>) -> Vec<u8> {
    let mut out = b"TRNMTR1\0".to_vec();
    for value in [tag, x, y, z, payload.len() as u64] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&payload);
    out
}

fn error(value: TranscriptError) -> Vec<u8> {
    let (tag, x, y, z) = match value {
        TranscriptError::EmptySegment => (1, 0, 0, 0),
        TranscriptError::EmptyTargets => (2, 0, 0, 0),
        TranscriptError::InvalidRange { start_seq, end_seq } => (3, start_seq, end_seq, 0),
        TranscriptError::MissingSequence { expected_seq } => (4, expected_seq, 0, 0),
        TranscriptError::OrderMismatch {
            expected_seq,
            got_seq,
        } => (5, expected_seq, got_seq, 0),
        TranscriptError::TargetOutOfRange {
            target_seq,
            start_seq,
            end_seq,
        } => (6, target_seq, start_seq, end_seq),
    };
    record(tag, x, y, z, Vec::new())
}

fn proof_bytes(proof: &TranscriptProof) -> Vec<u8> {
    let mut out = proof.leaf.to_vec();
    out.extend_from_slice(&(proof.path.len() as u64).to_le_bytes());
    out.extend_from_slice(&(proof.directions.len() as u64).to_le_bytes());
    for node in &proof.path {
        out.extend_from_slice(node);
    }
    for direction in &proof.directions {
        out.push(match direction {
            MerkleDirection::Left => 0,
            MerkleDirection::Right => 1,
        });
    }
    out
}

fn envelopes(input: &[u8]) -> (Vec<RelayAuthEnvelope>, usize) {
    let mut at = 80;
    let mut values = Vec::new();
    for _ in 0..word(input, 40) {
        let size = usize::try_from(word(input, at)).unwrap();
        let seq = word(input, at + 8);
        let timestamp_ms = u128::from_le_bytes(input[at + 16..at + 32].try_into().unwrap());
        let mut cursor = at + 120;
        let mut fields = Vec::new();
        for offset in (32..112).step_by(8) {
            let len = usize::try_from(word(input, at + offset)).unwrap();
            fields.push(String::from_utf8(input[cursor..cursor + len].to_vec()).unwrap());
            cursor += len;
        }
        let [chain_id, msg_type, version, task_id, session_id, from, to, nonce, payload_hash, sig]:
            [String; 10] = fields.try_into().unwrap();
        let payload_len = usize::try_from(word(input, at + 112)).unwrap();
        let payload = input[cursor..cursor + payload_len].to_vec();
        assert_eq!(cursor + payload_len, at + size);
        values.push(RelayAuthEnvelope {
            version,
            chain_id,
            task_id,
            session_id,
            seq,
            timestamp_ms,
            msg_type,
            from,
            to,
            nonce,
            payload,
            payload_hash,
            sig,
        });
        at += size;
    }
    (values, at)
}

fn run(input: &[u8]) -> Vec<u8> {
    assert!(input.len() >= 80);
    assert_eq!(&input[..8], b"TRNMTP1\0");
    let op = word(input, 8);
    if op == 5 {
        let root = input[80..112].try_into().unwrap();
        let leaf = input[112..144].try_into().unwrap();
        let path_count = usize::try_from(word(input, 56)).unwrap();
        let direction_count = usize::try_from(word(input, 64)).unwrap();
        let path = (0..path_count)
            .map(|j| input[144 + j * 32..176 + j * 32].try_into().unwrap())
            .collect();
        let at = 144 + path_count * 32;
        let directions = input[at..at + direction_count]
            .iter()
            .map(|byte| match byte {
                0 => MerkleDirection::Left,
                1 => MerkleDirection::Right,
                _ => panic!("invalid direction in typed reference input"),
            })
            .collect();
        assert_eq!(at + direction_count, input.len());
        let value = verify_proof(
            &root,
            &TranscriptProof {
                leaf,
                path,
                directions,
            },
        );
        return record(0, u64::from(value), 0, 0, Vec::new());
    }

    let (values, at) = envelopes(input);
    let targets: Vec<u64> = (0..word(input, 48))
        .map(|j| word(input, at + j as usize * 8))
        .collect();
    assert_eq!(at + targets.len() * 8, input.len());
    let start = word(input, 16);
    let end = word(input, 24);
    let target = word(input, 32);
    match op {
        0 => {
            assert_eq!(values.len(), 1);
            let hash = relay_auth_envelope_hash(&values[0]);
            assert_eq!(hash, values[0].envelope_hash());
            record(0, 0, 0, 0, hash.to_vec())
        }
        1 => match transcript_segment_root(&values, start, end) {
            Ok(root) => record(0, 0, 0, 0, root.to_vec()),
            Err(value) => error(value),
        },
        2 => match transcript_segment_proof(&values, start, end, target) {
            Ok((root, proof)) => {
                let mut payload = root.to_vec();
                payload.extend_from_slice(&proof_bytes(&proof));
                record(0, 0, 0, 0, payload)
            }
            Err(value) => error(value),
        },
        3 => match transcript_segment_proofs(&values, start, end, &targets) {
            Ok((root, proofs)) => {
                let mut payload = root.to_vec();
                payload.extend_from_slice(&(proofs.len() as u64).to_le_bytes());
                for proof in proofs {
                    payload.extend_from_slice(&proof_bytes(&proof));
                }
                record(0, 0, 0, 0, payload)
            }
            Err(value) => error(value),
        },
        4 | 6 | 7 | 8 => match transcript_segment_tree(&values, start, end) {
            Err(value) => error(value),
            Ok(tree) => match op {
                4 => record(0, tree.leaf_count() as u64, 0, 0, tree.root().to_vec()),
                6 => record(0, 0, 0, 0, tree.root().to_vec()),
                7 => record(0, tree.leaf_count() as u64, 0, 0, Vec::new()),
                8 => match tree.proof(usize::try_from(target).unwrap()) {
                    Some(proof) => record(0, 1, 0, 0, proof_bytes(&proof)),
                    None => record(0, 0, 0, 0, Vec::new()),
                },
                _ => unreachable!(),
            },
        },
        _ => panic!("unsupported test operation"),
    }
}

fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        assert_eq!(line.len() % 2, 0);
        let input: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect();
        for byte in run(&input) {
            write!(out, "{byte:02x}").unwrap();
        }
        writeln!(out).unwrap();
    }
}
