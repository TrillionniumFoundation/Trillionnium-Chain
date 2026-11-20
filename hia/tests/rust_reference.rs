//! Test-only adapter around the retained, original Rust implementations.
//!
//! Build from the repository root:
//!   rustc --edition=2021 -O hia/tests/rust_reference.rs -o /tmp/trnm-hia-rust-reference
//!
//! One stdin line is `C INPUT_HEX OUTPUT_HEX` (closed round) or
//! `R INPUT_HEX OUTPUT_HEX` (replay). A single `-` denotes an empty buffer.
//! Each stdout line is `STATUS FULL_OUTPUT_HEX`; failures preserve the output.
//! The codecs below only translate the documented HIA test envelopes. Policy,
//! constructors, replay transitions and acknowledgements call the original
//! modules through their public interfaces. No copied policy implementation is
//! used as an oracle. Replay operation 4 compares the original state's derived
//! PartialEq: it is a prior-state fact, not a manufactured verified token.
//!
//! SourceOk deliberately supplies no source authentication or durable recovery
//! authority. It makes the original pure boundaries observable in tests only.
//! Passing these comparisons does not close network, signature, persistence or
//! production-authorization requirements. This executable is never a runtime
//! dependency of the HIA implementation.

#![allow(dead_code)]

#[path = "../../trillionnium/crates/trnm-transport/src/lib.rs"]
mod transport;
#[path = "../../trillionnium/crates/trnm-verification-profiles/src/closed_round.rs"]
mod closed_round;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io::{self, BufRead, Write};
use transport::{
    AuthenticatedPeerFrameV0, CandidateP2pAdmissionV0, IoDigest32V0,
    PeerAdmissionErrorV0, PeerFrameSourceV0, PeerFrameVerificationErrorV0,
    PeerRecoveryErrorV0, PeerReplayRecoverySourceV0, PeerReplayStateV0,
    PeerSessionIdentityV0,
};

const DESCRIPTION: &str = "TRNM-HIA-RUST-REFERENCE/1 original-modules SourceOk-test-only";

fn boundary(error: PeerAdmissionErrorV0) -> u32 {
    match error {
        PeerAdmissionErrorV0::ZeroDigest => 1,
        PeerAdmissionErrorV0::InvalidSession => 2,
        PeerAdmissionErrorV0::InvalidFrame => 3,
        PeerAdmissionErrorV0::InvalidRecoveryState => 4,
        PeerAdmissionErrorV0::ReplayOverflow => 5,
        PeerAdmissionErrorV0::WrongSession => 6,
        PeerAdmissionErrorV0::StaleNonce => 7,
        PeerAdmissionErrorV0::NonContiguousNonce => 8,
        PeerAdmissionErrorV0::PendingFrame => 9,
        PeerAdmissionErrorV0::ConflictingReplay => 10,
        PeerAdmissionErrorV0::StaleToken => 11,
        PeerAdmissionErrorV0::UnexpectedAcknowledgement => 12,
    }
}

fn recovery_error(error: PeerRecoveryErrorV0<Infallible>) -> u32 {
    match error {
        PeerRecoveryErrorV0::Boundary(error) => boundary(error),
        PeerRecoveryErrorV0::Source(never) => match never {},
    }
}

fn verification_error(error: PeerFrameVerificationErrorV0<Infallible>) -> u32 {
    match error {
        PeerFrameVerificationErrorV0::Boundary(error) => boundary(error),
        PeerFrameVerificationErrorV0::Source(never) => match never {},
    }
}

struct SourceOk;

impl PeerReplayRecoverySourceV0 for SourceOk {
    type Error = Infallible;

    fn verify_recovery(&mut self, _: &PeerReplayStateV0) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl PeerFrameSourceV0 for SourceOk {
    type Error = Infallible;

    fn verify_frame(
        &mut self,
        _: PeerReplayStateV0,
        _: &AuthenticatedPeerFrameV0,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn le64(raw: &[u8]) -> u64 {
    u64::from_le_bytes(raw.try_into().expect("fixed-width envelope field"))
}

fn decode_session(raw: &[u8]) -> Result<PeerSessionIdentityV0, u32> {
    let digest = |offset: usize| {
        IoDigest32V0::new(raw[offset..offset + 32].try_into().unwrap()).map_err(boundary)
    };
    PeerSessionIdentityV0::new(
        digest(0)?,
        digest(32)?,
        digest(64)?,
        digest(96)?,
        digest(128)?,
        le64(&raw[160..168]),
    )
    .map_err(boundary)
}

fn decode_frame(raw: &[u8]) -> Result<AuthenticatedPeerFrameV0, u32> {
    let session = decode_session(&raw[..168])?;
    let digest = IoDigest32V0::new(raw[176..208].try_into().unwrap()).map_err(boundary)?;
    let size = usize::try_from(le64(&raw[208..216]))
        .map_err(|_| boundary(PeerAdmissionErrorV0::InvalidFrame))?;
    AuthenticatedPeerFrameV0::new(session, le64(&raw[168..176]), digest, size)
        .map_err(boundary)
}

fn decode_state(raw: &[u8]) -> Result<PeerReplayStateV0, u32> {
    let session = decode_session(&raw[..168])?;
    let pending = match le64(&raw[176..184]) {
        0 => {
            if raw[184..400].iter().any(|byte| *byte != 0) {
                return Err(15); // noncanonical absent-frame padding
            }
            None
        }
        1 => Some(decode_frame(&raw[184..400])?),
        _ => return Err(15),
    };
    PeerReplayStateV0::new(session, le64(&raw[168..176]), pending).map_err(boundary)
}

fn encode_session(session: PeerSessionIdentityV0, out: &mut Vec<u8>) {
    for digest in [
        session.chain_id(),
        session.protocol_digest(),
        session.peer_id(),
        session.session_id(),
        session.profile_digest(),
    ] {
        out.extend_from_slice(&digest.bytes());
    }
    out.extend_from_slice(&session.generation().to_le_bytes());
}

fn encode_state(state: PeerReplayStateV0) -> Vec<u8> {
    let mut out = Vec::with_capacity(400);
    encode_session(state.session(), &mut out);
    out.extend_from_slice(&state.highest_acknowledged_nonce().to_le_bytes());
    match state.pending() {
        None => out.resize(400, 0),
        Some(frame) => {
            out.extend_from_slice(&1_u64.to_le_bytes());
            encode_session(frame.session(), &mut out);
            out.extend_from_slice(&frame.replay_nonce().to_le_bytes());
            out.extend_from_slice(&frame.payload_digest().bytes());
            out.extend_from_slice(&(frame.payload_bytes() as u64).to_le_bytes());
        }
    }
    out
}

fn replay(raw: &[u8], out: &mut [u8]) -> Result<(), u32> {
    if raw.len() < 8 || out.len() != 400 {
        return Err(13);
    }
    if &raw[..5] != b"TRP1\x01" || raw[5] > 4 || raw[6..8] != [0, 0] {
        return Err(14);
    }
    let operation = raw[5];
    let expected = match operation {
        0 => 408,
        4 => 808,
        _ => 624,
    };
    if raw.len() != expected {
        return Err(13);
    }
    let current = decode_state(&raw[8..408])?;
    let mut source = SourceOk;
    let mut admission = CandidateP2pAdmissionV0::recover_verified(current, &mut source)
        .map_err(recovery_error)?;
    match operation {
        0 => {}
        4 => {
            let prior = decode_state(&raw[408..808])?;
            // This calls the original type's derived equality, matching the
            // prior-state fact offered by HIA, with no authority-token claim.
            if current != prior {
                return Err(boundary(PeerAdmissionErrorV0::StaleToken));
            }
        }
        _ => {
            let frame = decode_frame(&raw[408..624])?;
            if operation == 2 {
                admission.acknowledge(frame).map_err(boundary)?;
            } else {
                let verified = admission
                    .verify_frame(frame, &mut source)
                    .map_err(verification_error)?;
                if operation == 3 {
                    admission.admit_verified(verified).map_err(boundary)?;
                } else {
                    // Verify-only is the original boundary observation. No
                    // state transition or reusable token escapes the fixture.
                    drop(verified);
                }
            }
        }
    }
    out.copy_from_slice(&encode_state(admission.recovery_state()));
    Ok(())
}

struct Cursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], u32> {
        let end = self.offset.checked_add(size).ok_or(100_u32)?;
        let value = self.raw.get(self.offset..end).ok_or(100_u32)?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, u32> {
        Ok(le64(self.take(8)?))
    }

    fn name(&mut self) -> Result<String, u32> {
        let size = self.u32()? as usize;
        std::str::from_utf8(self.take(size)?)
            .map(str::to_owned)
            .map_err(|_| 101)
    }
}

fn closed(raw: &[u8], out: &mut [u8]) -> Result<(), u32> {
    if raw.len() < 20 {
        return Err(100);
    }
    if raw.len() > 1_048_576 {
        return Err(103);
    }
    if &raw[..4] != b"CRD1" {
        return Err(100);
    }
    let mut cursor = Cursor { raw, offset: 4 };
    let maximum = cursor.u64()?;
    let roster_count = cursor.u32()?;
    let vote_count = cursor.u32()?;
    let minimum = u64::from(roster_count) * 4 + u64::from(vote_count) * 12;
    if minimum > (raw.len() - 20) as u64 {
        return Err(100);
    }
    let mut eligible = BTreeSet::new();
    let mut last: Option<String> = None;
    for _ in 0..roster_count {
        let name = cursor.name()?;
        if last.as_ref().is_some_and(|previous| previous >= &name) {
            return Err(102);
        }
        last = Some(name.clone());
        eligible.insert(name);
    }
    let mut votes = BTreeMap::new();
    last = None;
    for _ in 0..vote_count {
        let name = cursor.name()?;
        if last.as_ref().is_some_and(|previous| previous >= &name) {
            return Err(102);
        }
        last = Some(name.clone());
        let score = cursor.u64()?;
        votes.insert(name, score);
    }
    if cursor.offset != raw.len() {
        return Err(100);
    }
    match closed_round::complete_score(&eligible, &votes, maximum) {
        Ok(Some(score)) => {
            if out.len() < 8 {
                return Err(104);
            }
            out[..8].copy_from_slice(&score.to_le_bytes());
            Ok(())
        }
        Ok(None) => Err(1),
        Err("EVALUATOR_ROSTER") => Err(2),
        Err("AUTHORITY") => Err(3),
        Err("EVIDENCE") => Err(4),
        Err(other) => panic!("unmapped original closed-round error: {other}"),
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    fn nibble(byte: u8) -> Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("hex must be lowercase ASCII".into()),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn encode_hex(raw: &[u8]) -> String {
    if raw.is_empty() {
        return "-".into();
    }
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(raw.len() * 2);
    for &byte in raw {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 15)] as char);
    }
    text
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--describe"] {
        println!("{DESCRIPTION}");
        return Ok(());
    }
    if !args.is_empty() {
        return Err("only --describe or stdin requests are supported".into());
    }
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for (number, line) in stdin.lock().lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 3 {
            return Err(format!("line {}: expected kind, input and output", number + 1));
        }
        let raw = decode_hex(fields[1])?;
        let mut output = decode_hex(fields[2])?;
        let status = match fields[0] {
            "C" => closed(&raw, &mut output),
            "R" => replay(&raw, &mut output),
            _ => return Err(format!("line {}: unknown kind", number + 1)),
        };
        writeln!(stdout, "{} {}", status.err().unwrap_or(0), encode_hex(&output))
            .map_err(|error| error.to_string())?;
    }
    stdout.flush().map_err(|error| error.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Rust reference fixture failed: {error}");
        std::process::exit(2);
    }
}
