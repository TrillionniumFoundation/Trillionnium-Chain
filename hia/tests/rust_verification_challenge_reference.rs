// The unchanged original per-record Rust implementation is prefixed by the test.
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

struct Sha256(Vec<u8>);
impl Sha256 {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn update(&mut self, value: impl AsRef<[u8]>) {
        self.0.extend_from_slice(value.as_ref());
    }
    fn finalize(self) -> [u8; 32] {
        let mut child = Command::new("/usr/bin/sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&self.0).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let hex = std::str::from_utf8(&output.stdout[..64]).unwrap();
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }
}
fn array<const N: usize>(v: &[u8], at: usize) -> [u8; N] {
    v[at..at + N].try_into().unwrap()
}
fn number(v: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(array(v, at))
}
fn phase(raw: u8) -> ChallengePhaseV1 {
    use ChallengePhaseV1::*;
    match raw {
        0 => Opened,
        1 => EvidencePeriod,
        2 => ResponsePeriod,
        3 => DecisionPending,
        4 => Upheld,
        5 => Rejected,
        6 => AppealPending,
        7 => Final,
        _ => panic!("untyped phase"),
    }
}
fn outcome(raw: u8) -> Option<ChallengeFinalOutcomeV1> {
    use ChallengeFinalOutcomeV1::*;
    match raw {
        0 => None,
        1 => Some(Upheld),
        2 => Some(Rejected),
        3 => Some(Withdrawn),
        4 => Some(Expired),
        _ => panic!("untyped outcome"),
    }
}
fn decode(v: &[u8]) -> ChallengeRecordV1 {
    ChallengeRecordV1 {
        challenge_id: array(v, 0),
        result_id: array(v, 32),
        challenger: array(v, 64),
        phase: phase(v[136]),
        opened_height: number(v, 96),
        evidence_deadline: number(v, 104),
        response_deadline: number(v, 112),
        decision_deadline: number(v, 120),
        appeal_deadline: number(v, 128),
        appeal_used: v[137] != 0,
        final_outcome: outcome(v[138]),
        record_digest: array(v, 141),
        economic_authority: v[139] != 0,
        order_reorg: v[140] != 0,
    }
}
fn encode(v: &ChallengeRecordV1, out: &mut impl Write) -> io::Result<()> {
    out.write_all(&v.challenge_id)?;
    out.write_all(&v.result_id)?;
    out.write_all(&v.challenger)?;
    for height in [
        v.opened_height,
        v.evidence_deadline,
        v.response_deadline,
        v.decision_deadline,
        v.appeal_deadline,
    ] {
        out.write_all(&height.to_le_bytes())?;
    }
    let tag = match v.final_outcome {
        None => 0,
        Some(ChallengeFinalOutcomeV1::Upheld) => 1,
        Some(ChallengeFinalOutcomeV1::Rejected) => 2,
        Some(ChallengeFinalOutcomeV1::Withdrawn) => 3,
        Some(ChallengeFinalOutcomeV1::Expired) => 4,
    };
    out.write_all(&[
        v.phase as u8,
        u8::from(v.appeal_used),
        tag,
        u8::from(v.economic_authority),
        u8::from(v.order_reorg),
    ])?;
    out.write_all(&v.record_digest)
}
fn execute(frame: &[u8]) -> VerificationProfileResultV1<ChallengeRecordV1> {
    let op = frame[4];
    let h = number(frame, 8);
    let a = number(frame, 16);
    let data = &frame[24..];
    if op == 0 {
        return ChallengeRecordV1::open(
            array(data, 0),
            array(data, 32),
            array(data, 64),
            number(data, 96),
            a,
            number(data, 104),
            number(data, 112),
            number(data, 120),
            number(data, 128),
        );
    }
    let mut record = decode(data);
    let before = record.clone();
    let result = match op {
        1 => record.submit_evidence(h),
        2 => record.begin_response(h),
        3 => record.submit_response(h),
        4 => record.decide(h, outcome(frame[5]).unwrap()),
        5 => record.appeal(h, a),
        6 => record.finalize(h),
        7 => record.withdraw(),
        8 => record.expire(h),
        _ => panic!("untyped action"),
    };
    if result.is_err() {
        assert_eq!(before, record);
    }
    result.map(|()| record)
}
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    assert_eq!(bytes.len() % 197, 0);
    let mut out = io::stdout().lock();
    for frame in bytes.chunks_exact(197) {
        match execute(frame) {
            Ok(record) => {
                assert!(!record.economic_authority && !record.order_reorg);
                out.write_all(&[0])?;
                encode(&record, &mut out)?;
            }
            Err(err) => {
                use VerificationProfileErrorV1::*;
                let code = match err {
                    ZeroIdentifier => 1,
                    InvalidChallengePhase => 17,
                    ChallengeDeadlineMissed => 18,
                    AppealAlreadyUsed => 19,
                    _ => panic!("outside per-record scope: {err}"),
                };
                out.write_all(&[code])?;
            }
        }
    }
    Ok(())
}
