//! Test-only wire adapter for the unchanged, complete original Rust crate.
//! It calls only LaneAdmissionGate's public constructor and public operations.
//! CLEAR is an explicit drop/reconstruct extension; CLOSE actually drops it.
use std::io::{self, BufRead, Write};
use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

fn emit(out: &mut impl Write, words: [u64; 12]) {
    for word in words {
        for byte in word.to_le_bytes() {
            write!(out, "{byte:02x}").unwrap();
        }
    }
    writeln!(out).unwrap();
}

fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let magic = u64::from_le_bytes(*b"NLOR0001");
    for line in io::stdin().lock().lines() {
        let values: Vec<u64> = line
            .unwrap()
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(values.len() % 3, 0);
        let mut owner: Option<LaneAdmissionGate> = None;
        let mut config = (0usize, 0usize);
        for command in values.chunks_exact(3) {
            let (op, a, b) = (command[0], command[1], command[2]);
            let (mut outcome, mut id) = (0, 0);
            match op {
                0 => {
                    assert!(owner.is_none(), "NEW over a live owner");
                    config = (usize::try_from(a).unwrap(), usize::try_from(b).unwrap());
                    owner = Some(LaneAdmissionGate::new(config.0, config.1));
                }
                1 | 2 => {
                    assert_eq!(b, 0);
                    id = a;
                    let class = if op == 1 {
                        IngressClass::Normal
                    } else {
                        IngressClass::Critical
                    };
                    outcome = match owner.as_mut().unwrap().admit(id, class) {
                        AdmitOutcome::Accepted => 0,
                        AdmitOutcome::Duplicate => 1,
                        AdmitOutcome::Backpressured => 2,
                    };
                }
                3 => {
                    assert_eq!((a, b), (0, 0));
                    if let Some(popped) = owner.as_mut().unwrap().pop_ready() {
                        outcome = 1;
                        id = popped;
                    }
                }
                4 | 5 => assert_eq!((a, b), (0, 0)),
                6 => {
                    assert_eq!((a, b), (0, 0));
                    drop(owner.take().unwrap());
                    owner = Some(LaneAdmissionGate::new(config.0, config.1));
                }
                7 => {
                    assert_eq!((a, b), (0, 0));
                    drop(owner.take().unwrap());
                    emit(&mut out, [magic, op, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                    continue;
                }
                _ => panic!("unsupported test operation"),
            }
            let gate = owner.as_ref().unwrap();
            let (normal, critical, total) = gate.queued_counts();
            let qos = gate.qos_snapshot();
            assert_eq!(
                (normal, critical, total),
                (qos.normal_queued, qos.critical_queued, qos.total_queued)
            );
            emit(
                &mut out,
                [
                    magic,
                    op,
                    outcome,
                    id,
                    normal as u64,
                    critical as u64,
                    total as u64,
                    qos.normal_headroom as u64,
                    qos.critical_headroom as u64,
                    qos.total_headroom as u64,
                    u64::from(qos.fresh_normal_admissible),
                    u64::from(qos.fresh_critical_admissible),
                ],
            );
        }
        assert!(owner.is_none(), "test must explicitly close the owner");
    }
}
