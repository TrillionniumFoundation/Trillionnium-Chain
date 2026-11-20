//! Original public M05 QoS snapshot adapter.
//! The trnm_mempool library is built directly from its unchanged original lib.rs.
//! No queue-state or QoS calculation is reproduced in this adapter.
use std::io::{self, BufRead};
use trnm_mempool::{IngressClass, LaneAdmissionGate};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("original snapshot input read");
        let words: Vec<u64> = line.split_ascii_whitespace()
            .map(|word| word.parse::<u64>().expect("original snapshot integer"))
            .collect();
        assert!(words.len() >= 2 && (words.len() - 2) % 2 == 0,
                "capacity, reserve and operation/id pairs required");
        let total = usize::try_from(words[0]).expect("total usize");
        let reserve = usize::try_from(words[1]).expect("reserve usize");
        assert!(total <= 8 && reserve <= 10, "bounded real-queue qualifier");
        let mut gate = LaneAdmissionGate::new(total, reserve);
        for event in words[2..].chunks_exact(2) {
            match event[0] {
                0 => { let _ = gate.admit(event[1], IngressClass::Normal); },
                1 => { let _ = gate.admit(event[1], IngressClass::Critical); },
                2 => { let _ = gate.pop_ready(); },
                _ => panic!("unsupported queue event"),
            }
        }
        let snapshot = gate.qos_snapshot();
        println!("{} {} {} {} {} {} {}",
                 snapshot.normal_queued, snapshot.critical_queued,
                 snapshot.total_headroom, snapshot.normal_headroom,
                 snapshot.critical_headroom,
                 u8::from(snapshot.fresh_normal_admissible),
                 u8::from(snapshot.fresh_critical_admissible));
    }
}
