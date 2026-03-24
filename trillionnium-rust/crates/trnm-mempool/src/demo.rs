use crate::AdmissionGate;

pub fn run() {
    let mut gate = AdmissionGate::new(1024);
    let _ = gate.admit(1);
    println!("mempool gate ready (queued={})", gate.queued());
}
