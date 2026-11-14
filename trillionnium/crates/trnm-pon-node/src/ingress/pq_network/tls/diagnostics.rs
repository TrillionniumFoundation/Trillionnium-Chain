//! Bounded local refusal observations. These never authorize dispatch or retry.
use super::*;
use crate::error::ErrorKind;
use std::{cell::Cell, io::Write, sync::atomic::AtomicUsize};

const MAX_REFUSAL_RECORDS: usize = 16;

#[derive(Clone, Copy)]
pub(super) struct Refusal {
    kind: ErrorKind,
    code: Option<&'static str>,
}
impl Refusal {
    pub(super) fn from_error(error: &Error) -> Self {
        // Typed codes retain their origin. Legacy witness strings are mapped
        // only to fixed diagnostic labels: no admission decision reads them.
        let code =
            error
                .code()
                .map(ErrorCode::as_str)
                .or_else(|| match error.to_string().as_str() {
                    "PQ_WITNESS_DEADLINE" => Some("PQ_WITNESS_DEADLINE"),
                    "PQ_WITNESS_EOF" => Some("PQ_WITNESS_EOF"),
                    "PQ_WITNESS_UNAVAILABLE" => Some("PQ_WITNESS_UNAVAILABLE"),
                    "PQ_WITNESS_BUSY" => Some("PQ_WITNESS_BUSY"),
                    "PQ_WITNESS_COMMIT_UNCERTAIN" => Some("PQ_WITNESS_COMMIT_UNCERTAIN"),
                    "PQ_WITNESS_ROLLBACK" => Some("PQ_WITNESS_ROLLBACK"),
                    "PQ_WITNESS_LOCAL_ROOT" => Some("PQ_WITNESS_LOCAL_ROOT"),
                    "PQ_TLS_CIPHERTEXT_LIMIT" => Some("PQ_TLS_CIPHERTEXT_LIMIT"),
                    _ => None,
                });
        Self {
            kind: error.kind(),
            code,
        }
    }
}

pub(super) struct Observation {
    started: Instant,
    stage_started: Cell<Instant>,
    stage: Cell<&'static str>,
    bio_refusal: Cell<Option<Refusal>>,
    charge_calls: Cell<u64>,
    charge_us: Cell<u64>,
}
impl Observation {
    pub(super) fn new() -> Self {
        let started = Instant::now();
        Self {
            started,
            stage_started: Cell::new(started),
            stage: Cell::new("peer_address"),
            bio_refusal: Cell::new(None),
            charge_calls: Cell::new(0),
            charge_us: Cell::new(0),
        }
    }
    pub(super) fn stage(&self, stage: &'static str) {
        self.stage.set(stage);
        self.stage_started.set(Instant::now());
    }
    pub(super) fn charge(&self, elapsed: Duration, error: Option<&Error>) {
        self.charge_calls
            .set(self.charge_calls.get().saturating_add(1));
        self.charge_us
            .set(self.charge_us.get().saturating_add(micros(elapsed)));
        if self.bio_refusal.get().is_none() {
            self.bio_refusal.set(error.map(Refusal::from_error));
        }
    }
    fn record(&self, error: &Error, deadline: Instant) -> serde_json::Value {
        let outer = Refusal::from_error(error);
        let bio = self.bio_refusal.get();
        serde_json::json!({
            "schema": "pq-tls-connection-refusal-v1",
            "stage": self.stage.get(),
            "elapsed_us": micros(self.started.elapsed()),
            "stage_elapsed_us": micros(self.stage_started.get().elapsed()),
            "deadline_elapsed": Instant::now() >= deadline,
            "error_kind": format!("{:?}", outer.kind),
            "error_code": outer.code,
            "bio_error_kind": bio.map(|e| format!("{:?}", e.kind)),
            "bio_error_code": bio.and_then(|e| e.code),
            "ingress_charge_calls": self.charge_calls.get(),
            "ingress_charge_us": self.charge_us.get(),
        })
    }
    pub(super) fn emit(&self, error: &Error, deadline: Instant, count: &AtomicUsize) {
        // The entire listener emits at most sixteen fixed-size records. Input
        // payloads, addresses, paths, certificates, keys and error text never
        // appear. Observation failures cannot replace the original result.
        if count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < MAX_REFUSAL_RECORDS).then_some(value + 1)
            })
            .is_ok()
        {
            let _ = writeln!(
                std::io::stderr().lock(),
                "TRNM_PQ_TLS_CONNECTION_REFUSAL {}",
                self.record(error, deadline)
            );
        }
    }
}
fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_keep_first_bio_cause_and_never_export_error_text() {
        let observation = Observation::new();
        observation.stage("tls_handshake");
        observation.charge(
            Duration::from_micros(17),
            Some(&Error::from("PQ_WITNESS_DEADLINE")),
        );
        observation.charge(
            Duration::from_micros(23),
            Some(&Error::from("secret:/key/path")),
        );
        let record = observation.record(
            &Error::from("peer-supplied private material"),
            Instant::now(),
        );
        assert_eq!(record["stage"], "tls_handshake");
        assert_eq!(record["bio_error_code"], "PQ_WITNESS_DEADLINE");
        assert_eq!(record["ingress_charge_calls"], 2);
        assert_eq!(record["ingress_charge_us"], 40);
        assert!(record["error_code"].is_null());
        assert!(!record.to_string().contains("private"));
        assert!(!record.to_string().contains("secret"));
        assert!(record.to_string().len() < 768);
    }
    #[test]
    fn observations_do_not_promote_quoted_witness_deadlines() {
        let deadline = Error::from("PQ_WITNESS_DEADLINE");
        let quoted = Error::from("PQ_WITNESS_DEADLINE: quoted");
        assert_eq!(
            Refusal::from_error(&deadline).code,
            Some("PQ_WITNESS_DEADLINE")
        );
        assert_eq!(Refusal::from_error(&quoted).code, None);
        assert_eq!(deadline.kind(), ErrorKind::Unclassified);
        assert_eq!(deadline.code(), None);
    }
}
