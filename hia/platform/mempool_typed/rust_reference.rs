//! Test-only protocol adapter: all queue, metadata and lease decisions call the
//! complete original Rust implementation in this parent module.
use super::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

type Events = Rc<RefCell<Vec<[u64; 2]>>>;

fn event(events: &Events, kind: u64, value: u64) {
    events.borrow_mut().push([kind, value]);
}
fn u64_at(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn digest_at(raw: &[u8], at: usize) -> [u8; 32] {
    raw[at..at + 32].try_into().unwrap()
}
fn reason(code: u64) -> AdmissionReject {
    match code {
        1 => AdmissionReject::CanonicalValidationUnavailable,
        2 => AdmissionReject::CanonicalValidationFailed,
        3 => AdmissionReject::CanonicalDigestChanged,
        4 => AdmissionReject::ZeroDigest,
        5 => AdmissionReject::ZeroSignerId,
        6 => AdmissionReject::SignerIdentityUnavailable,
        7 => AdmissionReject::EmptyBody,
        8 => AdmissionReject::BodyTooLarge,
        9 => AdmissionReject::InvalidNonce,
        10 => AdmissionReject::InvalidResourceLimits,
        11 => AdmissionReject::ResourceLimitExceeded,
        12 => AdmissionReject::SignatureUnavailable,
        13 => AdmissionReject::SignatureRejected,
        14 => AdmissionReject::ReplayCheckUnavailable,
        15 => AdmissionReject::Replay,
        16 => AdmissionReject::RecheckUnavailable,
        17 => AdmissionReject::RecheckFailed,
        18 => AdmissionReject::ReservationUnavailable,
        19 => AdmissionReject::ReservationStateConflict,
        20 => AdmissionReject::SlotIdExhausted,
        21 => AdmissionReject::InconsistentState,
        _ => panic!("unknown test error {code}"),
    }
}
fn reason_code(value: AdmissionReject) -> u64 {
    (1..=21).find(|&code| reason(code) == value).unwrap()
}
fn check(code: u64) -> Result<(), AdmissionReject> {
    if code == 0 { Ok(()) } else { Err(reason(code)) }
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}
struct Envelope<'a> {
    raw: &'a [u8],
    digest_calls: Cell<u64>,
    events: Events,
}
impl SignedEnvelopeView for Envelope<'_> {
    fn canonical_digest(&self) -> CanonicalTxDigest {
        let n = self.digest_calls.get();
        self.digest_calls.set(n + 1);
        event(&self.events, if n == 0 { 1 } else { 3 }, 0);
        // A private test child can construct deliberately invalid adapters.
        CanonicalTxDigest(digest_at(self.raw, if n == 0 { 40 } else { 72 }))
    }
    fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
        event(&self.events, 4, 0);
        check(u64_at(self.raw, 184))?;
        CanonicalSignerId::from_bytes(digest_at(self.raw, 104))
    }
    fn canonical_body(&self) -> &[u8] {
        event(&self.events, 5, 0);
        &self.raw[320..]
    }
    fn nonce(&self) -> u64 {
        event(&self.events, 6, 0);
        u64_at(self.raw, 136)
    }
    fn fee_limit(&self) -> u128 {
        event(&self.events, 8, 0);
        u128::from(u64_at(self.raw, 144)) | (u128::from(u64_at(self.raw, 152)) << 64)
    }
    fn resource_limits(&self) -> ResourceLimits {
        event(&self.events, 7, 0);
        ResourceLimits { max_gas: u64_at(self.raw, 160), max_bytes: u64_at(self.raw, 168) }
    }
    fn validate_canonical(&self) -> Result<(), AdmissionReject> {
        event(&self.events, 2, 0);
        check(u64_at(self.raw, 176))
    }
}
fn metadata_matches(raw: &[u8], metadata: &SignedEnvelopeMetadata) {
    assert_eq!(metadata.digest().as_bytes(), digest_at(raw, 72));
    assert_eq!(metadata.signer_id().as_bytes(), digest_at(raw, 104));
    assert_eq!(metadata.body(), &raw[320..]);
    assert_eq!(metadata.nonce(), u64_at(raw, 136));
    assert_eq!(metadata.fee_limit(), u128::from(u64_at(raw, 144)) | (u128::from(u64_at(raw, 152)) << 64));
    assert_eq!(metadata.resource_limits(), ResourceLimits { max_gas: u64_at(raw, 160), max_bytes: u64_at(raw, 168) });
    assert_eq!(metadata.sequence_key(), (metadata.signer_id(), metadata.nonce()));
}
struct Hooks<'a> { raw: &'a [u8], events: Events }
impl SignedAdmissionHooks<Envelope<'_>> for Hooks<'_> {
    fn verify_signature(&mut self, _envelope: &Envelope<'_>, metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        event(&self.events, 9, metadata.nonce());
        metadata_matches(self.raw, metadata);
        check(u64_at(self.raw, 192))
    }
    fn check_replay(&mut self, metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        event(&self.events, 10, metadata.nonce());
        metadata_matches(self.raw, metadata);
        check(u64_at(self.raw, 200))
    }
    fn recheck(&mut self, metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        event(&self.events, 11, metadata.nonce());
        metadata_matches(self.raw, metadata);
        check(u64_at(self.raw, 208))
    }
}
#[derive(Debug)]
struct Token { events: Events, bound: bool, owner: u64, tag: u64, handoff: u64, commit: u64, release: u64 }
impl PendingNonceReservation for Token {
    fn owner_binding(&self) -> Option<u64> {
        event(&self.events, 16, self.tag);
        self.bound.then_some(self.owner)
    }
    fn handoff(&mut self) -> Result<(), AdmissionReject> {
        event(&self.events, 13, self.tag); check(self.handoff)
    }
    fn commit(&mut self) -> Result<(), AdmissionReject> {
        event(&self.events, 14, self.tag); check(self.commit)
    }
    fn release(&mut self) -> Result<(), AdmissionReject> {
        event(&self.events, 15, self.tag); check(self.release)
    }
}
struct Authority<'a> { raw: &'a [u8], events: Events }
impl PendingNonceAuthority<Envelope<'_>> for Authority<'_> {
    fn reserve_pending_nonce(&mut self, _envelope: &Envelope<'_>, metadata: &SignedEnvelopeMetadata) -> Result<Box<dyn PendingNonceReservation>, AdmissionReject> {
        event(&self.events, 12, metadata.nonce());
        metadata_matches(self.raw, metadata);
        check(u64_at(self.raw, 216))?;
        Ok(Box::new(Token { events: self.events.clone(), bound: u64_at(self.raw, 224) != 0,
            owner: u64_at(self.raw, 232), tag: u64_at(self.raw, 240), handoff: u64_at(self.raw, 248),
            commit: u64_at(self.raw, 256), release: u64_at(self.raw, 264) }))
    }
}
fn metadata_json(metadata: &SignedEnvelopeMetadata) -> String {
    format!("{{\"digest\":\"{}\",\"signer\":\"{}\",\"body\":\"{}\",\"nonce\":{},\"fee_limit\":\"{}\",\"max_gas\":{},\"max_bytes\":{}}}",
        hex(&metadata.digest().as_bytes()), hex(&metadata.signer_id().as_bytes()), hex(metadata.body()),
        metadata.nonce(), metadata.fee_limit(), metadata.resource_limits().max_gas, metadata.resource_limits().max_bytes)
}
fn state_code(state: PendingNonceReservationState) -> u64 {
    match state { PendingNonceReservationState::Reserved => 1, PendingNonceReservationState::HandedOff => 2,
        PendingNonceReservationState::Committed => 3, PendingNonceReservationState::Released => 4 }
}

struct Cursor { raw: Vec<u8>, at: usize }
impl Cursor {
    fn word(&mut self) -> usize {
        let value = usize::try_from(u64_at(&self.raw, self.at)).unwrap(); self.at += 8; value
    }
    fn bytes(&mut self) -> Vec<u8> {
        let size = self.word(); let value = self.raw[self.at..self.at + size].to_vec(); self.at += size; value
    }
}

#[test]
fn complete_typed_owner_actual_corpus() {
    let path = std::env::var("TRNM_TYPED_CORPUS").expect("explicit immutable input corpus");
    let mut input = Cursor { raw: std::fs::read(path).unwrap(), at: 0 };
    let histories = input.word();
    for _ in 0..histories {
        let name = String::from_utf8(input.bytes()).unwrap();
        assert!(name.is_ascii());
        let commands = input.word();
        let events: Events = Rc::new(RefCell::new(Vec::new()));
        let mut gate: Option<TypedAdmissionGate> = None;
        let mut ready: BTreeMap<u64, PendingNonceAdmission> = BTreeMap::new();
        let mut next_handle = 1u64;
        let mut last_limit = 0u64;
        for index in 0..commands {
            let raw = input.bytes();
            assert_eq!(&raw[..8], b"MTIN0001");
            let op = u64_at(&raw, 8); let a = u64_at(&raw, 16);
            events.borrow_mut().clear();
            let mut outcome = 0u64; let mut error = 0u64; let mut present = 0u64; let mut handle = 0u64;
            let mut extra = Vec::<String>::new();
            match op {
                0 | 23 => {
                    assert!(gate.is_none());
                    last_limit = if op == 23 { DEFAULT_MAX_ADMISSION_BODY_BYTES } else { u64_at(&raw, 32) };
                    gate = Some(TypedAdmissionGate::new(usize::try_from(a).unwrap(), usize::try_from(u64_at(&raw, 24)).unwrap(), last_limit));
                }
                1..=4 | 10 => {
                    assert_eq!(u64_at(&raw, 272) as usize, raw.len() - 320);
                    let envelope = Envelope { raw: &raw, digest_calls: Cell::new(0), events: events.clone() };
                    let mut hooks = Hooks { raw: &raw, events: events.clone() };
                    let mut authority = Authority { raw: &raw, events: events.clone() };
                    let current = gate.as_mut().unwrap();
                    if op == 10 {
                        match current.canonical_metadata_v0(&envelope) {
                            Ok(metadata) => { present = 1; extra.push(format!("\"metadata\":{}", metadata_json(&metadata))); }
                            Err(reason) => { outcome = 3; error = reason_code(reason); }
                        }
                    } else {
                        let class = if op == 2 || op == 4 { IngressClass::Critical } else { IngressClass::Normal };
                        let result = if op <= 2 { current.admit_signed(&envelope, class, &mut hooks) }
                            else { current.admit_signed_with_pending_nonce(&envelope, class, &mut hooks, &mut authority) };
                        match result { TypedAdmitOutcome::Accepted => {}, TypedAdmitOutcome::Duplicate => outcome = 1,
                            TypedAdmitOutcome::Backpressured => outcome = 2,
                            TypedAdmitOutcome::Rejected(reason) => { outcome = 3; error = reason_code(reason); } }
                    }
                }
                5 => {
                    if let Some(metadata) = gate.as_mut().unwrap().pop_ready() {
                        present = 1; extra.push(format!("\"metadata\":{}", metadata_json(&metadata)));
                    }
                }
                6 => {
                    if let Some(item) = gate.as_mut().unwrap().pop_ready_with_lifecycle() {
                        present = 1; handle = next_handle; next_handle += 1;
                        extra.push(format!("\"metadata\":{}", metadata_json(item.metadata())));
                        assert!(ready.insert(handle, item).is_none());
                    }
                }
                7 | 8 => {
                    let qos = gate.as_ref().unwrap().qos_snapshot();
                    extra.push(format!("\"headroom\":[{},{},{}]", qos.normal_headroom, qos.critical_headroom, qos.total_headroom));
                }
                9 => present = u64::from(gate.as_ref().unwrap().contains_digest(CanonicalTxDigest(digest_at(&raw, 40)))),
                11..=19 => {
                    if !ready.contains_key(&a) { outcome = 3; error = 21; }
                    else if op == 18 {
                        let metadata = ready.remove(&a).unwrap().into_metadata();
                        present = 1; handle = a; extra.push(format!("\"metadata\":{}", metadata_json(&metadata)));
                    } else if op == 19 { drop(ready.remove(&a).unwrap()); }
                    else {
                        let item = ready.get_mut(&a).unwrap();
                        let mut result = Ok(());
                        match op {
                            11 => { present = 1; handle = a; extra.push(format!("\"metadata\":{}", metadata_json(item.metadata()))); }
                            12 => match item.reservation_state() {
                                Ok(state) => { present = 1; extra.push(format!("\"state\":{}", state_code(state))); }
                                Err(reason) => result = Err(reason),
                            },
                            13 => match item.owner_binding() {
                                Some(value) => { present = 1; extra.push(format!("\"binding\":{value}")); }
                                None => extra.push("\"binding\":null".to_string()),
                            },
                            14 => result = item.handoff(), 15 => result = item.commit(),
                            16 => result = item.release(), 17 => result = item.cancel(), _ => unreachable!(),
                        }
                        if let Err(reason) = result { outcome = 3; error = reason_code(reason); }
                    }
                }
                20 => {
                    let old = gate.take().unwrap();
                    let new = TypedAdmissionGate::new(old.lanes.total_capacity, old.lanes.critical.capacity, old.max_body_bytes);
                    drop(old); gate = Some(new);
                }
                21 => drop(gate.take().unwrap()),
                22 => { drop(gate.take()); ready.clear(); }
                _ => panic!("unknown test operation {op}"),
            }
            let (normal, critical, total, fresh_normal, fresh_critical, streak) = match gate.as_ref() {
                Some(current) => {
                    let counts = current.queued_counts(); let qos = current.qos_snapshot();
                    (counts.0, counts.1, counts.2, u64::from(qos.fresh_normal_admissible),
                        u64::from(qos.fresh_critical_admissible), current.lanes.critical_served_streak)
                }
                None => (0, 0, 0, 0, 0, 0),
            };
            let suffix = if extra.is_empty() { String::new() } else { format!(",{}", extra.join(",")) };
            println!("HIA_TYPED_OBS {{\"history\":{name:?},\"index\":{index},\"returned\":{{\"op\":{op},\"outcome\":{outcome},\"reason\":{error},\"present\":{present},\"handle\":{handle},\"counts\":[{normal},{critical},{total}],\"streak\":{streak},\"max_body_bytes\":{last_limit},\"fresh\":[{fresh_normal},{fresh_critical}],\"events\":{:?}{suffix}}}}}", *events.borrow());
        }
        assert!(gate.is_none() && ready.is_empty(), "all native/original owners must close explicitly");
    }
    assert_eq!(input.at, input.raw.len());
}
