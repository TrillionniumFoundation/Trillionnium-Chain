//! Shared same-process real-signature fixtures, never independent custody evidence.
#![allow(dead_code)]

use openssl::{
    asn1::Asn1Object,
    pkey::{Id, PKey, Private},
    pkey_ctx::PkeyCtx,
    sign::Signer,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use trnm_crypto_primitives::pq_root_v3::{
    possession_message_v3, DualFamilyRosterV3, RootPublicKeyV3, RootSignatureV3, RootSuiteV3,
    VerificationBudgetV3,
};
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::{
    DigestV3, ReleaseIntentV3, ReleaseUseV3, RootActionV3, RootEnvelopeV3, RootPolicyV3,
    RootStateV3, RootStatementV3,
};

pub(crate) fn rejected(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

pub(crate) struct Keys {
    pub(crate) roster: DualFamilyRosterV3,
    pub(crate) secret: BTreeMap<DigestV3, PKey<Private>>,
}
impl Keys {
    pub(crate) fn generate() -> Self {
        assert!(
            openssl::version::number() >= 0x3050_0000,
            "actual OpenSSL 3.5+ required"
        );
        let mut keys = Vec::new();
        let mut secret = BTreeMap::new();
        for (suite, oid) in [
            (RootSuiteV3::MlDsa87, "2.16.840.1.101.3.4.3.19"),
            (RootSuiteV3::SlhDsaSha2_256s, "2.16.840.1.101.3.4.3.24"),
        ] {
            for _ in 0..3 {
                let object = Asn1Object::from_str(oid).unwrap();
                let mut generation = PkeyCtx::new_id(Id::from_raw(object.nid().as_raw())).unwrap();
                generation.keygen_init().unwrap();
                let private = generation.keygen().unwrap();
                let public = RootPublicKeyV3 {
                    suite,
                    spki: private.public_key_to_der().unwrap(),
                };
                secret.insert(public.id().unwrap(), private);
                keys.push(public);
            }
        }
        Self {
            roster: DualFamilyRosterV3::from_keys(keys).unwrap(),
            secret,
        }
    }
    pub(crate) fn sign(&self, id: DigestV3, message: &[u8]) -> RootSignatureV3 {
        let mut signer = Signer::new_without_digest(&self.secret[&id]).unwrap();
        RootSignatureV3 {
            signer: id,
            signature: signer.sign_oneshot_to_vec(message).unwrap(),
        }
    }
    pub(crate) fn quorum(&self, message: &[u8]) -> Vec<RootSignatureV3> {
        RootSuiteV3::ALL
            .into_iter()
            .flat_map(|suite| {
                self.roster
                    .keys()
                    .iter()
                    .filter(move |key| key.suite == suite)
                    .take(2)
            })
            .map(|key| self.sign(key.id().unwrap(), message))
            .collect()
    }
    pub(crate) fn policy(&self) -> RootPolicyV3 {
        RootPolicyV3 {
            roster: self.roster.clone(),
            expires_at_unix: 1000,
        }
    }
    pub(crate) fn envelope(
        &self,
        statement: RootStatementV3,
        successor: Option<&Keys>,
    ) -> RootEnvelopeV3 {
        let approvals = self.quorum(&statement.signing_message().unwrap());
        let successor_possessions = successor.map_or_else(Vec::new, |next| {
            next.roster
                .key_ids()
                .into_iter()
                .map(|id| {
                    next.sign(
                        id,
                        &possession_message_v3(&statement.encode().unwrap(), &next.roster, id)
                            .unwrap(),
                    )
                })
                .collect()
        });
        RootEnvelopeV3 {
            statement,
            approvals,
            successor_possessions,
        }
    }
}
pub(crate) struct Fixtures {
    pub(crate) root: Keys,
    pub(crate) next: Keys,
    pub(crate) writer: Keys,
    pub(crate) anchor: Keys,
}
pub(crate) fn fixtures() -> &'static Fixtures {
    static FIXTURE: OnceLock<Fixtures> = OnceLock::new();
    FIXTURE.get_or_init(|| Fixtures {
        root: Keys::generate(),
        next: Keys::generate(),
        writer: Keys::generate(),
        anchor: Keys::generate(),
    })
}
pub(crate) fn owner_budget() -> OwnerBudgetV3 {
    let until = Instant::now() + Duration::from_secs(120);
    OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, until).unwrap(),
        until,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
}
pub(crate) fn domain() -> JournalDomainV3 {
    JournalDomainV3::new([17; 32], [18; 32], [19; 32]).unwrap()
}
pub(crate) fn state() -> RootStateV3 {
    RootStateV3::bootstrap(domain().scope(), fixtures().root.policy(), 100).unwrap()
}
pub(crate) fn intent(attempt: u8) -> ReleaseIntentV3 {
    ReleaseIntentV3::from_bytes(
        ReleaseUseV3::Install,
        b"complete bundle",
        b"complete launch contract",
        b"held actual executable",
        [attempt; 32],
    )
    .unwrap()
}
pub(crate) fn statement(current: &RootStateV3, nonce: u8, action: RootActionV3) -> RootStatementV3 {
    RootStatementV3 {
        scope: current.scope(),
        generation: current.generation(),
        sequence: current.sequence() + 1,
        predecessor: current.checkpoint(),
        nonce: [nonce; 32],
        valid_from_unix: 100,
        expires_at_unix: 900,
        action,
    }
}
pub(crate) fn normal(current: &RootStateV3, nonce: u8) -> RootEnvelopeV3 {
    fixtures().root.envelope(
        statement(
            current,
            nonce,
            RootActionV3::Normal {
                intent: intent(nonce),
            },
        ),
        None,
    )
}

pub(crate) struct Writer {
    pub(crate) malformed: bool,
}
impl RootWriterSignerV3 for Writer {
    fn sign(
        &mut self,
        message: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
        budget.check()?;
        let mut signatures = fixtures().writer.quorum(message);
        if self.malformed {
            signatures[0].signature[0] ^= 1;
        }
        budget.check()?;
        Ok(signatures)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    BeforeCas,
    AfterCas,
    WrongChallenge,
    WrongSignature,
    CancelAfterCas,
    ReplaceBudgetAfterCas,
}
pub(crate) struct ServiceState {
    pub(crate) head: JournalHeadV3,
    pub(crate) calls: usize,
    pub(crate) cas_calls: usize,
    pub(crate) fault: Fault,
    pub(crate) reset_cancellation: Option<Arc<AtomicBool>>,
}
#[derive(Clone)]
pub(crate) struct Service {
    pub(crate) state: Rc<RefCell<ServiceState>>,
    pub(crate) scope: DigestV3,
}
impl RootAnchorTransportV3 for Service {
    fn exchange(
        &mut self,
        request: AnchorEnvelopeV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedAnchorReceiptV3> {
        // The fixture uses the exact exported anchor-side authenticator. Its
        // separate enrollment pins cannot be supplied by this request.
        request.verify_writer(self.scope, &fixtures().writer.roster, budget)?;
        let mut state = self.state.borrow_mut();
        state.calls += 1;
        let outcome = if let (Some(expected), Some(target)) =
            (request.request.expected, request.request.target)
        {
            state.cas_calls += 1;
            if state.fault == Fault::BeforeCas {
                return Err(rejected("fixture disconnect before CAS"));
            }
            if expected != state.head {
                AnchorOutcomeV3::Mismatch
            } else {
                state.head = target;
                if state.fault == Fault::AfterCas {
                    return Err(rejected("fixture lost reply after CAS"));
                }
                if state.fault == Fault::CancelAfterCas {
                    budget.cancel();
                    if let Some(external) = &state.reset_cancellation {
                        external.store(false, Ordering::Release);
                    }
                }
                AnchorOutcomeV3::Advanced
            }
        } else {
            AnchorOutcomeV3::Current
        };
        let mut receipt = AnchorReceiptV3::for_request(&request.request, state.head, outcome)?;
        if state.fault == Fault::WrongChallenge {
            receipt.challenge[0] ^= 1;
        }
        let mut approvals = fixtures().anchor.quorum(&receipt.message()?);
        if state.fault == Fault::WrongSignature {
            approvals[0].signature[0] ^= 1;
        }
        if state.fault == Fault::ReplaceBudgetAfterCas && request.request.target.is_some() {
            *budget = owner_budget();
        }
        Ok(SignedAnchorReceiptV3 { receipt, approvals })
    }
}

pub(crate) struct Harness {
    pub(crate) directory: TempDir,
    pub(crate) enrollment: JournalEnrollmentV3,
    pub(crate) service: Service,
}
impl Harness {
    pub(crate) fn new() -> Self {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let enrollment = JournalEnrollmentV3::new(
            domain(),
            fixtures().root.policy(),
            100,
            fixtures().writer.roster.clone(),
            fixtures().anchor.roster.clone(),
        )
        .unwrap();
        let service = Service {
            scope: enrollment.scope(),
            state: Rc::new(RefCell::new(ServiceState {
                head: enrollment.initial_head().unwrap(),
                calls: 0,
                cas_calls: 0,
                fault: Fault::None,
                reset_cancellation: None,
            })),
        };
        Self {
            directory,
            enrollment,
            service,
        }
    }
    pub(crate) fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("root.sqlite")
    }
    pub(crate) fn create(&self) -> RootOwnerV3 {
        RootOwnerV3::create(
            &self.path(),
            self.enrollment.clone(),
            Writer { malformed: false },
            self.service.clone(),
            &mut owner_budget(),
        )
        .unwrap()
    }
    pub(crate) fn open(&self) -> RootOwnerResultV3<RootOwnerV3> {
        RootOwnerV3::open_existing(
            &self.path(),
            self.enrollment.clone(),
            Writer { malformed: false },
            self.service.clone(),
            &mut owner_budget(),
        )
    }
    pub(crate) fn pending(&self) -> usize {
        rusqlite::Connection::open(self.path())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM pending", [], |row| row.get(0))
            .unwrap()
    }
}
