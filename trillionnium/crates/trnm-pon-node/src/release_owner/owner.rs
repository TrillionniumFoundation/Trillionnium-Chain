//! Real M15 publication owner. Persisted authorization grants no exec by itself.
use super::deployment::Deployment;
use super::frontier::{invalid, Digest32, ExternalM15Authority, Frontier, Result, Validity};
use super::proof_state::{Context, State};
use super::proof_wire::Publication;
use super::records::{self, Index, Record};
use super::transaction::TransactionStore;
use super::trust_client::SignedAuthorityClient;

pub(super) struct Owner {
    pub deployment: Deployment,
    pub context: Context,
    pub store: TransactionStore,
    trust: SignedAuthorityClient,
    invalidated: bool,
}

impl Owner {
    pub fn initialize() -> Result<Self> {
        let deployment = Deployment::load()?;
        let mut trust = deployment.connect()?;
        let context = Context::from_client(&trust);
        let now = trust.now_seconds()?;
        let state = State::initial(&context, now)?;
        let raw = state.index.encode()?;
        let validity = state.check_root_time(now)?;
        let mut store = TransactionStore::initialize(
            &deployment.owner_directory,
            context.namespace,
            &mut trust,
        )?;
        store.commit_with_files(&mut trust, &raw, validity, |files, candidate, fresh| {
            deployment.revalidate()?;
            let state = State::replay(files, candidate, &context)?;
            state.check_root_time(fresh)?;
            if !state.index.records.is_empty() {
                return Err(invalid("M15 initialization is not empty"));
            }
            Ok(())
        })?;
        Ok(Self {
            deployment,
            context,
            store,
            trust,
            invalidated: false,
        })
    }

    pub fn open() -> Result<Self> {
        let deployment = Deployment::load()?;
        let mut trust = deployment.connect()?;
        let context = Context::from_client(&trust);
        let store = TransactionStore::open_existing(
            &deployment.owner_directory,
            context.namespace,
            &mut trust,
        )?;
        let mut owner = Self {
            deployment,
            context,
            store,
            trust,
            invalidated: false,
        };
        owner.reload()?;
        Ok(owner)
    }

    /// Full independent frontier/index and cryptographic replay on every new
    /// operation. Historical expiry is not mistaken for current permission.
    pub fn reload(&mut self) -> Result<State> {
        if self.invalidated {
            return Err(invalid("M15 owner is fenced"));
        }
        let result = (|| {
            self.deployment.revalidate()?;
            self.store.recheck(&mut self.trust)?;
            let (_, raw) = self.store.snapshot()?;
            let state = State::replay(
                self.store.objects()?,
                raw.ok_or_else(|| invalid("M15 owner index not initialized"))?,
                &self.context,
            )?;
            self.store.recheck(&mut self.trust)?;
            let now = checked_time(&mut self.store, &mut self.trust, || {
                self.deployment.revalidate()
            })?;
            if now < state.index.time_floor {
                return Err(invalid("M15 signed clock below retained history"));
            }
            Ok(state)
        })();
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }

    pub fn now(&mut self) -> Result<u64> {
        if self.invalidated {
            return Err(invalid("M15 owner is fenced"));
        }
        let result = self.trust.now_seconds();
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }

    pub fn frontier(&self) -> Result<&Frontier> {
        self.store
            .snapshot()?
            .0
            .ok_or_else(|| invalid("M15 owner has no external frontier"))
    }

    pub fn publish(&mut self, publication: Publication) -> Result<Digest32> {
        let mut state = self.reload()?;
        let now = self.now()?;
        let record = state.prepare_publication(&self.context, publication, now)?;
        self.commit_record(state, record, |_, _| Ok(()))
    }

    /// Only private real installer/launcher/consumer paths call this. They add
    /// the exact held-object check to both verification points.
    pub fn append(
        &mut self,
        record: Record,
        check_actual: impl FnMut(&State, u64) -> Result<()>,
    ) -> Result<Digest32> {
        let mut state = self.reload()?;
        let digest = record.digest()?;
        state.append_verified(&self.context, digest, record.clone())?;
        self.commit_record(state, record, check_actual)
    }

    fn commit_record(
        &mut self,
        state: State,
        record: Record,
        mut check_actual: impl FnMut(&State, u64) -> Result<()>,
    ) -> Result<Digest32> {
        let result = (|| {
            self.deployment.revalidate()?;
            self.store.recheck(&mut self.trust)?;
            let before_raw = self
                .store
                .snapshot()?
                .1
                .ok_or_else(|| invalid("missing M15 prior index"))?
                .to_vec();
            let before: Index =
                super::codec::decode(&before_raw, super::frontier::MAX_INDEX_BYTES)?;
            let mut prior = State::replay(self.store.objects()?, &before_raw, &self.context)?;
            let digest = record.digest()?;
            let mut expected = before.clone();
            expected.records.push(digest);
            expected.kernel_checkpoint = state.index.kernel_checkpoint;
            expected.time_floor = record.observed_at();
            let raw = state.index.encode()?;
            if expected.encode()? != raw {
                return Err(invalid(
                    "M15 mutation must append exactly one retained record",
                ));
            }
            let now = self.now()?;
            let window = transition_window(&mut prior, &state, &record, now)?;
            check_actual(&state, now)?;
            if records::put(self.store.objects()?, &record)? != digest {
                return Err(invalid("M15 retained record digest changed"));
            }
            let context = &self.context;
            let deployment = &self.deployment;
            self.store.commit_with_files(
                &mut self.trust,
                &raw,
                window,
                |files, candidate, fresh| {
                    deployment.revalidate()?;
                    if candidate != raw.as_slice() {
                        return Err(invalid("M15 exact candidate index changed"));
                    }
                    let mut prior = State::replay(files, &before_raw, context)?;
                    let state = State::replay(files, candidate, context)?;
                    let current = transition_window(&mut prior, &state, &record, fresh)?;
                    if current.expires_at != window.expires_at {
                        return Err(invalid("M15 transition validity changed before CAS"));
                    }
                    check_actual(&state, fresh)
                },
            )?;
            Ok(digest)
        })();
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }

    /// Last-use observation under this held owner. The bound consumer immediately
    /// uses it; the observation cannot be serialized, reused, or turned into exec.
    pub fn revalidate_current(
        &mut self,
        state: &State,
        contract: &super::execution_wire::Contract,
    ) -> Result<Validity> {
        let result = (|| {
            if self.invalidated {
                return Err(invalid("M15 owner is fenced"));
            }
            self.deployment.revalidate()?;
            self.store.recheck(&mut self.trust)?;
            if self.store.snapshot()?.1 != Some(state.index.encode()?.as_slice()) {
                return Err(invalid(
                    "M15 last-use state differs from protected current index",
                ));
            }
            let now = checked_time(&mut self.store, &mut self.trust, || {
                self.deployment.revalidate()
            })?;
            let window = state.current_contract(contract, now)?;
            self.trust.require_current_window(window)?;
            Ok(window)
        })();
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }
    /// Called after actual-object checks and immediately before the final use.
    /// Only the authenticated lower sample is a retained floor; this check uses
    /// the live conservative upper interval without any subsequent remote call.
    pub fn finish_observation(&mut self, window: Validity) -> Result<()> {
        if self.invalidated {
            return Err(invalid("M15 owner is fenced"));
        }
        let result = (|| {
            self.deployment.revalidate()?;
            self.store.recheck_local()?;
            self.trust.require_current_window(window)
        })();
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }
}

/// Rotation preserves the original kernel's expired-old-root recovery rule.
/// It still needs the actual prior history, dual quorums and a fresh successor.
/// Ordinary effects retain the prior current-root requirement.
fn transition_window(
    prior: &mut State,
    candidate: &State,
    record: &Record,
    now: u64,
) -> Result<Validity> {
    let next = candidate.record_window(record, now)?;
    if let Record::Publication(super::proof_wire::ObservedPublication {
        publication:
            Publication::RootRotation {
                root,
                old_signatures,
                new_signatures,
            },
        ..
    }) = record
    {
        if now < prior.index.time_floor {
            return Err(invalid("M15 rotation below prior trusted floor"));
        }
        prior
            .authority
            .rotate_root(
                root.kernel()?,
                &super::proof_wire::signatures(old_signatures)?,
                &super::proof_wire::signatures(new_signatures)?,
                now,
            )
            .map_err(std::io::Error::other)?;
        return Ok(next);
    }
    let previous = prior.check_root_time(now)?;
    let window = Validity {
        not_before: previous.not_before.max(next.not_before),
        expires_at: previous.expires_at.min(next.expires_at),
    };
    window.check(now)?;
    Ok(window)
}

/// The final authenticated clock may yield. Rebind the same local owner after
/// that callback and deployment check, before returning a last-use observation.
pub(super) fn checked_time(
    store: &mut TransactionStore,
    trust: &mut impl ExternalM15Authority,
    check_deployment: impl FnOnce() -> Result<()>,
) -> Result<u64> {
    let now = trust.now_seconds()?;
    check_deployment()?;
    store.recheck_local()?;
    Ok(now)
}
