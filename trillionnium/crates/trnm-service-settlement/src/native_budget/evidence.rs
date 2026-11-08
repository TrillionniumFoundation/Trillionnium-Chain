//! Read-only, typed exports from the checked M12 journal.
//!
//! These exports authenticate the journal's retained statements, not its owner
//! callback. A native consumer must re-read every retained funding observation
//! and payment through its own real state owner. No JSON decoder constructs an
//! export, and a checkpoint is only an expectation to verify against a store.
use super::*;
use serde_json::json;

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeBudgetCheckpointV1 {
    pub configuration: NativeBudgetConfigV1,
    pub sequence: u64,
    pub root: NativeBudgetHashV1,
}

/// An immutable statement retained by an actual Open, Reserve or Intent event.
/// Its construction is private; `verify_observation` still requires the native
/// consumer to supply an observation read from its own checked history.
#[derive(Clone, Debug)]
pub struct NativeBudgetFundingEvidenceV1 {
    anchor: NativeBudgetAnchorV1,
    funding: Funding,
}
impl NativeBudgetFundingEvidenceV1 {
    pub fn anchor(&self) -> NativeBudgetAnchorV1 {
        self.anchor
    }
    pub fn source(&self) -> NativeFundingSourceV1 {
        self.funding.pin.source
    }
    pub fn verify_observation(
        &self,
        observed: &NativeFundingObservationV1,
    ) -> NativeBudgetResultV1<()> {
        require(
            observed.anchor == self.anchor && observed.source == self.source(),
            "BUDGET_EVIDENCE_NATIVE_ANCHOR",
        )?;
        let actual = funding(observed, self.funding.pin.lane)?;
        require(
            encoded(&actual)? == encoded(&self.funding)?,
            "BUDGET_EVIDENCE_NATIVE_FUNDING",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBudgetEffectEvidenceV1 {
    pub operation: NativeBudgetHashV1,
    pub effect: NativeBudgetHashV1,
    pub window: Option<(u64, u64)>,
    pub receipt: Option<NativeBudgetHashV1>,
}

/// Sealed snapshot, obtained only by replaying a real NativeBudgetStoreV1.
/// Resources and outcomes remain statements by the local operation owner;
/// neither a hash chain nor an export performs physical metering or evaluation.
#[derive(Clone, Debug)]
pub struct NativeBudgetClaimEvidenceV1 {
    checkpoint: NativeBudgetCheckpointV1,
    budget: Budget,
    claim: Claim,
    funding: Vec<NativeBudgetFundingEvidenceV1>,
}
impl NativeBudgetClaimEvidenceV1 {
    pub fn checkpoint(&self) -> &NativeBudgetCheckpointV1 {
        &self.checkpoint
    }
    pub fn policy(&self) -> &NativeBudgetPolicyV1 {
        &self.budget.policy
    }
    pub fn claim(&self) -> &NativeBudgetClaimV1 {
        &self.claim.specification
    }
    pub fn funding_observations(&self) -> &[NativeBudgetFundingEvidenceV1] {
        &self.funding
    }
    pub fn funding_owner(&self) -> NativeBudgetHashV1 {
        self.budget.funding.owner
    }
    pub fn outcome(&self) -> Option<NativeResourceOutcomeV1> {
        self.claim.outcome
    }
    pub fn consumed(&self) -> Option<&NativeBudgetResourcesV1> {
        self.claim.consumed.as_ref()
    }
    pub fn effect(&self) -> Option<NativeBudgetEffectEvidenceV1> {
        self.claim
            .effect
            .as_ref()
            .map(|effect| NativeBudgetEffectEvidenceV1 {
                operation: effect.operation,
                effect: effect.effect,
                window: effect.window,
                receipt: effect.receipt,
            })
    }
    pub fn historical_payment(&self) -> Option<&NativePaymentObservationV1> {
        self.claim.payment.as_ref()
    }
    /// Stable across later completion, metering, payment and journal appends.
    pub fn binding_digest(&self) -> NativeBudgetResultV1<NativeBudgetHashV1> {
        let bytes = encoded(&(
            &self.checkpoint.configuration,
            &self.budget.policy,
            &self.budget.funding,
            &self.claim.specification,
        ))?;
        Ok(digest(b"pon-native-budget-evidence-binding-v1", &bytes))
    }
    pub fn evidence_digest(&self) -> NativeBudgetResultV1<NativeBudgetHashV1> {
        let bytes = encoded(&(&self.checkpoint, &self.budget, &self.claim))?;
        Ok(digest(b"pon-native-budget-claim-evidence-v1", &bytes))
    }
    /// A display/export format only. There is deliberately no inverse decoder.
    pub fn report(&self) -> NativeBudgetResultV1<Value> {
        let effect = self.effect().map(|effect| {
            json!({
                "operation":hex_string(&effect.operation),
                "effect":hex_string(&effect.effect),
                "window":effect.window,
                "receipt":effect.receipt.map(|value| hex_string(&value)),
            })
        });
        Ok(json!({
            "schema":"pon-native-budget-claim-evidence-v1",
            "binding_digest":hex_string(&self.binding_digest()?),
            "evidence_digest":hex_string(&self.evidence_digest()?),
            "checkpoint":{
                "network":hex_string(&self.checkpoint.configuration.network),
                "parameters":hex_string(&self.checkpoint.configuration.parameters),
                "genesis":hex_string(&self.checkpoint.configuration.genesis),
                "max_records":self.checkpoint.configuration.max_records,
                "sequence":self.checkpoint.sequence,
                "root":hex_string(&self.checkpoint.root),
            },
            "budget":hex_string(&self.budget.policy.budget),
            "claim":hex_string(&self.claim.specification.claim),
            "source":self.budget.policy.source.key(),
            "funding_owner":hex_string(&self.budget.funding.owner),
            "subject":hex_string(&self.claim.specification.subject),
            "beneficiary":hex_string(&self.claim.specification.beneficiary),
            "monetary_cap":self.budget.policy.monetary_cap,
            "monetary_reservation":self.claim.specification.monetary_reservation,
            "deadline":self.budget.policy.deadline,
            "lane":format!("{:?}", self.budget.policy.resource_cap.lane()),
            "resource_reservation":self.claim.specification.resource_reservation.vector(),
            "resource_charge":self.claim.resource_charge().vector(),
            "measured_resources":self.claim.consumed.as_ref().map(NativeBudgetResourcesV1::vector),
            "outcome":self.claim.outcome.map(|outcome| format!("{outcome:?}")),
            "effect":effect,
            "closed":self.budget.closed,
            "funding_observation_count":self.funding.len(),
            "historical_payment":self.claim.payment.as_ref().map(payment_report),
            "physical_metering_verified":false,
            "independent_evaluation_verified":false,
            "external_demand_verified":false,
            "execution_authority":false,
        }))
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> NativeBudgetHashV1 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}
fn payment_report(payment: &NativePaymentObservationV1) -> Value {
    json!({
        "block":hex_string(&payment.anchor.block),
        "state_root":hex_string(&payment.anchor.state_root),
        "height":payment.anchor.height,
        "generation":payment.anchor.generation,
        "operation":hex_string(&payment.operation),
        "gross_escrow_debit":payment.gross_escrow_debit,
        "beneficiary_credit":payment.beneficiary_credit,
    })
}

impl NativeBudgetStoreV1 {
    pub fn evidence_checkpoint_v1(&self) -> NativeBudgetResultV1<NativeBudgetCheckpointV1> {
        let (_, sequence, root) = load_snapshot(&self.connection, &self.configuration)?;
        Ok(NativeBudgetCheckpointV1 {
            configuration: self.configuration.clone(),
            sequence,
            root,
        })
    }

    /// Accept only a retained, exact prefix of this fully checked journal.
    /// A valid append may follow the checkpoint. A rollback, substituted file,
    /// or different event at the same sequence fails closed.
    pub fn verify_evidence_checkpoint_v1(
        &self,
        expected: &NativeBudgetCheckpointV1,
    ) -> NativeBudgetResultV1<NativeBudgetCheckpointV1> {
        require(
            expected.configuration == self.configuration,
            "BUDGET_EVIDENCE_CHECKPOINT_CONTEXT",
        )?;
        let transaction = self.connection.unchecked_transaction()?;
        let (_, sequence, root) = load_checked(&transaction, &self.configuration, None)?;
        require(sequence >= expected.sequence, "BUDGET_EVIDENCE_ROLLBACK")?;
        let actual = if expected.sequence == 0 {
            [0; 32]
        } else {
            fixed(transaction.query_row(
                "SELECT root FROM native_budget_events_v1 WHERE sequence=?1",
                [expected.sequence],
                |row| row.get(0),
            )?)?
        };
        require(actual == expected.root, "BUDGET_EVIDENCE_FORK")?;
        transaction.commit()?;
        Ok(NativeBudgetCheckpointV1 {
            configuration: self.configuration.clone(),
            sequence,
            root,
        })
    }

    pub fn claim_evidence_v1(
        &self,
        identity: NativeBudgetHashV1,
    ) -> NativeBudgetResultV1<NativeBudgetClaimEvidenceV1> {
        self.claim_evidence_after_v1(identity, None)
    }

    /// Check the consumer's retained prefix and export the claim in one SQLite
    /// read transaction. Separate preflight reads cannot establish this link.
    pub fn claim_evidence_after_v1(
        &self,
        identity: NativeBudgetHashV1,
        expected: Option<&NativeBudgetCheckpointV1>,
    ) -> NativeBudgetResultV1<NativeBudgetClaimEvidenceV1> {
        let transaction = self.connection.unchecked_transaction()?;
        let (state, sequence, root) = load_checked(&transaction, &self.configuration, None)?;
        if let Some(expected) = expected {
            require(
                expected.configuration == self.configuration,
                "BUDGET_EVIDENCE_CHECKPOINT_CONTEXT",
            )?;
            require(sequence >= expected.sequence, "BUDGET_EVIDENCE_ROLLBACK")?;
            let actual = if expected.sequence == 0 {
                [0; 32]
            } else {
                fixed(transaction.query_row(
                    "SELECT root FROM native_budget_events_v1 WHERE sequence=?1",
                    [expected.sequence],
                    |row| row.get(0),
                )?)?
            };
            require(actual == expected.root, "BUDGET_EVIDENCE_FORK")?;
        }
        let claim = state.claim(identity)?.clone();
        let budget = state.budget(claim.specification.budget)?.clone();
        let mut funding = Vec::new();
        {
            let mut query = transaction
                .prepare("SELECT payload FROM native_budget_events_v1 ORDER BY sequence")?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let payload: Vec<u8> = row.get(0)?;
                // The same pinned transaction was completely validated above.
                let event: Event = borsh::from_slice(&payload)?;
                let observed = match event {
                    Event::Open {
                        anchor,
                        funding,
                        policy,
                    } if policy.budget == budget.policy.budget => Some((anchor, funding)),
                    Event::Reserve {
                        anchor,
                        funding,
                        claim,
                    } if claim.claim == identity => Some((anchor, funding)),
                    Event::Intent {
                        anchor,
                        funding,
                        claim,
                        ..
                    } if claim == identity => Some((anchor, funding)),
                    _ => None,
                };
                if let Some((anchor, observed)) = observed {
                    funding.push(NativeBudgetFundingEvidenceV1 {
                        anchor,
                        funding: observed,
                    });
                }
            }
        }
        require(
            funding.len() == 2 + usize::from(claim.effect.is_some()),
            "BUDGET_EVIDENCE_FUNDING_COUNT",
        )?;
        transaction.commit()?;
        Ok(NativeBudgetClaimEvidenceV1 {
            checkpoint: NativeBudgetCheckpointV1 {
                configuration: self.configuration.clone(),
                sequence,
                root,
            },
            budget,
            claim,
            funding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These unit fixtures exercise the journal only. The Node integration
    // suite separately proves that a fabricated owner never authenticates funds.
    struct TestOwner(NativeFundingObservationV1);
    impl NativeFundingOwnerV1 for TestOwner {
        fn observe_funding(
            &mut self,
            _source: NativeFundingSourceV1,
        ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
            Ok(self.0.clone())
        }
    }
    fn resources(amount: u64) -> NativeBudgetResourcesV1 {
        NativeBudgetResourcesV1::Evaluation {
            evaluation_cpu_ns: amount,
            evaluated_examples: amount,
        }
    }
    fn fixture(path: &Path) -> (NativeBudgetStoreV1, TestOwner) {
        let configuration = NativeBudgetConfigV1 {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            max_records: 16,
        };
        let source = NativeFundingSourceV1::Task([6; 32]);
        let mut owner = TestOwner(NativeFundingObservationV1 {
            anchor: NativeBudgetAnchorV1 {
                network: configuration.network,
                parameters: configuration.parameters,
                genesis: configuration.genesis,
                block: [4; 32],
                state_root: [5; 32],
                height: 1,
                generation: 1,
            },
            source,
            row: Some(json!({
                "owner":hex_string(&[7; 32]), "provider":hex_string(&[8; 32]),
                "remaining":20,"deadline":100,"status":"reserved","output":null,
            })),
        });
        let mut store = NativeBudgetStoreV1::open(path, configuration).unwrap();
        store
            .open_budget(
                &mut owner,
                NativeBudgetPolicyV1 {
                    budget: [10; 32],
                    source,
                    monetary_cap: 20,
                    deadline: 99,
                    resource_cap: resources(10),
                    max_inflight: 1,
                },
            )
            .unwrap();
        store
            .reserve(
                &mut owner,
                NativeBudgetClaimV1 {
                    claim: [11; 32],
                    budget: [10; 32],
                    subject: [12; 32],
                    beneficiary: [8; 32],
                    monetary_reservation: 20,
                    resource_reservation: resources(4),
                },
            )
            .unwrap();
        (store, owner)
    }

    #[test]
    fn evidence_snapshot_preserves_binding_and_checks_exact_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, mut owner) = fixture(&directory.path().join("budget.sqlite"));
        let before = store.claim_evidence_v1([11; 32]).unwrap();
        assert_eq!(before.funding_observations().len(), 2);
        assert!(before.effect().is_none());
        store
            .begin_effect(&mut owner, [11; 32], [13; 32], [12; 32])
            .unwrap();
        store
            .record_resources(
                [11; 32],
                NativeResourceOutcomeV1::NoGain,
                Some(resources(3)),
            )
            .unwrap();
        store.complete_effect([11; 32], [13; 32], [14; 32]).unwrap();
        let after = store
            .claim_evidence_after_v1([11; 32], Some(before.checkpoint()))
            .unwrap();
        assert_eq!(after.funding_observations().len(), 3);
        assert_eq!(
            before.binding_digest().unwrap(),
            after.binding_digest().unwrap()
        );
        assert_ne!(
            before.evidence_digest().unwrap(),
            after.evidence_digest().unwrap()
        );
        assert_eq!(after.effect().unwrap().receipt, Some([14; 32]));
        assert_eq!(after.report().unwrap()["outcome"], "NoGain");
        assert_eq!(after.report().unwrap()["external_demand_verified"], false);
        assert_eq!(
            store
                .verify_evidence_checkpoint_v1(before.checkpoint())
                .unwrap(),
            *after.checkpoint()
        );
        for retained in after.funding_observations() {
            retained.verify_observation(&owner.0).unwrap();
        }
        owner.0.row.as_mut().unwrap()["remaining"] = json!(21);
        assert!(after.funding_observations()[0]
            .verify_observation(&owner.0)
            .is_err());
        let mut invalid = before.checkpoint().clone();
        invalid.root[0] ^= 1;
        assert!(matches!(
            store.claim_evidence_after_v1([11; 32], Some(&invalid)),
            Err(NativeBudgetErrorV1::Invalid("BUDGET_EVIDENCE_FORK"))
        ));
        invalid = after.checkpoint().clone();
        invalid.sequence += 1;
        assert!(matches!(
            store.verify_evidence_checkpoint_v1(&invalid),
            Err(NativeBudgetErrorV1::Invalid("BUDGET_EVIDENCE_ROLLBACK"))
        ));
        invalid = after.checkpoint().clone();
        invalid.configuration.max_records += 1;
        assert!(matches!(
            store.claim_evidence_after_v1([11; 32], Some(&invalid)),
            Err(NativeBudgetErrorV1::Invalid(
                "BUDGET_EVIDENCE_CHECKPOINT_CONTEXT"
            ))
        ));
    }

    #[test]
    fn evidence_export_rechecks_live_journal_instead_of_trusting_a_cached_report() {
        let directory = tempfile::tempdir().unwrap();
        let (store, _) = fixture(&directory.path().join("budget.sqlite"));
        let before = store.claim_evidence_v1([11; 32]).unwrap();
        store.connection.execute(
            "UPDATE native_budget_events_v1 SET payload=zeroblob(length(payload)) WHERE sequence=1", [],
        ).unwrap();
        assert!(store.claim_evidence_v1([11; 32]).is_err());
        assert!(store
            .verify_evidence_checkpoint_v1(before.checkpoint())
            .is_err());
        assert!(store.evidence_checkpoint_v1().is_err());
    }
}
