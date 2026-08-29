    fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32]).expect("nonzero digest")
    }

    fn config() -> CoordinatorConfigV1 {
        CoordinatorConfigV1::new(
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            digest(8),
            1,
        )
        .expect("nonzero process generation")
    }

    fn target(height: u64, epoch: u64, view: u64, offset: u8) -> SignTargetV1 {
        SignTargetV1::new(
            epoch,
            view,
            height,
            digest(10 + offset),
            digest(20 + offset),
            digest(30 + offset),
            digest(40 + offset),
            digest(50 + offset),
            digest(60 + offset),
            digest(70 + offset),
        )
        .expect("target")
    }

    fn cut(target: SignTargetV1, app: u64, safety: u64, signer: u64) -> CandidateCutV1 {
        CandidateCutV1::new(
            target,
            ApplicationFinalizationReadbackV1::new(
                digest(1),
                digest(2),
                app,
                target.height,
                target.block_id,
                target.body_hash,
                target.application_root,
                target.receipts_root,
                true,
            ),
            SafetyTag3ReadbackV1::new(
                digest(1),
                digest(3),
                safety,
                target.epoch,
                target.view,
                target.height,
                target.block_id,
                target.body_hash,
                target.application_root,
                target.safety_state_hash,
                SAFETY_FINALIZATION_TAG_V1,
                true,
            ),
            SignerPreparedIntentReadbackV1::new(
                digest(1),
                digest(4),
                signer,
                target.epoch,
                target.view,
                target.block_id,
                target.sign_intent_hash,
                target.signing_root,
                digest(7),
                digest(8),
                1,
                true,
            ),
        )
    }

    fn plan(
        coordinator: &mut CrossStoreCoordinatorV1,
        cut: CandidateCutV1,
    ) -> CommitPlanV1 {
        match coordinator
            .reconcile(cut, None, None)
            .expect("prepare new cut")
        {
            ReconcileOutcomeV1::CommitRequired(plan) => plan,
            ReconcileOutcomeV1::Permit(_) => panic!("unexpected permit"),
        }
    }

    #[test]
    fn exact_dual_readback_releases_permit() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        let plan = plan(&mut coordinator, candidate);
        match coordinator
            .reconcile(candidate, Some(*plan.checkpoint()), Some(*plan.watermark()))
            .unwrap()
        {
            ReconcileOutcomeV1::Permit(permit) => {
                assert_eq!(permit.target(), candidate.target());
                assert_eq!(permit.checkpoint_generation(), 1);
                assert_eq!(permit.application_store_id(), digest(2));
                assert_eq!(permit.safety_store_id(), digest(3));
                assert_eq!(permit.signer_journal_id(), digest(4));
            }
            ReconcileOutcomeV1::CommitRequired(_) => panic!("expected permit"),
        }
    }

    #[test]
    fn response_loss_exact_replay_releases_same_generation() {
        let candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        let mut first = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let plan = plan(&mut first, candidate);
        let checkpoint = *plan.checkpoint();
        let watermark = *plan.watermark();
        let mut restarted =
            CrossStoreCoordinatorV1::open(config(), Some(checkpoint), Some(watermark)).unwrap();
        match restarted
            .reconcile(candidate, Some(checkpoint), Some(watermark))
            .unwrap()
        {
            ReconcileOutcomeV1::Permit(permit) => {
                assert_eq!(permit.checkpoint_generation(), checkpoint.generation());
            }
            ReconcileOutcomeV1::CommitRequired(_) => panic!("replay must not re-commit"),
        }
    }

    #[test]
    fn application_root_mismatch_is_rejected() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let target = target(1, 1, 1, 0);
        let mut candidate = cut(target, 1, 1, 1);
        candidate.application.application_root = digest(99);
        assert_eq!(
            coordinator.reconcile(candidate, None, None).unwrap_err(),
            CoordinatorErrorV1::ApplicationTargetMismatch
        );
        assert!(!coordinator.is_fenced());
    }

    #[test]
    fn wrong_safety_tag_is_rejected() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let mut candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        candidate.safety.transition_tag = 2;
        assert_eq!(
            coordinator.reconcile(candidate, None, None).unwrap_err(),
            CoordinatorErrorV1::WrongSafetyTransitionTag
        );
    }

    #[test]
    fn checkpoint_only_commit_fences() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        let plan = plan(&mut coordinator, candidate);
        assert_eq!(
            coordinator
                .reconcile(candidate, Some(*plan.checkpoint()), None)
                .unwrap_err(),
            CoordinatorErrorV1::MixedCommit
        );
        assert!(coordinator.is_fenced());
        assert_eq!(
            coordinator.reconcile(candidate, None, None).unwrap_err(),
            CoordinatorErrorV1::Fenced
        );
    }

    #[test]
    fn watermark_only_commit_fences() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        let plan = plan(&mut coordinator, candidate);
        assert_eq!(
            coordinator
                .reconcile(candidate, None, Some(*plan.watermark()))
                .unwrap_err(),
            CoordinatorErrorV1::MixedCommit
        );
        assert!(coordinator.is_fenced());
    }

    #[test]
    fn unknown_third_state_fences() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        let plan = plan(&mut coordinator, candidate);
        let mut third = *plan.checkpoint();
        third.generation = 99;
        assert_eq!(
            coordinator.reconcile(candidate, Some(third), None).unwrap_err(),
            CoordinatorErrorV1::ThirdState
        );
        assert!(coordinator.is_fenced());
    }

    #[test]
    fn successor_must_advance_every_durable_sequence() {
        let first_cut = cut(target(1, 1, 1, 0), 1, 1, 1);
        let mut first = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let first_plan = plan(&mut first, first_cut);
        let checkpoint = *first_plan.checkpoint();
        let watermark = *first_plan.watermark();
        let mut coordinator =
            CrossStoreCoordinatorV1::open(config(), Some(checkpoint), Some(watermark)).unwrap();
        let stale = cut(target(2, 1, 2, 1), 1, 2, 2);
        assert_eq!(
            coordinator
                .reconcile(stale, Some(checkpoint), Some(watermark))
                .unwrap_err(),
            CoordinatorErrorV1::SequenceRollback
        );
    }

    #[test]
    fn same_height_different_target_is_rejected() {
        let first_cut = cut(target(1, 1, 1, 0), 1, 1, 1);
        let mut first = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let first_plan = plan(&mut first, first_cut);
        let checkpoint = *first_plan.checkpoint();
        let watermark = *first_plan.watermark();
        let mut coordinator =
            CrossStoreCoordinatorV1::open(config(), Some(checkpoint), Some(watermark)).unwrap();
        let conflict = cut(target(1, 1, 2, 1), 2, 2, 2);
        assert_eq!(
            coordinator
                .reconcile(conflict, Some(checkpoint), Some(watermark))
                .unwrap_err(),
            CoordinatorErrorV1::SameHeightConflict
        );
    }

    #[test]
    fn store_identity_substitution_on_reopen_is_rejected() {
        let candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        let mut first = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let plan = plan(&mut first, candidate);
        let substituted = CoordinatorConfigV1::new(
            digest(1),
            digest(82),
            digest(83),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            digest(8),
            1,
        )
        .expect("nonzero process generation");
        assert_eq!(
            CrossStoreCoordinatorV1::open(
                substituted,
                Some(*plan.checkpoint()),
                Some(*plan.watermark()),
            )
            .unwrap_err(),
            CoordinatorErrorV1::StoreIdentityMismatch
        );
    }

    #[test]
    fn custody_policy_mismatch_is_rejected() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let mut candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        candidate.signer.custody_policy_hash = digest(99);
        assert_eq!(
            coordinator.reconcile(candidate, None, None).unwrap_err(),
            CoordinatorErrorV1::CustodyBindingMismatch
        );
    }

    #[test]
    fn process_generation_mismatch_is_rejected() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let mut candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        candidate.signer.process_generation = 2;
        assert_eq!(
            coordinator.reconcile(candidate, None, None).unwrap_err(),
            CoordinatorErrorV1::ProcessGenerationMismatch
        );
    }

    #[test]
    fn cross_namespace_cut_is_rejected() {
        let mut coordinator = CrossStoreCoordinatorV1::open(config(), None, None).unwrap();
        let mut candidate = cut(target(1, 1, 1, 0), 1, 1, 1);
        candidate.signer.namespace_scope = digest(88);
        assert_eq!(
            coordinator.reconcile(candidate, None, None).unwrap_err(),
            CoordinatorErrorV1::NamespaceMismatch
        );
    }
