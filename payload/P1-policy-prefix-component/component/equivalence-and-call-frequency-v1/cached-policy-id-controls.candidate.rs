    fn original_policy_id(
        bits: u8,
        lifetime_ms: u64,
        burst_ns: u64,
        refill_ns: u64,
        start_reserve_ns: u64,
        workers: u32,
    ) -> Hash {
        // The original complete pon_wire::hash call is the independent oracle.
        hash(
            b"public-protected-profile-v3",
            &[
                PROFILE.as_bytes(),
                PUBLIC_RESOURCE_CONTRACT,
                &[bits],
                &lifetime_ms.to_le_bytes(),
                &burst_ns.to_le_bytes(),
                &refill_ns.to_le_bytes(),
                &start_reserve_ns.to_le_bytes(),
                &workers.to_le_bytes(),
            ],
        )
    }

    #[test]
    fn cached_policy_id_matches_original_hash_for_public_fields() {
        // Public fields can be deserialized without passing the constructor.
        for bits in [0, 7, 8, 12, 16, 20, 21, u8::MAX] {
            for lifetime_ms in [0, 99, 100, 1999, 2000, 2001, u64::MAX] {
                let policy = PublicPolicy { bits, lifetime_ms };
                assert_eq!(
                    policy.id(),
                    original_policy_id(
                        bits,
                        lifetime_ms,
                        MUTATION_CPU_BURST_NS,
                        MUTATION_CPU_REFILL_NS_PER_SECOND,
                        MUTATION_CPU_START_RESERVE_NS,
                        MUTATION_CPU_WORKERS as u32,
                    )
                );
            }
        }
    }

    #[test]
    fn cached_policy_id_retains_all_six_framed_suffix_parts() {
        let base = (16, 2000, 1, 2, 3, 4);
        let cases = [
            base,
            (17, 2000, 1, 2, 3, 4),
            (16, 2001, 1, 2, 3, 4),
            (16, 2000, 5, 2, 3, 4),
            (16, 2000, 1, 5, 3, 4),
            (16, 2000, 1, 2, 5, 4),
            (16, 2000, 1, 2, 3, 5),
            (0, 0, 0, 0, 0, 0),
            (u8::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u32::MAX),
        ];
        let baseline = original_policy_id(base.0, base.1, base.2, base.3, base.4, base.5);
        for (index, (bits, lifetime, burst, refill, reserve, workers)) in
            cases.into_iter().enumerate()
        {
            let expected = original_policy_id(bits, lifetime, burst, refill, reserve, workers);
            let actual = hash_public_policy([
                &[bits],
                &lifetime.to_le_bytes(),
                &burst.to_le_bytes(),
                &refill.to_le_bytes(),
                &reserve.to_le_bytes(),
                &workers.to_le_bytes(),
            ]);
            assert_eq!(actual, expected);
            if index != 0 {
                assert_ne!(actual, baseline);
            }
        }
    }

    #[test]
    fn cached_policy_id_clones_are_independent_across_callers() {
        let barrier = std::sync::Barrier::new(4);
        thread::scope(|scope| {
            for worker in 0..4u8 {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for round in 0..32u64 {
                        let policy = PublicPolicy {
                            bits: 8 + worker,
                            lifetime_ms: 100 + round + u64::from(worker),
                        };
                        let expected = original_policy_id(
                            policy.bits,
                            policy.lifetime_ms,
                            MUTATION_CPU_BURST_NS,
                            MUTATION_CPU_REFILL_NS_PER_SECOND,
                            MUTATION_CPU_START_RESERVE_NS,
                            MUTATION_CPU_WORKERS as u32,
                        );
                        assert_eq!(policy.id(), expected);
                    }
                });
            }
        });
        assert_eq!(
            hex::encode(PublicPolicy::development().id()),
            "59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b"
        );
    }

