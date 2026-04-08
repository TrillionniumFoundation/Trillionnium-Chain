use super::support::mock_task;
use super::*;

    fn fraud_verifier_rejects_case_variant_duplicate_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"Task_Id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":\" 7\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":\"7 \",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":'7',\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_double_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":\"7\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7\xef\xbc\x8c\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_task_id_binding_fail_closed()
    {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7\xef\xbc\x9b\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_semicolon_delimited_duplicate_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7;\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]

    fn fraud_verifier_rejects_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"Worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\"worker-fraud \",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\" worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",'worker':\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker:\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"WORKER\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed()
    {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud \",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_with_quoted_leading_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\" fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"Proof_Type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",'proof_type':\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_missing_result_hash_binding_when_expected() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"Result_Hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909 \"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\" 0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_unclosed_quoted_alias_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",'result_hash':\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_double_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_uppercase_prefixed_alias_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0X0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_unexpected_result_hash_binding_without_context_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
        ));
    }

    #[test]

    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"\xef\xbc\x8c\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"\xef\xbc\x9b\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_proof_type_binding_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"\xef\xbc\x9b\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"\xef\xbc\x8c\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_semicolon_delimited_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7;\"worker\":\"worker-fraud\";\"proof_type\":\"fraud\";\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_comma_delimited_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_result_hash_binding_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"\xef\xbc\x8c\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_result_hash_binding_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"\xef\xbc\x9b\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]

