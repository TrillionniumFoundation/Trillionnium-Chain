use trnm_verification_profiles::exact_integer_linear_v1::*;

fn context() -> IntegerLinearContextV1 {
    IntegerLinearContextV1::new(INTEGER_LINEAR_FAMILY_V1, [3; 32], 0).unwrap()
}

fn adapter(context: &IntegerLinearContextV1, a: &[Vec<i64>], b: &[Vec<i64>]) -> Vec<u8> {
    fn matrix(m: &[Vec<i64>]) -> String {
        format!(
            "[{}]",
            m.iter()
                .map(|row| format!(
                    "[{}]",
                    row.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
                ))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
    format!(
        "{{\"A\":{},\"B\":{},\"contract\":\"{}\",\"schema\":\"pon-integer-linear-adapter-v1\"}}",
        matrix(a),
        matrix(b),
        hex(&context.contract_id())
    )
    .into_bytes()
}

fn verify(
    c: &IntegerLinearContextV1,
    a: &[Vec<i64>],
    b: &[Vec<i64>],
) -> CheckedIntegerLinearUpdateV1 {
    verify_integer_linear_v1(c, &adapter(c, a, b), MAX_MULTIPLICATIONS).unwrap()
}

#[test]
fn basis_sign_padding_and_full_vector_equality_without_digest_oracle() {
    let c = context();
    let a0: Vec<i64> = (0..COLUMNS).map(|j| j as i64 % 7 - 3).collect();
    let a1: Vec<i64> = (0..COLUMNS).map(|j| j as i64 % 5 - 2).collect();
    let first = verify(
        &c,
        &[a0.clone(), a1.clone()],
        &[vec![2, 3], vec![1, -2], vec![0, 4]],
    );
    // T=[[1,1],[0,1]], A'=TA, B'=BT^-1; integer invertible basis.
    let sum = a0.iter().zip(&a1).map(|(x, y)| x + y).collect::<Vec<_>>();
    let changed = verify(
        &c,
        &[sum, a1.clone()],
        &[vec![2, 1], vec![1, -3], vec![0, 4]],
    );
    let sign = verify(
        &c,
        &[a0.iter().map(|v| -v).collect(), a1.clone()],
        &[vec![-2, 3], vec![-1, -2], vec![0, 4]],
    );
    let padding = verify(
        &c,
        &[a0.clone(), a1.clone(), vec![FACTOR_BOUND; COLUMNS]],
        &[vec![2, 3, 0], vec![1, -2, 0], vec![0, 4, 0]],
    );
    for copy in [changed, sign, padding] {
        assert!(first.same_declared_update(&copy));
        assert_eq!(first.delta(), copy.delta());
        assert_eq!(first.function_fingerprint(), copy.function_fingerprint());
        assert_ne!(first.artifact(), copy.artifact());
    }
    assert_eq!(first.factor_coefficients(), 520);
    assert_eq!(first.product_multiplications(), 1542);
}

#[test]
fn parent_slot_family_numeric_and_adapter_context_are_closed() {
    let c = context();
    assert_eq!(
        IntegerLinearContextV1::decode(&c.canonical_bytes()).unwrap(),
        c
    );
    let a = [vec![1; COLUMNS]];
    let b = [vec![1], vec![0], vec![0]];
    let first = verify(&c, &a, &b);
    for other in [
        IntegerLinearContextV1::new(INTEGER_LINEAR_FAMILY_V1, [4; 32], 0).unwrap(),
        IntegerLinearContextV1::new(INTEGER_LINEAR_FAMILY_V1, [3; 32], 1).unwrap(),
    ] {
        let checked = verify(&other, &a, &b);
        assert!(!first.same_declared_update(&checked));
        assert_ne!(first.function_fingerprint(), checked.function_fingerprint());
        assert_eq!(
            verify_integer_linear_v1(&other, &adapter(&c, &a, &b), MAX_MULTIPLICATIONS),
            Err(IntegerLinearErrorV1::Context)
        );
    }
    assert_eq!(
        IntegerLinearContextV1::new([0; 32], [3; 32], 0),
        Err(IntegerLinearErrorV1::Family)
    );
    assert_eq!(
        IntegerLinearContextV1::new(INTEGER_LINEAR_FAMILY_V1, [3; 32], 3),
        Err(IntegerLinearErrorV1::Slot)
    );
    for replacement in ["1023", "2048", "true", "1024.0"] {
        let raw = String::from_utf8(c.canonical_bytes())
            .unwrap()
            .replace("\"scale\":1024", &format!("\"scale\":{replacement}"));
        assert!(IntegerLinearContextV1::decode(raw.as_bytes()).is_err());
    }
}

#[test]
fn malformed_factor_bytes_and_unbounded_work_refuse() {
    let c = context();
    let raw = adapter(&c, &[vec![1; COLUMNS]], &[vec![1], vec![0], vec![0]]);
    for changed in [
        raw[..raw.len() - 1].to_vec(),
        [raw.as_slice(), b"\n"].concat(),
        b"{}".to_vec(),
        vec![b' '; MAX_ADAPTER_BYTES + 1],
    ] {
        assert!(verify_integer_linear_v1(&c, &changed, MAX_MULTIPLICATIONS).is_err());
    }
    let text = String::from_utf8(raw.clone()).unwrap();
    for value in ["01", "-0", "true", "1.0", "32768", "9223372036854775808"] {
        let changed = text.replacen("[[1,", &format!("[[{value},"), 1);
        assert!(verify_integer_linear_v1(&c, changed.as_bytes(), MAX_MULTIPLICATIONS).is_err());
    }
    let duplicate = text.replace("\"B\":", "\"A\":[],\"B\":");
    assert!(verify_integer_linear_v1(&c, duplicate.as_bytes(), MAX_MULTIPLICATIONS).is_err());
    assert_eq!(
        verify_integer_linear_v1(&c, &raw, MIN_MULTIPLICATIONS - 1),
        Err(IntegerLinearErrorV1::WorkBudget)
    );
    assert_eq!(
        verify_integer_linear_v1(&c, &raw, MAX_MULTIPLICATIONS + 1),
        Err(IntegerLinearErrorV1::WorkBudget)
    );
    for rank in [0, MAX_RANK + 1] {
        assert!(verify_integer_linear_v1(
            &c,
            &adapter(
                &c,
                &vec![vec![1; COLUMNS]; rank],
                &vec![vec![1; rank]; ROWS]
            ),
            MAX_MULTIPLICATIONS
        )
        .is_err());
    }
    assert_eq!(
        verify_integer_linear_v1(
            &c,
            &adapter(&c, &vec![vec![1; COLUMNS]; 2], &vec![vec![1; 2]; ROWS]),
            MIN_MULTIPLICATIONS
        ),
        Err(IntegerLinearErrorV1::WorkBudget)
    );
}

#[test]
fn full_product_cancellation_checks_i64_before_delta_bound() {
    let c = context();
    let a = vec![vec![FACTOR_BOUND; COLUMNS]; 8];
    let b = vec![
        vec![
            FACTOR_BOUND,
            FACTOR_BOUND,
            FACTOR_BOUND,
            FACTOR_BOUND,
            -FACTOR_BOUND,
            -FACTOR_BOUND,
            -FACTOR_BOUND,
            -FACTOR_BOUND
        ];
        3
    ];
    let cancellation = verify(&c, &a, &b);
    assert_eq!(cancellation.delta(), &[[0; COLUMNS]; ROWS]);
    assert_eq!(cancellation.product_multiplications(), MAX_MULTIPLICATIONS);
    assert_eq!(
        verify_integer_linear_v1(
            &c,
            &adapter(
                &c,
                &[vec![FACTOR_BOUND; COLUMNS]],
                &[vec![FACTOR_BOUND], vec![0], vec![0]]
            ),
            MAX_MULTIPLICATIONS
        ),
        Err(IntegerLinearErrorV1::DeltaBound)
    );
}

#[test]
fn perturbation_and_complementary_updates_are_not_collapsed() {
    let c = context();
    let mut a = vec![0; COLUMNS];
    a[0] = 1;
    let mut other = vec![0; COLUMNS];
    other[1] = 1;
    let b = [vec![0], vec![5], vec![0]];
    let first = verify(&c, &[a.clone()], &b);
    let second = verify(&c, &[other.clone()], &b);
    assert!(!first.same_declared_update(&second));
    let perturbation = verify(&c, &[a.clone()], &[vec![0], vec![6], vec![0]]);
    assert!(!first.same_declared_update(&perturbation));
    let joint = verify(&c, &[a, other], &[vec![0, 0], vec![5, 5], vec![0, 0]]);
    for i in 0..ROWS {
        for j in 0..COLUMNS {
            assert_eq!(
                joint.delta()[i][j],
                first.delta()[i][j] + second.delta()[i][j]
            );
        }
    }
    assert!(!joint.same_declared_update(&first));
    const { assert!(!CONSENSUS_AUTHORITY && !ECONOMIC_AUTHORITY && !GENERAL_MODEL_EQUIVALENCE) };
}
