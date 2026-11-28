use super::*;

fn model(d: u32, m: u32) -> PftModelDescriptorV1 {
    PftModelDescriptorV1 {
        schema: MODEL_SCHEMA.into(),
        family: FAMILY.into(),
        numeric_profile: PROFILE.into(),
        candidate_sha256: [1; 32],
        contract_sha256: [2; 32],
        head: [3; 32],
        weight_sha256: [4; 32],
        feature_program_sha256: [5; 32],
        normalization_sha256: [6; 32],
        time_semantics_sha256: [7; 32],
        dimension: d,
        outputs: m,
    }
}

fn input(m: &PftModelDescriptorV1, rows: u32) -> PftInputDescriptorV1 {
    PftInputDescriptorV1 {
        schema: INPUT_SCHEMA.into(),
        candidate_sha256: m.candidate_sha256,
        weight_sha256: m.weight_sha256,
        contract_sha256: m.contract_sha256,
        feature_program_sha256: m.feature_program_sha256,
        normalization_sha256: m.normalization_sha256,
        time_semantics_sha256: m.time_semantics_sha256,
        request_id: [8; 32],
        source_sha256: [9; 32],
        row_ids_sha256: [10; 32],
        feature_packet_sha256: [11; 32],
        rows,
        dimension: m.dimension,
    }
}

fn wire(values: &[f64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn compute(x: &[f64], w: &[f64]) -> Result<PftPredictionV1> {
    let m = model(x.len() as u32, 1);
    let w = wire(w);
    let prepared = PreparedPftReadoutV1::prepare(&m, &w, &m, &w)?;
    let i = input(&m, 1);
    let x = wire(x);
    let i = prepared.prepare_input(&i, &x, &i, &x)?;
    prepared.predict(&i)
}

fn sum_bits(values: &[f64]) -> Result<u64> {
    compute(values, &vec![1.0; values.len()]).map(|p| p.values()[0].to_bits())
}

#[test]
fn known_ieee_octets_and_row_major_orientation() {
    let m = model(2, 3);
    let weights = wire(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
    let p = PreparedPftReadoutV1::prepare(&m, &weights, &m, &weights).unwrap();
    let i = input(&m, 2);
    let x = wire(&[1.0, 2.0, -1.0, 0.0]);
    let i = p.prepare_input(&i, &x, &i, &x).unwrap();
    let result = p.predict(&i).unwrap();
    // Independently specified IEEE encodings for [9,12,15,-1,-2,-3].
    let expected = [
        0x4022_0000_0000_0000_u64,
        0x4028_0000_0000_0000,
        0x402e_0000_0000_0000,
        0xbff0_0000_0000_0000,
        0xc000_0000_0000_0000,
        0xc008_0000_0000_0000,
    ];
    assert_eq!(result.shape(), [2, 3]);
    assert_eq!(
        result.to_le_bytes(),
        expected
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>()
    );
    let transposed = wire(&[1.0, 4.0, 2.0, 5.0, 3.0, 6.0]);
    assert_eq!(
        PreparedPftReadoutV1::prepare(&m, &transposed, &m, &weights).err(),
        Some(PftErrorV1::InputConsistency)
    );
}

#[test]
fn large_cancellation_and_intermediate_overflow_are_exact() {
    let large = f64::from_bits(0x7e70_0000_0000_0000); // 2^1000.
    assert_eq!(sum_bits(&[large, 1.0, -large]), Ok(0x3ff0_0000_0000_0000));
    assert_eq!(sum_bits(&[-large, -1.0, large]), Ok(0xbff0_0000_0000_0000));
    // Python fsum can reject this intermediate overflow; this new profile does not.
    assert_eq!(
        sum_bits(&[f64::MAX, f64::MAX, -f64::MAX]),
        Ok(0x7fef_ffff_ffff_ffff)
    );
    let mut terms = vec![f64::MAX; 1024];
    assert_eq!(sum_bits(&terms), Err(PftErrorV1::SumOverflow));
    terms[512..].fill(-f64::MAX);
    assert_eq!(sum_bits(&terms), Ok(0));
}

#[test]
fn small_tail_and_halfway_ties_are_nearest_even() {
    let half = f64::from_bits(0x3ca0_0000_0000_0000); // 2^-53.
    let tail = f64::from_bits(0x3c90_0000_0000_0000); // 2^-54.
    let odd = f64::from_bits(0x3ff0_0000_0000_0001);
    assert_eq!(sum_bits(&[1.0, half]), Ok(0x3ff0_0000_0000_0000));
    assert_eq!(sum_bits(&[odd, half]), Ok(0x3ff0_0000_0000_0002));
    assert_eq!(sum_bits(&[-odd, -half]), Ok(0xbff0_0000_0000_0002));
    assert_eq!(sum_bits(&[1.0, half, tail]), Ok(0x3ff0_0000_0000_0001));
    assert_eq!(
        sum_bits(&[f64::from_bits(0x3fff_ffff_ffff_ffff), half]),
        Ok(0x4000_0000_0000_0000)
    );
}

#[test]
fn ordering_does_not_lose_small_remainders() {
    let big = f64::from_bits(0x7e70_0000_0000_0000);
    let half = f64::from_bits(0x3ca0_0000_0000_0000);
    let tail = f64::from_bits(0x3c90_0000_0000_0000);
    for terms in [
        [big, 1.0, -big, half, tail],
        [tail, half, -big, 1.0, big],
        [-big, big, tail, half, 1.0],
        [1.0, tail, big, half, -big],
    ] {
        assert_eq!(sum_bits(&terms), Ok(0x3ff0_0000_0000_0001));
    }
}

#[test]
fn product_rounding_is_separate_from_exact_sum() {
    // (1+2^-27)*(1-2^-27) rounds to 1 before -1 is added. FMA would differ.
    let a = f64::from_bits(0x3ff0_0000_0200_0000);
    let b = f64::from_bits(0x3fef_ffff_fc00_0000);
    assert_eq!(
        compute(&[a, -1.0], &[b, 1.0]).unwrap().values()[0].to_bits(),
        0
    );
    assert_eq!(
        compute(&[f64::MAX], &[2.0]).err(),
        Some(PftErrorV1::ProductOverflow)
    );
    for factor in [0.5, f64::MIN_POSITIVE] {
        assert_eq!(
            compute(&[f64::MIN_POSITIVE], &[factor]).err(),
            Some(PftErrorV1::ProductUnderflow)
        );
    }
}

#[test]
fn final_range_and_signed_zero_are_explicit() {
    assert_eq!(sum_bits(&[-0.0, 0.0, -0.0]), Ok(0));
    assert_eq!(sum_bits(&[1.0, -1.0]), Ok(0));
    assert_eq!(sum_bits(&[f64::MIN_POSITIVE]), Ok(0x0010_0000_0000_0000));
    assert_eq!(
        sum_bits(&[f64::from_bits(0x0010_0000_0000_0001), -f64::MIN_POSITIVE]),
        Err(PftErrorV1::SumUnderflow)
    );
    assert_eq!(
        sum_bits(&[f64::MAX, f64::from_bits(0x7c90_0000_0000_0000)]),
        Err(PftErrorV1::SumOverflow)
    ); // Exact half-ULP rounds past maximum finite.
    assert_eq!(
        sum_bits(&[f64::MAX, f64::from_bits(0x7c80_0000_0000_0000)]),
        Ok(0x7fef_ffff_ffff_ffff)
    );
}

#[test]
fn nonfinite_and_subnormal_inputs_refuse_before_prediction() {
    for value in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::from_bits(1),
    ] {
        assert_eq!(
            compute(&[value], &[1.0]).err(),
            Some(PftErrorV1::NumericInput)
        );
        assert_eq!(
            compute(&[1.0], &[value]).err(),
            Some(PftErrorV1::NumericInput)
        );
    }
}

#[test]
fn schema_family_profile_and_comparison_pins_are_separate() {
    let m = model(1, 1);
    let weights = wire(&[1.0]);
    for field in 0..5 {
        let mut changed = m.clone();
        match field {
            0 => changed.schema = "pon-cell-stateful-native-int257-v1/model".into(),
            1 => changed.family = "int257".into(),
            2 => changed.numeric_profile = "python-math-fsum".into(),
            3 => changed.contract_sha256 = [0; 32],
            _ => changed.head = [0; 32],
        }
        assert_eq!(
            PreparedPftReadoutV1::prepare(&changed, &weights, &changed, &weights).err(),
            Some(PftErrorV1::Contract)
        );
    }
    let mut changed = m.clone();
    changed.head = [99; 32];
    assert_eq!(
        PreparedPftReadoutV1::prepare(&changed, &weights, &m, &weights).err(),
        Some(PftErrorV1::InputConsistency)
    );
    assert_eq!(
        PreparedPftReadoutV1::prepare(&m, &wire(&[-0.0]), &m, &wire(&[0.0])).err(),
        Some(PftErrorV1::InputConsistency)
    );
}

#[test]
fn all_shape_boundaries_and_exact_byte_lengths_are_enforced() {
    for (d, m) in [(0, 1), (1025, 1), (1, 0), (1, 33), (u32::MAX, u32::MAX)] {
        let m = model(d, m);
        assert_eq!(
            PreparedPftReadoutV1::prepare(&m, &[], &m, &[]).err(),
            Some(PftErrorV1::Shape)
        );
    }
    let m = model(1, 1);
    for bytes in [vec![], vec![0; 7], vec![0; 9]] {
        assert_eq!(
            PreparedPftReadoutV1::prepare(&m, &bytes, &m, &bytes).err(),
            Some(PftErrorV1::Shape)
        );
    }
    let weights = wire(&[1.0]);
    let p = PreparedPftReadoutV1::prepare(&m, &weights, &m, &weights).unwrap();
    for rows in [0, 257, u32::MAX] {
        let i = input(&m, rows);
        assert_eq!(
            p.prepare_input(&i, &[], &i, &[]).err(),
            Some(PftErrorV1::Shape)
        );
    }
    let m = model(1024, 32);
    let w = vec![0; 1024 * 32 * 8];
    let p = PreparedPftReadoutV1::prepare(&m, &w, &m, &w).unwrap();
    let i = input(&m, 256);
    let x = vec![0; 256 * 1024 * 8];
    let i = p.prepare_input(&i, &x, &i, &x).unwrap();
    assert_eq!(p.predict(&i).unwrap().shape(), [256, 32]);
}

#[test]
fn feature_contract_request_row_order_and_source_are_pinned() {
    let m = model(1, 1);
    let w = wire(&[1.0]);
    let p = PreparedPftReadoutV1::prepare(&m, &w, &m, &w).unwrap();
    let expected = input(&m, 1);
    for field in 0..8 {
        let mut i = expected.clone();
        let code = match field {
            0 => {
                i.normalization_sha256 = [99; 32];
                PftErrorV1::Contract
            }
            1 => {
                i.feature_program_sha256 = [99; 32];
                PftErrorV1::Contract
            }
            2 => {
                i.time_semantics_sha256 = [99; 32];
                PftErrorV1::Contract
            }
            3 => {
                i.candidate_sha256 = [99; 32];
                PftErrorV1::Contract
            }
            4 => {
                i.request_id = [0; 32];
                PftErrorV1::Contract
            }
            5 => {
                i.source_sha256 = [99; 32];
                PftErrorV1::InputConsistency
            }
            6 => {
                i.row_ids_sha256 = [99; 32];
                PftErrorV1::InputConsistency
            }
            _ => {
                i.feature_packet_sha256 = [99; 32];
                PftErrorV1::InputConsistency
            }
        };
        assert_eq!(p.prepare_input(&i, &w, &expected, &w).err(), Some(code));
    }
}

#[test]
fn owned_bytes_and_instance_binding_prevent_later_substitution() {
    let m = model(1, 1);
    let mut w = wire(&[2.0]);
    let p = PreparedPftReadoutV1::prepare(&m, &w, &m, &w).unwrap();
    let i = input(&m, 1);
    let mut x = wire(&[3.0]);
    let prepared = p.prepare_input(&i, &x, &i, &x).unwrap();
    w.fill(0);
    x.fill(0);
    assert_eq!(p.predict(&prepared).unwrap().values(), &[6.0]);
    // A dishonest caller can reuse every label with different expected bytes.
    // That still cannot make a distinct prepared model consume this handle.
    let other_bytes = wire(&[9.0]);
    let other = PreparedPftReadoutV1::prepare(&m, &other_bytes, &m, &other_bytes).unwrap();
    assert_eq!(
        other.predict(&prepared).err(),
        Some(PftErrorV1::InputConsistency)
    );
    assert_eq!(
        p.prepare_input(&i, &wire(&[4.0]), &i, &wire(&[3.0])).err(),
        Some(PftErrorV1::InputConsistency)
    );
}
