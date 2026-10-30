use super::{ConstraintSystem, LcIndex, LinearCombination, Variable};
use ark_test_curves::bls12_381::Fr;

fn ordered_variables() -> [Variable; 11] {
    use Variable::*;
    [
        Zero,
        One,
        Instance(0),
        Instance(1),
        Instance(usize::MAX),
        Witness(0),
        Witness(1),
        Witness(usize::MAX),
        SymbolicLc(LcIndex(0)),
        SymbolicLc(LcIndex(1)),
        SymbolicLc(LcIndex(usize::MAX)),
    ]
}

#[test]
fn variable_order_is_total_for_every_variant_and_index_boundary() {
    let variables = ordered_variables();
    for (i, left) in variables.iter().enumerate() {
        for (j, right) in variables.iter().enumerate() {
            let expected = i.cmp(&j);
            assert_eq!(
                left.cmp(right),
                expected,
                "{left:?} compared with {right:?}"
            );
            assert_eq!(left.partial_cmp(right), Some(expected));
            assert_eq!(left == right, i == j);
            assert_eq!(left.cmp(right), right.cmp(left).reverse());
            for middle in &variables {
                if left <= middle && middle <= right {
                    assert!(left <= right, "{left:?} <= {middle:?} <= {right:?}");
                }
            }
        }
    }
}

#[test]
fn compactify_merges_repeated_constants_and_preserves_coefficients() {
    let variables = ordered_variables();
    let mut combination = LinearCombination::<Fr>(
        variables
            .iter()
            .rev()
            .map(|variable| (Fr::from(1u64), *variable))
            .chain(variables.iter().map(|variable| (Fr::from(2u64), *variable)))
            .collect(),
    );
    combination.compactify();
    assert_eq!(combination.0.len(), variables.len());
    for ((coefficient, variable), expected) in combination.0.iter().zip(variables) {
        assert_eq!(*variable, expected);
        assert_eq!(*coefficient, Fr::from(3u64));
    }
}

#[test]
fn transform_lc_map_accepts_borrowed_state() {
    let mut cs = ConstraintSystem::<Fr>::new();
    let variable = cs.new_lc(LinearCombination::from(Variable::One)).unwrap();
    let coefficient = Fr::from(3u64);
    let mut visits = 0;
    cs.transform_lc_map(&mut |_, _, combination| {
        visits += 1;
        *combination *= coefficient;
        (0, None)
    });
    assert_eq!(visits, 1);
    assert_eq!(cs.assigned_value(variable), Some(coefficient));
}
