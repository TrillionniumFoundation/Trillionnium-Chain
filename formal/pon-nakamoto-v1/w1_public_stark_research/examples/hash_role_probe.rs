//! Forward-only check of independently generated inverse witnesses using exact P3 APIs.
//! Copy into the pinned full-W1 research crate's examples/hash_role_probe.rs.
//! cargo run --locked --release --example hash_role_probe
//! A primitive-model counterexample; this is not a Merkle or W1 forgery.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, default_goldilocks_poseidon2_8};
use p3_symmetric::{
    CryptographicHasher, PaddingFreeSponge, Permutation, PseudoCompressionFunction,
    TruncatedPermutation,
};

fn words<const N: usize>(input: [u64; N]) -> [Goldilocks; N] {
    input.map(Goldilocks::from_u64)
}
fn canonical<const N: usize>(input: [Goldilocks; N]) -> [u64; N] {
    input.map(|x| x.as_canonical_u64())
}
fn main() {
    let perm = default_goldilocks_poseidon2_8();
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    let compress = TruncatedPermutation::<_, 2, 4, 8>::new(perm.clone());
    let a = words([
        895525109234590730,
        2513871637543481359,
        6866580664439037727,
        12213085372619991112,
        5421210880553664044,
        10404719342431952033,
        758541627951963262,
        6961099732014900331,
    ]);
    let b = words([
        18007219444761515550,
        15576305404914934757,
        6343815722533953670,
        5593369638671632307,
        524455038159463593,
        15550145857063644192,
        3791585759269295459,
        6656745112379943842,
    ]);
    assert_ne!(a, b);
    assert_eq!(canonical(perm.permute(a)), [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(canonical(perm.permute(b)), [0, 1, 2, 3, 4, 5, 6, 8]);
    let ca = canonical(compress.compress([a[..4].try_into().unwrap(), a[4..].try_into().unwrap()]));
    let cb = canonical(compress.compress([b[..4].try_into().unwrap(), b[4..].try_into().unwrap()]));
    assert_eq!(ca, [0, 1, 2, 3]);
    assert_eq!(cb, ca);

    let row = words([11, 22, 33, 44]);
    let h4 = canonical(hash.hash_iter(row));
    assert_eq!(h4, canonical(compress.compress([row, words([0; 4])])));
    assert_eq!(
        h4,
        [
            2498895455050071425,
            14732045805774730310,
            10489624707904524498,
            8346550446195805760
        ]
    );
    let h2 = canonical(hash.hash_iter(words([11, 22])));
    assert_eq!(h2, canonical(hash.hash_iter(words([11, 22, 0, 0]))));
    assert_eq!(
        h2,
        [
            14060240337387336135,
            2328936029578056232,
            6742761464079187629,
            1300653439592473024
        ]
    );
    println!(
        "{{\"schema\":\"trnm-p3-hash-role-probe-v1\",\"actual_p3_api\":true,\"p3_version\":\"0.8.0\",\"arbitrary_compressor_collision\":true,\"h4_compressor_overlap\":true,\"h2_h4_overlap\":true,\"merkle_or_w1_forgery\":false,\"qualification\":\"HOLD_NO_GO\"}}"
    );
}
