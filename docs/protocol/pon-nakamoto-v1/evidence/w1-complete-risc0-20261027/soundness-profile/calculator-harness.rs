// Numerical descriptor harness only; not a cryptographic HAL or proof system.
extern crate self as risc0_core;
pub mod field {
    pub mod baby_bear { pub const P:u32=15*(1<<27)+1; }
    pub trait ExtElem { const EXT_SIZE:usize; }
}
pub mod adapter { pub const REGISTER_GROUP_ACCUM:usize=0; pub const REGISTER_GROUP_CODE:usize=1; pub const REGISTER_GROUP_DATA:usize=2; }
pub mod hal { pub trait Hal { type ExtElem:crate::field::ExtElem; } }
pub mod taps {
    pub struct TapSet { pub groups:[usize;3], pub combo_sizes:Vec<usize> }
    pub struct Combo(usize);
    impl Combo { pub fn size(&self)->usize { self.0 } }
    impl TapSet {
        pub fn group_size(&self,index:usize)->usize { self.groups[index] }
        pub fn combos(&self)->impl Iterator<Item=Combo>+'_ { self.combo_sizes.iter().map(|&n|Combo(n)) }
    }
}
pub const FRI_FOLD:usize=16; pub const FRI_MIN_DEGREE:usize=256; pub const INV_RATE:usize=4; pub const QUERIES:usize=50;
struct ExtensionDegree; impl field::ExtElem for ExtensionDegree { const EXT_SIZE:usize=4; }
struct CalculatorParameters; impl hal::Hal for CalculatorParameters { type ExtElem=ExtensionDegree; }
#[path="/workspace/scratch/20f5e808bfa5/pon-proof-artifacts/soundness-profile/upstream/risc0/zkp/src/prove/soundness.rs"] mod calculator;
fn main() {
    let taps=taps::TapSet { groups:[103, 1, 211], combo_sizes:vec![1, 2, 6, 5] };
    for argument in std::env::args().skip(1) {
        let po2:u32=argument.parse().unwrap(); assert!((13..=24).contains(&po2));
        let coefficients=(1usize<<po2)*4;
        let toy=calculator::toy_model_security::<CalculatorParameters>(&taps,coefficients);
        let proven=calculator::proven::<CalculatorParameters>(&taps,coefficients);
        let strict=calculator::conjectured_strict::<CalculatorParameters>(&taps,coefficients);
        println!("{{\"po2\":{},\"toy_model_bits\":{},\"proven_list_decoding_bits\":{},\"conjectured_strict_bits\":{}}}",po2,toy,proven,strict);
    }
}
