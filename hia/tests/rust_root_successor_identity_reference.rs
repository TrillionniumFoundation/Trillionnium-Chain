//! Inert public RootStatement V3 identity fixture; never signs or applies.
#[allow(dead_code)]
#[path = "rust_root_recovery_checkpoint_reference.rs"]
mod fixture;
use std::io::{self, Write};
use trnm_release_bundle::root_recovery_v3::{RootActionV3 as A, RootErrorV3 as E,
    RootPolicyV3 as P, RootStatementV3 as S};

fn row(w: &mut impl Write, wire: &[u8]) {
    let result = S::decode(wire).and_then(|s| {
        assert_eq!(s.encode().unwrap(), wire);
        assert!(s.action.successor().is_some());
        s.operation_id()
    });
    let (status, out) = match result {
        Ok(bytes) => (0, bytes.to_vec()),
        Err(E::Context) => (9, vec![]),
        Err(e) => (fixture::status(e), vec![]),
    };
    w.write_all(&status.to_le_bytes()).unwrap();
    w.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    w.write_all(wire).unwrap();
    w.write_all(&out).unwrap();
}
fn main() {
    let mut w = io::stdout().lock();
    let p = P{roster: fixture::roster(3), expires_at_unix:65536};
    let s = S { scope:[1;64], generation:3, sequence:256,
        predecessor:[2;64], nonce:[3;32], valid_from_unix:255,
        expires_at_unix:256, action:A::Rotate{next:p.clone()} };
    let rotate = s.encode().unwrap();
    row(&mut w,&rotate);
    let recover = S{action:A::Recover{next:p.clone()},..s.clone()}.encode().unwrap();
    row(&mut w,&recover);
    let change = S{action:A::PolicyChange{next:p.clone()},..s.clone()}.encode().unwrap();
    row(&mut w,&change);
    let successor = P{roster:fixture::roster(17),expires_at_unix:65536};
    row(&mut w,&S{action:A::Rotate{next:successor},..s.clone()}.encode().unwrap());
    row(&mut w,&S{sequence:257,..s.clone()}.encode().unwrap());
    row(&mut w,&S{valid_from_unix:u64::MAX-1,expires_at_unix:u64::MAX,..s}.encode().unwrap());

    let mut bad=rotate.clone();
    bad[107..115].fill(0);
    row(&mut w,&bad); // zero generation, original Context
    let mut bad=rotate.clone();
    bad[219..227].copy_from_slice(&256u64.to_be_bytes());
    row(&mut w,&bad); // equal endpoint, original Context
    let mut bad=rotate.clone();
    bad[268..276].fill(0);
    row(&mut w,&bad); // original nested policy expiry failure
    let mut bad=rotate.clone();
    bad[236..240].copy_from_slice(&16385u32.to_be_bytes());
    row(&mut w,&bad); // original nested extent cap
    row(&mut w,&rotate[..rotate.len()-1]);
    let mut bad=rotate.clone();
    bad.push(0);
    row(&mut w,&bad);
    let mut bad=rotate.clone();
    bad[187..219].fill(0); // invalid outer nonce
    bad[314]=9; // unknown fixed roster family has earlier priority
    row(&mut w,&bad);
}
