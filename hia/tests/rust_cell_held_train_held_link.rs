// Appended only to the private source-pinned CTRX referee. No Rust object
// address (model/rows/features/products) enters the Selfhost byte ABI.

unsafe extern "C" {
    #[link_name = "f0"]
    fn trnm_held_train_native(
        raw: *const u8, raw_len: usize, out: *mut u8, out_len: usize,
        arena: *mut u8, arena_len: usize,
    ) -> u64;
}

fn frame_from_held(a:&OwnerAdmission, features:&[Vec<i64>], products:&[Vec<i64>]) -> Vec<u8> {
    let n=a.inputs.len();
    assert!((1..=MAX_BATCH).contains(&n) && features.len()==n
        && products.len()==15 && products.iter().all(|p|p.len()==n));
    let tr=a.policy.training.as_ref().unwrap();
    let mut out=b"CTRX0001".to_vec();
    let mut put=|w:u64|out.extend_from_slice(&w.to_le_bytes());
    for w in [n as u64,0,u64::from(a.before.optimizer.is_some()),
        a.before.optimizer.as_ref().map_or(0,|o|o.step),tr.learning_rate_num,
        tr.learning_rate_den,tr.momentum_num,tr.momentum_den,tr.clip_abs] { put(w); }
    for w in a.model.base.iter().chain(a.model.deltas.iter().flatten()).flatten() { put(*w as u64); }
    match a.before.optimizer.as_ref() {
        Some(o)=>for w in o.base.iter().chain(o.deltas.iter().flatten()).flatten() { put(*w as u64); },
        None=>for _ in 0..4*3*DIM { put(0); }
    }
    for w in tr.trainable_mask.base.iter().chain(tr.trainable_mask.deltas.iter().flatten()).flatten() {
        put(u64::from(*w));
    }
    put(a.before.remaining_steps);
    for w in &a.before.memory { put(*w as u64); }
    for (k,row) in features.iter().enumerate() {
        let mask=a.policy.expert_mask[k].iter().enumerate().map(|(j,&on)|u64::from(on)<<j).sum();
        put(mask);
        put(u64::from(a.inputs[k].label));
        for lane in products { put(lane[k] as u64); }
        for &w in row { put(w as u64); }
    }
    assert_eq!(out.len(),74128+2192*n);
    out
}

fn compare_while_held(a:&OwnerAdmission, features:&[Vec<i64>], products:&[Vec<i64>],
                      external:&[u8], status:u8, original:&[u8], rows:&[u8]) {
    let loan=frame_from_held(a,features,products);
    assert_eq!(loan,external,"projection differs from independent input frame");
    let live=(a.before.remaining_steps.min(a.inputs.len() as u64)) as usize;
    let out_n=154280+104*live;
    let arena_n=if live==0 {out_n} else {262144+2096*live};
    assert!(loan.len()<=214416 && out_n<=160936 && arena_n<=396288);
    assert_eq!(original.len(),if status==0 {out_n} else {0});
    assert_eq!(rows.len(),if status==0 {2096*live} else {0});
    let mut out=vec![0x71;out_n+11];
    let mut arena=vec![0x92;arena_n+13];
    // Only three non-overlapping, sized Vec allocations are passed. The exact
    // stock native object owns no imports and receives no Rust typed pointers.
    let code=unsafe {
        trnm_held_train_native(loan.as_ptr(),loan.len(),out.as_mut_ptr(),out_n,
                               arena.as_mut_ptr(),arena_n)
    };
    assert_eq!(code,u64::from(status),"full packed native return differs");
    assert_eq!(&out[..original.len()],original);
    assert!(out[original.len()..].iter().all(|&b|b==0x71));
    assert!(arena[arena_n..].iter().all(|&b|b==0x92));
    if status==0 {
        assert_eq!(&arena[..out_n],original);
        if live>0 {
            assert!(arena[out_n..262144].iter().all(|&b|b==0x92));
            assert_eq!(&arena[262144..arena_n],rows);
        }
    } else if status==201 {
        assert!(arena.iter().all(|&b|b==0x92));
    } else {
        assert_eq!(status,203);
        let first_update=30848+80*live+32;
        assert!(arena[first_update..first_update+40].iter().any(|&b|b!=0x92));
        let last_update=30848+80*live+123392-40;
        assert!(arena[last_update..last_update+40].iter().all(|&b|b==0x92));
    }
    assert_eq!(loan,external,"immutable frame changed");
    assert_eq!(frame_from_held(a,features,products),loan,"held typed residents changed");
}
