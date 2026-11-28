// Appended only to the exact private CCT test driver. Native receives
// the canonical byte extent, not Rust pointers to typed fixture values.

unsafe extern "C" {
    #[link_name = "f0"]
    fn trnm_cell_source_train_native(
        input: *const u8, input_n: usize, output: *mut u8, output_n: usize,
        arena: *mut u8, arena_n: usize,
    ) -> u64;
}

fn cct_rebuild(a:&OwnerAdmission)->Vec<u8> {
    let n=a.inputs.len();
    let n_coord=4*CLASSES.len()*DIM;
    let mut out=b"CCT00001".to_vec();
    let tr=a.policy.training.as_ref().unwrap();
    let opt=a.before.optimizer.as_ref();
    fn put(out:&mut Vec<u8>,word:u64) { out.extend_from_slice(&word.to_le_bytes()); }
    for v in [n as u64,0,u64::from(opt.is_some()),opt.map_or(0,|o|o.step),
              tr.learning_rate_num,tr.learning_rate_den,tr.momentum_num,
              tr.momentum_den,tr.clip_abs] { put(&mut out,v); }
    for w in a.model.base.iter().chain(a.model.deltas.iter().flatten()).flatten() {
        put(&mut out,*w as u64);
    }
    if let Some(o)=opt {
        for w in o.base.iter().chain(o.deltas.iter().flatten()).flatten() { put(&mut out,*w as u64); }
    } else {
        for _ in 0..n_coord { put(&mut out,0); }
    }
    for w in tr.trainable_mask.base.iter().chain(tr.trainable_mask.deltas.iter().flatten()).flatten() {
        put(&mut out,u64::from(*w));
    }
    put(&mut out,a.before.remaining_steps);
    for v in &a.before.memory { put(&mut out,*v as u64); }
    assert_eq!(out.len(),74128);
    for v in a.model.router.iter().flatten() { put(&mut out,*v as u64); }
    assert_eq!(out.len(),80296);
    out.extend(a.policy.feature_mask.iter().map(|x|u8::from(*x)));
    out.extend([0;7]);
    assert_eq!(out.len(),80560);
    for (j,s) in a.inputs.iter().enumerate() {
        let mask=a.policy.expert_mask[j].iter().enumerate().map(|(i,&b)|u64::from(b)<<i).sum();
        let text=s.content_hex.as_bytes();
        put(&mut out,text.len() as u64);
        put(&mut out,mask);
        put(&mut out,u64::from(s.label));
        out.extend_from_slice(text);
    }
    out
}

fn cct_compare_source_stages(trace:&[u8],arena:&[u8],n:usize) {
    assert_eq!(trace[0],0);
    assert_eq!(u32::from_le_bytes(trace[1..5].try_into().unwrap()) as usize,n);
    let mut offset=5;
    for j in 0..n {
        let size=word(trace,offset) as usize;
        assert!(size<=4096 && word(trace,offset+8)<=1024);
        let next=offset+4160+size;
        let row=396288+j*2192;
        let norm=536576+j*4096;
        let original=798720+j*2056;
        let header=930304+j*48;
        assert_eq!(&arena[header..header+48],&trace[offset..offset+48]);
        assert_eq!(&arena[original..original+2056],&trace[offset+48..offset+2104]);
        assert_eq!(&arena[row+136..row+2192],&trace[offset+2104..offset+4160]);
        assert_eq!(&arena[norm..norm+size],&trace[offset+4160..next]);
        assert!(arena[norm+size..norm+4096].iter().all(|&v|v==0x51));
        assert_eq!(&arena[row..row+136],&trace[next..next+136]);
        offset=next+136;
    }
    assert_eq!(offset,trace.len());
}

fn cct_compare_while_held(a:&OwnerAdmission,external:&[u8],trace:&[u8],status:u8,
                          report:&[u8],active:&[u8]) {
    let loan=cct_rebuild(a);
    assert_eq!(loan,external,"same held typed snippet/model frame differs");
    let active_len=a.before.remaining_steps.min(a.inputs.len() as u64) as usize;
    let out_n=154280+104*active_len;
    let arena_n=933376;
    assert!((80586..=606384).contains(&loan.len()) && out_n<=160936);
    assert_eq!(report.len(),if status==0 {out_n} else {0});
    assert_eq!(active.len(),if status==0 {2096*active_len} else {0});
    let mut output=vec![0xa9;out_n+13];
    let mut arena=vec![0x51;arena_n+11];
    // Three independently allocated, disjoint borrowed byte spans. Native
    // receives no address from the typed fixture, not even its Vec storage.
    let code=unsafe {
        trnm_cell_source_train_native(loan.as_ptr(),loan.len(),output.as_mut_ptr(),out_n,
                                    arena.as_mut_ptr(),arena_n)
    };
    assert_eq!(code,u64::from(status),"packed stock status differs");
    assert_eq!(&output[..report.len()],report);
    assert!(output[report.len()..].iter().all(|&v|v==0xa9));
    assert!(arena[arena_n..].iter().all(|&v|v==0x51));
    if !trace.is_empty() { cct_compare_source_stages(trace,&arena,a.inputs.len()); }
    if status==0 {
        assert_eq!(&arena[..report.len()],report);
        assert_eq!(&arena[262144..262144+active.len()],active);
        assert!(arena[262144+active.len()..396288].iter().all(|&v|v==0x51));
    } else if status==203 {
        let start=30848+80*active_len+32;
        let stop=start+123392-32;
        assert!(arena[start..start+40].iter().any(|&v|v!=0x51));
        assert!(arena[stop-40..stop].iter().all(|&v|v==0x51));
    } else {
        assert!([10,11,201].contains(&status));
        assert!(arena[262144..396288].iter().all(|&v|v==0x51));
    }
    assert_eq!(loan,external,"immutable native loan was mutated");
    assert_eq!(cct_rebuild(a),loan,"typed fixture changed before observation");
}
