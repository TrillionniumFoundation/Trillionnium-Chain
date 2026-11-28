// Private static qualification while the same synthetic SQLite snapshot is held.
unsafe extern "C" {
    #[link_name = "f0"]
    fn held_two_batch_native(
        input: *const u8, input_n: usize, out: *mut u8, out_n: usize,
        arena: *mut u8, arena_n: usize,
    ) -> u64;
}

fn compare_two_batch_while_held(tx:&rusqlite::Transaction<'_>,frame:&[u8],code:u64,expected:&[u8]) {
    use rusqlite::TransactionState::Read;
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),Read);
    assert!(!tx.is_autocommit());
    let writes=tx.total_changes();
    assert!(frame.starts_with(b"HPT00001") && (144..=71_408).contains(&frame.len()));
    assert!(expected.len()<=536 && (code==0 || expected.is_empty()));
    let captured=frame.to_vec();
    let mut output=[0xb9u8;549];
    let mut scratch=[0x71u8;529];
    let out_cap=if code==0 {expected.len()} else {541};
    // The borrowed projection remains live. No SQLite handle or filesystem
    // path reaches native code; the three buffers do not overlap.
    let observed=unsafe {
        held_two_batch_native(frame.as_ptr(),frame.len(),output.as_mut_ptr(),out_cap,
                              scratch.as_mut_ptr(),512)
    };
    assert_eq!(observed,code);
    assert_eq!(&output[..expected.len()],expected);
    assert!(output[expected.len()..].iter().all(|&v|v==0xb9));
    assert!(scratch[512..].iter().all(|&v|v==0x71));
    if code==0 && frame.len()==71_408 {
        assert_eq!(u64::from_le_bytes(output[..8].try_into().unwrap()),128);
    }
    assert_eq!(frame,captured);
    assert_eq!(tx.total_changes(),writes);
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),Read);
    assert!(!tx.is_autocommit());
}
