// Private fixed replay inside the already-open synthetic SQLite read transaction.
unsafe extern "C" {
    #[link_name = "f0"]
    fn trnm_history_page_fold_native(
        raw: *const u8, raw_len: usize, out: *mut u8, out_len: usize,
        scratch: *mut u8, scratch_len: usize,
    ) -> u64;
}

fn compare_page_while_held(tx:&rusqlite::Transaction<'_>,name:&str,input:&[u8],code:u64,
                           report:&[u8],local:&[u8]) {
    use rusqlite::TransactionState::Read;
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),Read);
    assert!(!tx.is_autocommit());
    let changes=tx.total_changes();
    assert!((128..=35_456).contains(&input.len()));
    let baseline=input.to_vec();
    let count=u64::from_le_bytes(input[8..16].try_into().unwrap());
    assert!(count<=64 && report.len()<=584 && (32..=544).contains(&local.len()));
    let mut output=[0xb9u8; 599];
    let mut scratch=[0x71u8; 529];
    let exact=name=="full-batch-continuation";
    let cap=if exact {584} else {591};
    let arena=if exact {512} else {521};
    // Three nonoverlapping live byte arrays only. No SQLite handle, returned
    // pointer, callback, filesystem path, or shared writable buffer crosses.
    let status=unsafe {
        trnm_history_page_fold_native(input.as_ptr(),input.len(),output.as_mut_ptr(),cap,
                                      scratch.as_mut_ptr(),arena)
    };
    assert_eq!(status,code);
    assert_eq!(&output[..report.len()],report);
    assert!(output[report.len()..].iter().all(|&x| x==0xb9));
    assert!(scratch[512..].iter().all(|&x| x==0x71));
    assert_eq!(input,baseline);
    if code==0 {
        assert_eq!(&scratch[..report.len()-72],&report[72..]);
    } else {
        assert!(report.is_empty());
        if matches!(name,"missing-late"|"height-after-one") {
            assert_eq!(&scratch[..local.len()-32],&local[32..]);
        }
    }
    if exact {
        assert_eq!(count,64);
        assert_eq!((input.len(),report.len(),local.len()),(35456,584,544));
    }
    assert_eq!(tx.total_changes(),changes);
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),Read);
    assert!(!tx.is_autocommit());
}
