// Uses the already frozen literal and independent Rust fixture inserts.
fn main() {
    let mut out=io::BufWriter::new(io::stdout().lock());
    for after in [0,63,66] {
        let db=fixture(66,None,&[]);
        let tx=db.db.unchecked_transaction().unwrap();
        let mut all=Vec::new();
        {
            let mut stmt=tx.prepare(SELECT_TEXT).unwrap();
            assert_eq!(stmt.column_count(),11);
            let mut rows=stmt.query(params![id(66).as_slice(),id(after).as_slice(),
                                             id(0).as_slice(),ANCESTOR_BATCH]).unwrap();
            while let Some(row)=rows.next().unwrap() {
                let mut projected=Vec::new();
                for i in 0..11 {
                    let (class,bytes)=value(row,i);
                    put(&mut projected,class);
                    put(&mut projected,bytes.len() as u64);
                    projected.extend(bytes);
                }
                all.push(projected);
            }
        }
        let count=all.len();
        assert_eq!(count,(66-after as usize).min(ANCESTOR_BATCH as usize));
        assert_eq!(tx.transaction_state(Some("main")).unwrap(),rusqlite::TransactionState::Read);
        // Separate original private reader confirms the same synthetic query
        // outcome; its queue is not used in the projected result.
        let mut history=VecDeque::new();
        let observed=db.history_page_ancestors(id(66),id(after),&mut history,16,&inline_record);
        if count==0 {
            assert_eq!(status(&observed.unwrap_err()),40);
        } else {
            assert_eq!(observed.unwrap(),(id(66-count as u64),count as u64));
        }
        tx.commit().unwrap();
        db.db.close().unwrap();
        let length=8+all.iter().map(Vec::len).sum::<usize>();
        out.write_all(&(length as u64).to_le_bytes()).unwrap();
        out.write_all(&(count as u64).to_le_bytes()).unwrap();
        for row in all {out.write_all(&row).unwrap();}
    }
}
