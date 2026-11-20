// Appended to an exact original store.rs prefix only in the isolated oracle.
pub fn qualification_store_io(method:u64,path:PathBuf)->AgentMarketResultV1<Vec<u8>>{
    if method==3 {require_existing_regular_store(&path)?;return Ok(Vec::new());}
    if method==4 {reject_sidecars(&path)?;return Ok(Vec::new());}
    let connection=match method {0=>open_ro_raw(&path)?,1=>open_rw_raw(&path,false)?,2=>open_rw_raw(&path,true)?,_=>unreachable!()};
    let mut out=Vec::new();
    for sql in ["PRAGMA foreign_keys","PRAGMA synchronous","PRAGMA busy_timeout"] {
        let value:u64=connection.query_row(sql,[],|row|row.get(0))?;
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}
