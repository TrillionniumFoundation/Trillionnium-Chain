use rusqlite::Connection;
type Result<T> = rusqlite::Result<T>;
type ReadbackSchema=Vec<(String,String,String,String,i64,Option<String>)>;
fn readback_schema(db: &Connection) -> Result<Option<ReadbackSchema>> {
    // A configuration change is not necessarily an executed write: SQLite
    // applies some PRAGMAs at prepare time. Never qualify writable catalog mode.
    let writable: bool = db.query_row("PRAGMA writable_schema", [], |row| row.get(0))?;
    if writable {
        return Ok(None);
    }
    let mut databases = db.prepare("PRAGMA database_list")?;
    let mut rows = databases.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name != "main" && name != "temp" {
            return Ok(None);
        }
    }
    let temp_objects: u64 = db.query_row("SELECT COUNT(*) FROM temp.sqlite_master", [], |row| {
        row.get(0)
    })?;
    if temp_objects != 0 {
        return Ok(None);
    }
    let mut statement = db.prepare(
        "SELECT 'main',type,name,tbl_name,rootpage,sql FROM main.sqlite_master UNION ALL SELECT 'temp',type,name,tbl_name,rootpage,sql FROM temp.sqlite_master ORDER BY 1,2,3",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;
    Ok(Some(rows.collect::<rusqlite::Result<_>>()?))
}

fn cached_schema(db: &Connection) -> Result<Option<ReadbackSchema>> {
    // A configuration change is not necessarily an executed write: SQLite
    // applies some PRAGMAs at prepare time. Never qualify writable catalog mode.
    let writable: bool = db.query_row("PRAGMA writable_schema", [], |row| row.get(0))?;
    if writable {
        return Ok(None);
    }
    let mut databases = db.prepare("PRAGMA database_list")?;
    let mut rows = databases.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name != "main" && name != "temp" {
            return Ok(None);
        }
    }
    let temp_objects: u64 = db.query_row("SELECT COUNT(*) FROM temp.sqlite_master", [], |row| {
        row.get(0)
    })?;
    if temp_objects != 0 {
        return Ok(None);
    }
    let mut statement = db.prepare_cached(
        "SELECT 'main',type,name,tbl_name,rootpage,sql FROM main.sqlite_master UNION ALL SELECT 'temp',type,name,tbl_name,rootpage,sql FROM temp.sqlite_master ORDER BY 1,2,3",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;
    Ok(Some(rows.collect::<rusqlite::Result<_>>()?))
}

fn main() {
 let db=Connection::open_in_memory().unwrap();
 for i in 0..20 { db.execute_batch(&format!("CREATE TABLE table_{i}(key BLOB PRIMARY KEY,value BLOB);CREATE INDEX index_{i} ON table_{i}(value);")).unwrap(); }
 for round in 0..8 {
  for cached in if round%2==0 {[false,true]} else {[true,false]} {
   let start=std::time::Instant::now();
   for _ in 0..2000 {let value=if cached {cached_schema(&db)} else {readback_schema(&db)}.unwrap(); assert_eq!(value.as_ref().unwrap().len(),60);std::hint::black_box(value);}
   println!("round={round} cached={cached} ns={}",start.elapsed().as_nanos());
  }
 }
}
