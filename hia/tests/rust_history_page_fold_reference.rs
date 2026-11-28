#![allow(dead_code)]
use std::cell::Cell;
use std::collections::VecDeque;
use std::error::Error as _;
use std::io::{self,Write};
use rusqlite::{params,types::{Value,ValueRef},Connection};
type Hash=[u8;32];
type Result<T>=std::result::Result<T,Error>;
include!("frozen.rs");

struct HeldSettings(Hash);
impl HeldSettings {
    fn genesis(&self)->Hash { self.0 }
}
struct HeldMemory {
    db:Connection,
    settings:HeldSettings,
    history_page_read_counters:Cell<HistoryPageReadCounters>,
}
impl HeldMemory {
    // EXACT_ORIGINAL_HISTORY_PAGE_ANCESTORS
}

const SELECT_TEXT:&str=
// EXACT_ORIGINAL_RECURSIVE_SQL
;

fn id(n:u64)->Hash {
    let mut h=[0x57;32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h
}
fn put(out:&mut Vec<u8>,word:u64) { out.extend_from_slice(&word.to_le_bytes()); }
fn value(row:&rusqlite::Row<'_>,n:usize)->(u64,Vec<u8>) {
    match row.get_ref(n).unwrap() {
        ValueRef::Null=>(0,Vec::new()),
        ValueRef::Integer(x)=>(1,x.to_le_bytes().to_vec()),
        ValueRef::Real(x)=>(2,x.to_le_bytes().to_vec()),
        ValueRef::Text(x)=>(3,x.to_vec()),
        ValueRef::Blob(x)=>(4,x.to_vec()),
    }
}
fn append_record(row:&rusqlite::Row<'_>,start:usize)->Vec<u8> {
    let mut packet=b"HIR1\0\0\0\0".to_vec();
    let cells=(start..start+4).map(|k|value(row,k)).collect::<Vec<_>>();
    for (kind,bytes) in &cells {
        put(&mut packet,*kind);
        put(&mut packet,bytes.len() as u64);
    }
    for (_,bytes) in cells { packet.extend(bytes); }
    packet
}
fn edge(row:&rusqlite::Row<'_>)->Vec<u8> {
    let mut packet=Vec::new();
    let scalars=[8,9,10].map(|k|value(row,k));
    for (kind,bytes) in &scalars {
        put(&mut packet,*kind);
        put(&mut packet,bytes.len() as u64);
    }
    let child=append_record(row,0);
    let parent=append_record(row,4);
    put(&mut packet,child.len() as u64);
    put(&mut packet,parent.len() as u64);
    for (_,bytes) in scalars { packet.extend(bytes); }
    packet.extend(child);
    packet.extend(parent);
    packet
}

type Change=(u64,usize,Value);
fn fixture(n:u64,missing:Option<u64>,changes:&[Change])->HeldMemory {
    let db=Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA temp_store=MEMORY; CREATE TABLE blocks(id BLOB PRIMARY KEY,parent,height,chainwork,state_root);").unwrap();
    for index in 0..=n {
        if missing==Some(index) { continue; }
        let mut cols=[
            if index==0 {Value::Null} else {Value::Blob(id(index-1).to_vec())},
            Value::Integer(index as i64),Value::Blob(vec![index as u8;64]),
            Value::Blob(vec![(index as u8)^0x5a;32]),
        ];
        for (which,k,v) in changes {
            if *which==index { cols[*k]=v.clone(); }
        }
        db.execute("INSERT INTO blocks(id,parent,height,chainwork,state_root) VALUES (?,?,?,?,?)",
                   params![id(index).as_slice(),cols[0],cols[1],cols[2],cols[3]]).unwrap();
    }
    db.execute_batch("PRAGMA query_only=ON;").unwrap();
    HeldMemory{db,settings:HeldSettings(id(0)),history_page_read_counters:Cell::new(HistoryPageReadCounters::default())}
}

fn status(e:&Error)->u64 {
    if let Some(source)=e.source().and_then(|x|x.downcast_ref::<rusqlite::Error>()) {
        assert!(e.requires_owner_stop());
        return match source {
            rusqlite::Error::InvalidColumnType(k,_,_) if *k<=3=>10+*k as u64,
            rusqlite::Error::InvalidColumnType(k,_,_) if *k<=7=>50+(*k as u64-4),
            rusqlite::Error::InvalidColumnType(8,_,_)=>22,
            rusqlite::Error::InvalidColumnType(9,_,_)=>23,
            rusqlite::Error::InvalidColumnType(10,_,_)=>25,
            rusqlite::Error::IntegralValueOutOfRange(1,_)=>14,
            rusqlite::Error::IntegralValueOutOfRange(5,_)=>54,
            rusqlite::Error::IntegralValueOutOfRange(9,_)=>24,
            other=>panic!("Unexpected SQLite origin: {other:?}"),
        };
    }
    match e.to_string().as_str() {
        "UNKNOWN_PARENT"=> if e.requires_owner_stop(){41}else{40},
        "ANCESTRY_HEIGHT"=>{assert!(e.requires_owner_stop());42},
        "STORAGE_HASH"=>{assert!(e.requires_owner_stop());30},
        "STORAGE_WORK"=>{assert!(e.requires_owner_stop());31},
        other=>panic!("Unexpected original status {other}"),
    }
}

fn capture(db:&HeldMemory,start:Hash,after:Hash,seed:&[Hash],limit:usize)->Vec<u8> {
    let mut statement=db.db.prepare_cached(SELECT_TEXT).unwrap();
    let mut rows=statement.query(params![
        start.as_slice(),after.as_slice(),db.settings.genesis().as_slice(),ANCESTOR_BATCH]).unwrap();
    let mut raw=b"HPF00001".to_vec();
    put(&mut raw,0);
    put(&mut raw,limit as u64);
    put(&mut raw,seed.len() as u64);
    for h in [start,after,db.settings.genesis()] { raw.extend(h); }
    for h in seed { raw.extend(h); }
    let mut count=0;
    while let Some(row)=rows.next().unwrap() {
        raw.extend(edge(row));
        count+=1;
    }
    raw[8..16].copy_from_slice(&u64::to_le_bytes(count));
    raw
}

fn emit(out:&mut impl Write,name:&str,db:&HeldMemory,start:Hash,after:Hash,seed:&[Hash],lim:usize) {
    db.history_page_read_counters.set(HistoryPageReadCounters::default());
    let before=db.db.total_changes();
    let q=capture(db,start,after,seed,lim);
    let mut window=VecDeque::from_iter(seed.iter().copied());
    let answer=db.history_page_ancestors(start,after,&mut window,lim,&inline_record);
    assert_eq!(db.db.total_changes(),before);
    let c=db.history_page_read_counters.get();
    let mut payload=Vec::new();
    let code=match answer{
        Ok((next,count))=>{
            put(&mut payload,count);
            payload.extend(next);
            put(&mut payload,window.len() as u64);
            put(&mut payload,c.ancestor_selects);
            put(&mut payload,c.ancestor_links);
            put(&mut payload,c.retained_ids_high_water);
            for h in &window { payload.extend(h); }
            0
        }
        Err(e)=>status(&e),
    };
    assert_eq!(c.ancestor_selects,1);
    // An original failure can leave local mutation. Observe but never return
    // it as the native caller's output or as an authoritative page.
    let mut local=Vec::new();
    for x in [c.ancestor_selects,c.ancestor_links,c.retained_ids_high_water,window.len() as u64] { put(&mut local,x); }
    for h in &window { local.extend(h); }
    for n in [name.len() as u64,q.len() as u64,code,payload.len() as u64,local.len() as u64] {
        out.write_all(&n.to_le_bytes()).unwrap();
    }
    out.write_all(name.as_bytes()).unwrap();
    out.write_all(&q).unwrap();
    out.write_all(&payload).unwrap();
    out.write_all(&local).unwrap();
}

fn main() {
    let mut out=io::BufWriter::new(io::stdout().lock());
    let good=fixture(75,None,&[]);
    emit(&mut out,"unknown-first",&good,id(100),id(0),&[],4);
    emit(&mut out,"excluded-cursor",&good,id(3),id(3),&[],16);
    emit(&mut out,"excluded-genesis",&good,id(0),id(3),&[id(150)],16);
    emit(&mut out,"single-to-genesis",&good,id(1),id(0),&[],16);
    emit(&mut out,"stop-at-cursor",&good,id(9),id(4),&[],16);
    emit(&mut out,"window-one",&good,id(7),id(0),&[],1);
    emit(&mut out,"full-batch-continuation",&good,id(75),id(0),&[],16);
    emit(&mut out,"full-batch-stop-edge",&good,id(64),id(0),&[],16);
    emit(&mut out,"seed-partial",&good,id(4),id(1),&[id(6),id(5)],16);
    emit(&mut out,"seed-rolling",&good,id(4),id(1),&[id(7),id(6),id(5)],3);
    emit(&mut out,"missing-late",&fixture(5,Some(2),&[]),id(5),id(0),&[],16);
    emit(&mut out,"no-child-parent",&fixture(2,None,&[(2,0,Value::Null)]),id(2),id(0),&[],16);
    emit(&mut out,"parent-height",&fixture(4,None,&[(4,1,Value::Integer(7))]),id(4),id(0),&[],16);
    emit(&mut out,"height-after-one",&fixture(4,None,&[(2,1,Value::Integer(0))]),id(4),id(0),&[],16);
    emit(&mut out,"child-type-before-parent-width",&fixture(1,None,&[(1,0,Value::Blob(vec![4;31])),
        (1,2,Value::Text("ordinary type mismatch".into()))]),id(1),id(0),&[],16);
    emit(&mut out,"parent-width-before-work-width",&fixture(1,None,&[(1,0,Value::Blob(vec![4;31])),
        (1,2,Value::Blob(vec![5;63]))]),id(1),id(0),&[],16);
    emit(&mut out,"parent-root-type",&fixture(4,None,&[(3,3,Value::Text("ordinary type mismatch".into()))]),
        id(4),id(3),&[],16);
    emit(&mut out,"parent-height-sign",&fixture(2,None,&[(1,1,Value::Integer(-1))]),id(2),id(1),&[],16);
    emit(&mut out,"native-work-width",&fixture(1,None,&[(1,2,Value::Blob(vec![7;63]))]),id(1),id(0),&[],16);
    emit(&mut out,"top-signed-height",&fixture(2,None,&[(1,1,Value::Integer(i64::MAX-1)),
        (2,1,Value::Integer(i64::MAX))]),id(2),id(1),&[],16);
    out.flush().unwrap();
}
