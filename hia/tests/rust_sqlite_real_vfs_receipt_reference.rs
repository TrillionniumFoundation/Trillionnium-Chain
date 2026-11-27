//! Locked Rust NativeIoOwner, not a direct Ledger or host-created evidence mock.
#![forbid(unsafe_code)]
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use rusqlite::OpenFlags;
use trnm_sqlite_io_boundary::{
    registered_receipt, LifecycleReceipt, NativeIoLease, NativeIoOwner, RootReceipt, ROOT_COUNT,
};

fn word(out: &mut impl Write, v:u64) {out.write_all(&v.to_le_bytes()).unwrap();}
fn typed(out:&mut Vec<u8>, e:&LifecycleReceipt, ordinary:bool) {
    let tag=match e.action {
        "reserve-open"=>1,"bind-existing-before-io-v2"=>2,"bind-real-inode"=>3,
        "reserve-growth"=>4,"reserve-handle"=>5,"opened"=>6,
        "unpublished-actual-close"=>7,"failed-open-no-methods"=>8,"shm-reference"=>9,
        "underlying-close"=>10,"underlying-shm-unmap"=>11,"unlinked"=>12,
        other=>panic!("unexpected original action {other:?}"),
    };
    assert_eq!(ordinary,(1..=6).contains(&tag) || tag==9);
    let flags=u64::from(e.device.is_some())|(u64::from(e.inode.is_some())<<1)
        |(u64::from(e.requested_endpoint.is_some())<<2);
    for v in [104+e.basename.len() as u64,tag,e.sequence,e.generation,e.device.unwrap_or(0),
        e.inode.unwrap_or(0),e.linked.into(),e.handles.into(),e.pending_opens.into(),
        e.shm_references.into(),e.high_water_bytes,e.actual_last_bytes,e.requested_endpoint.unwrap_or(0),flags] {
        word(out,v);
    }
    out.extend_from_slice(e.basename.as_bytes());
}

fn measure(r:&RootReceipt)->(Vec<u8>,Vec<u8>,Vec<u64>) {
    assert!(r.lifecycle_complete && !r.failed && r.first_failure.is_none());
    assert_eq!(r.quarantined_actual_states,0);
    assert_eq!(r.denied_operations,0);
    assert_eq!(r.owner_pid,std::process::id());
    let mut ordinary=Vec::new();let mut cleanup=Vec::new();let mut widths=Vec::new();
    for (list,out,normal) in [(&r.lifecycle,&mut ordinary,true),(&r.cleanup_lifecycle,&mut cleanup,false)] {
        assert!(list.windows(2).all(|p|p[0].sequence<p[1].sequence));
        for e in list {
            let body=serde_json::to_vec(e).unwrap();
            assert!(body.len()<=512);
            widths.push((e.sequence,body.len() as u64,normal));
            typed(out,e,normal);
        }
    }
    // Sorting is confined to the reference width oracle; native input streams remain independent.
    widths.sort_by_key(|p|p.0);
    let mut sum=0u64;
    let mut order=Vec::new();
    for (i,(seq,width,normal)) in widths.into_iter().enumerate() {assert_eq!(seq,i as u64);sum+=width;order.push(2*width+u64::from(!normal));}
    assert_eq!(sum,r.lifecycle_serialized_bytes as u64);
    (ordinary,cleanup,order)
}

fn snap(out:&mut impl Write,lease:&NativeIoLease,stage:u64,policy:u64,previous:&mut Option<RootReceipt>) {
    let r=lease.receipt().unwrap();
    assert_eq!((r.root_device,r.root_inode),lease.identity());
    assert_eq!(serde_json::to_vec(&r).unwrap(),serde_json::to_vec(&registered_receipt(lease.vfs_name()).unwrap()).unwrap());
    assert_eq!(r.growth_reservation_quantum_bytes,if policy==2 {Some(65536)} else {None});
    if let Some(old)=previous.as_ref() {
        assert!(r.callback_operations>=old.callback_operations);
        for (before,new) in [(&old.lifecycle,&r.lifecycle),(&old.cleanup_lifecycle,&r.cleanup_lifecycle)] {
            assert!(new.len()>=before.len());
            assert_eq!(serde_json::to_vec(before).unwrap(),serde_json::to_vec(&new[..before.len()]).unwrap());
        }
    }
    if stage==2 || stage==3 {
        assert!(r.objects.iter().any(|x|x.basename=="native.sqlite-shm" && x.shm_references>0));
        assert!(r.objects.iter().any(|x|x.basename=="native.sqlite-wal"));
        if policy==2 {assert!(r.lifecycle.iter().any(|e|e.action=="reserve-growth" && e.requested_endpoint.is_some()));}
    }
    if stage==4 {
        assert!(r.objects.iter().all(|x|x.handles==0 && x.pending_opens==0 && x.shm_references==0));
        assert!(r.cleanup_lifecycle.iter().any(|e|e.action=="underlying-shm-unmap"));
        assert!(r.cleanup_lifecycle.iter().any(|e|e.action=="underlying-close"));
    }
    let (ord,cleanup,widths)=measure(&r);
    let n=24+ord.len()+cleanup.len();
    for v in [policy,stage,n as u64,r.lifecycle.len() as u64,r.cleanup_lifecycle.len() as u64,
        r.lifecycle_serialized_bytes as u64,r.lifecycle.len() as u64,r.cleanup_lifecycle.len() as u64,
        24+ord.len() as u64] {word(out,v);}
    out.write_all(&ord).unwrap();
    out.write_all(&cleanup).unwrap();
    for w in widths {word(out,w);}
    *previous=Some(r);
}

fn case(out:&mut impl Write,top:&Path,policy:u64) {
    let roots:[PathBuf;ROOT_COUNT]=std::array::from_fn(|i|top.join(format!("root-{i}")));
    let owner=if policy==1 {NativeIoOwner::create(roots)} else {NativeIoOwner::create_with_reservation_v2(roots)}.unwrap();
    let lease=owner.lease(0).unwrap();
    let path=lease.directory().join("native.sqlite");
    let mut previous=None;
    snap(out,&lease,0,policy,&mut previous);
    let flags=OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_CREATE|OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let writer=lease.open(&path,flags).unwrap();
    writer.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        CREATE TABLE sample(k INTEGER PRIMARY KEY, v TEXT NOT NULL);
        INSERT INTO sample VALUES(1,'before');").unwrap();
    assert_eq!(writer.query_row("SELECT count(*) FROM sample",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    snap(out,&lease,1,policy,&mut previous);
    let mode:String=writer.query_row("PRAGMA journal_mode=WAL",[],|r|r.get(0)).unwrap();
    assert_eq!(mode,"wal");
    writer.execute("UPDATE sample SET v='in-wal' WHERE k=1",[]).unwrap();
    snap(out,&lease,2,policy,&mut previous);

    let mut reader=lease.open(&path,flags).unwrap();
    let held=reader.transaction().unwrap();
    assert_eq!(held.query_row("SELECT count(*) FROM sample",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    writer.execute("INSERT INTO sample VALUES(2,'after')",[]).unwrap();
    assert_eq!(held.query_row("SELECT count(*) FROM sample",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    snap(out,&lease,3,policy,&mut previous);
    held.rollback().unwrap();drop(reader);
    assert_eq!(writer.query_row("SELECT count(*) FROM sample",[],|r|r.get::<_,i64>(0)).unwrap(),2);
    let (busy,frames,applied):(i64,i64,i64)=writer.query_row("PRAGMA wal_checkpoint(PASSIVE)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(busy,0);assert!(frames > 0 && applied == frames);
    drop(writer);
    snap(out,&lease,4,policy,&mut previous);
}

fn main() {
    let args:Vec<_>=std::env::args_os().collect();
    assert_eq!(args.len(),3);
    let policy=args[2].to_str().unwrap().parse().unwrap();
    assert!([1,2].contains(&policy));
    case(&mut io::stdout().lock(),Path::new(&args[1]),policy);
}
