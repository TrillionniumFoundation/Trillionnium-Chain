use std::io::{self, Write};

mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));

    fn words(out: &mut impl std::io::Write, values: &[u64]) {
        for n in values { out.write_all(&n.to_le_bytes()).unwrap(); }
    }

    fn before(l: &Ledger) -> [u64; 7] {
        let why = match l.failed.as_deref() {
            None => 0,
            Some("bounded lifecycle record cannot be retained") => 1,
            Some("base xOpen failed; pending reservation retained") => 2,
            x => panic!("unrecognized first failure {x:?}"),
        };
        [l.lifecycle.len() as u64, l.cleanup.len() as u64, l.lifecycle_bytes as u64,
         l.lifecycle_complete.into(), l.denied, why, l.first_failure_code.unwrap_or(0) as u64]
    }

    fn row(object: Option<&Object>) -> [u64; 9] {
        object.map_or([0; 9], |o| {
            let r = &o.receipt;
            let flags = 1 | (u64::from(o.main) << 1) | (u64::from(r.linked) << 2)
                | (u64::from(r.reserved_pending_open) << 3);
            [flags, r.handles.into(), r.pending_opens.into(), r.shm_references.into(),
             r.high_water_bytes, r.actual_last_bytes, r.generation, r.device.unwrap_or(0), r.inode.unwrap_or(0)]
        })
    }

    fn create(l: &mut Ledger, name: &str, ino: u64, main: bool, end: u64) -> usize {
        let i = l.reserve_open(name,main).unwrap();
        l.bind(i,Identity {dev:7,ino},0,0,true).unwrap();
        l.reserve_growth(i,end).unwrap();
        l.bind(i,Identity {dev:7,ino},end,1,true).unwrap();
        l.reserve_handle(i).unwrap();
        l.opened(i).unwrap();
        i
    }

    fn ordinary_full(p: GrowthPolicy) -> (Ledger,usize) {
        let mut l = Ledger::with_policy(p);
        for ino in 10..=14 {
            let s = create(&mut l,"fixture-shm",ino,false,0);
            for n in 1..=256u64 {
                if l.lifecycle.len() == 992 { break; }
                l.reserve_growth(s,n*65_536).unwrap();
            }
            if l.lifecycle.len() == 992 {
                for _ in 0..32 {l.add_shm(s).unwrap();}
                l.close_shm(s);
                assert_eq!(l.lifecycle.len(),1024);
                assert_eq!(l.slots[s].as_ref().unwrap().receipt.shm_references,31);
                return (l,s);
            }
            l.unlinked(s);
            l.close_handle(s);
            assert!(l.slots[s].is_none());
        }
        unreachable!("exact lifecycle prefill")
    }

    fn propose(l: &Ledger,i:usize,close:bool)->LifecycleReceipt {
        let r=&l.slots[i].as_ref().unwrap().receipt;
        LifecycleReceipt {
            sequence:l.next_event,action:if close {"underlying-shm-unmap"} else {"shm-reference"},
            generation:r.generation,basename:r.basename.clone(),device:r.device,inode:r.inode,
            linked:r.linked,handles:r.handles,pending_opens:r.pending_opens,
            shm_references:if close {r.shm_references.saturating_sub(1)} else {r.shm_references+1},
            high_water_bytes:r.high_water_bytes,actual_last_bytes:r.actual_last_bytes,requested_endpoint:None,
        }
    }

    fn attempt(l:&mut Ledger,i:usize,close:bool,expected:u64)->([u64;9],u64,Vec<u8>) {
        let event=propose(l,i,close);
        let marker=l.next_event;
        let operations=l.operations;
        let prior=before(l);
        let outer=if close {l.close_shm(i);0} else {l.add_shm(i).err().unwrap_or(0) as u64};
        let status=if l.next_event==marker {13} else {0};
        assert_eq!(status,expected);
        assert_eq!(outer,if close {0} else {status});
        assert_eq!(l.operations,operations);
        let state=before(l);
        if let Some(o)=&l.slots[i] {assert_eq!(o.receipt.shm_references,event.shm_references);}
        let bytes=if status==0 {
            let retained=(if close {l.cleanup.last()} else {l.lifecycle.last()}).unwrap();
            let encoded=serde_json::to_vec(retained).unwrap();
            assert_eq!(encoded,serde_json::to_vec(&event).unwrap());
            assert_eq!(state[2]-prior[2],encoded.len() as u64);
            encoded
        } else {
            assert_eq!(state[..3],prior[..3]);
            assert_eq!(state[3],0);
            assert_eq!(state[4],prior[4]+1);
            Vec::new()
        };
        ([state[0],state[1],l.next_event,state[2],state[3],state[4],state[5],state[6],u64::from(status==0)],
         event.shm_references.into(),bytes)
    }

    fn witness(out:&mut impl std::io::Write,family:u64,l:&mut Ledger,i:usize,close:bool,status:[u64;2]) {
        let first=propose(l,i,close);
        let active=l.active_main_handles;
        let opts=u64::from(first.device.is_some())|(u64::from(first.inode.is_some())<<1);
        words(out,&[family,392+first.basename.len() as u64,if close {11} else {9},first.sequence,
          first.generation,first.device.unwrap_or(0),first.inode.unwrap_or(0),first.linked.into(),
          first.handles.into(),first.pending_opens.into(),first.shm_references.into(),
          first.high_water_bytes,first.actual_last_bytes,0,opts]);
        words(out,&before(l));
        words(out,&[i as u64,active.into()]);
        for x in 0..OBJECTS_PER_ROOT {words(out,&row(l.slots[x].as_ref()));}
        out.write_all(first.basename.as_bytes()).unwrap();
        let (d1,h1,b1)=attempt(l,i,close,status[0]);
        assert!(l.slots[i].is_some());
        let (d2,h2,b2)=attempt(l,i,true,status[1]);
        assert_eq!(h2,h1-1);
        assert_eq!(l.active_main_handles,active);
        let mask=l.slots.iter().enumerate().fold(0,|m,(i,o)|m|(u64::from(o.is_some())<<i));
        let charge=l.slots.iter().flatten().map(|o|o.receipt.high_water_bytes).sum();
        words(out,&d1);words(out,&d2);words(out,&status);words(out,&[h1,h2,mask,charge]);
        for b in [b1,b2] {
            if !b.is_empty() {words(out,&[b.len() as u64]);out.write_all(&b).unwrap();}
        }
    }

    pub fn run(out:&mut impl std::io::Write) {
        for p in [GrowthPolicy::ExactV1,GrowthPolicy::Reserve64KiBV2] {
            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-é_\"_pair",31,false,65243);
            for _ in 0..9 {l.add_shm(i).unwrap();}
            witness(out,0,&mut l,i,false,[0,0]); // refs 9 -> 10 -> 9, exact decimal bytes
            let (mut l,i)=ordinary_full(p);
            witness(out,1,&mut l,i,false,[13,0]); // FULL still increments prior31 before close
            let (mut l,i)=ordinary_full(p);
            while l.cleanup.len()<256 {l.close_shm(i);}
            witness(out,2,&mut l,i,false,[13,13]);
            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-old",32,false,65537);
            l.add_shm(i).unwrap();l.add_shm(i).unwrap();l.close_handle(i);
            let peer=create(&mut l,"fixture-peer",33,false,4097);
            while l.cleanup.len()<255 {l.close_shm(peer);}
            l.unlinked(i);
            witness(out,3,&mut l,i,true,[13,13]);
            assert!(l.slots[i].is_none());

            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-old",34,false,65537);
            l.add_shm(i).unwrap();l.add_shm(i).unwrap();l.close_handle(i);l.unlinked(i);
            witness(out,4,&mut l,i,true,[0,0]);
            assert!(l.slots[i].is_none());

            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-healthy",35,false,4097);
            while l.cleanup.len()<256 {l.close_shm(i);}
            witness(out,5,&mut l,i,false,[0,13]);
            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-one-left",36,false,4097);
            l.add_shm(i).unwrap();l.add_shm(i).unwrap();
            while l.cleanup.len()<255 {
                let peer=l.named("fixture-peer").unwrap_or_else(|| create(&mut l,"fixture-peer",37,false,33));
                l.close_shm(peer);
            }
            witness(out,6,&mut l,i,true,[0,13]);
        }
    }
}
fn main() {
    original::run(&mut io::stdout().lock());
}
