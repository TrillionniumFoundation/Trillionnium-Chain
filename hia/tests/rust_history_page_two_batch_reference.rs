// Only generated in-memory rows and inert lengths; no Packet parser.
#[derive(Clone)]
struct InertPacket { id:Hash, length:usize }
struct LengthFixture(Vec<InertPacket>);
impl LengthFixture {
    fn packet(&self,id:Hash)->Result<InertPacket> {
        Ok(self.0.iter().find(|p|p.id==id).expect("only a retained ID").clone())
    }
    fn select(&self, window:VecDeque<Hash>, packet_length:impl Fn(&InertPacket)->Result<usize>)
        ->Result<Vec<InertPacket>> {
        // EXACT_ORIGINAL_CUTOFF_LOOP
        Ok(packets)
    }
}

fn observe_two(out:&mut impl Write, n:u64, after:u64, limit:usize, seed:&[Hash],
               profile:usize, bad_height:bool) {
    let changes=if bad_height {vec![(1,1,Value::Integer(0))]} else {vec![]};
    let node=fixture(n,None,&changes);
    let tx=node.db.unchecked_transaction().unwrap();
    let mut window=VecDeque::from_iter(seed.iter().copied());
    let start=id(n);
    let stop=id(after);
    let first=capture(&node,start,stop,seed,limit);
    let (handoff,links1)=node.history_page_ancestors(start,stop,&mut window,limit,&inline_record).unwrap();
    assert_eq!(links1,64);
    assert_ne!(handoff,stop);
    assert_ne!(handoff,id(0));
    let second=capture(&node,handoff,stop,&[],limit);
    let links2=u64::from_le_bytes(second[8..16].try_into().unwrap());
    assert!((1..=64).contains(&links2));
    let result=node.history_page_ancestors(handoff,stop,&mut window,limit,&inline_record);
    let first_end=16+first.len();
    let last_end=first_end+second.len()-128;
    let mut frame=b"HPT00001".to_vec();
    put(&mut frame,links2);
    frame.extend(&first[16..128]);
    put(&mut frame,first_end as u64); put(&mut frame,last_end as u64);
    frame.extend(&first[128..]); frame.extend(&second[128..]);
    assert_eq!(frame.len(),last_end);
    let mut output=Vec::new();
    let code=match result {
        Ok((cursor,actual_links))=>{
            assert_eq!(cursor,stop);
            assert_eq!(actual_links,links2);
            let total=window.len();
            let mut roster=Vec::new();
            for (i,&item) in window.iter().enumerate() {
                let visit=total-1-i;
                let length=match (profile,visit) {
                    (1,0) | (1,1)=>400_000,
                    (2,0)=>1_048_576,
                    (3,0)=>400_001,
                    (3,1)=>400_000,
                    _=>49_508,
                };
                frame.extend(item); put(&mut frame,length as u64);
                roster.push(InertPacket{id:item,length});
            }
            let fixture=LengthFixture(roster);
            let chosen=fixture.select(window,|p|Ok(p.length)).unwrap();
            put(&mut output,links1+actual_links); put(&mut output,chosen.len() as u64);
            put(&mut output,chosen.iter().map(|p|p.length as u64).sum());
            for item in chosen {output.extend(item.id);}
            0
        }
        Err(err)=>status(&err),
    };
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),rusqlite::TransactionState::Read);
    tx.rollback().unwrap();
    for x in [frame.len() as u64,code,output.len() as u64] {put_writer(out,x);}
    out.write_all(&frame).unwrap();
    out.write_all(&output).unwrap();
}

fn put_writer(out:&mut impl Write,n:u64) {out.write_all(&n.to_le_bytes()).unwrap();}

fn main() {
    let mut out=io::BufWriter::new(io::stdout().lock());
    observe_two(&mut out,65,0,16,&[],0,false);
    observe_two(&mut out,86,2,16,&[id(90),id(89)],1,false);
    observe_two(&mut out,128,0,16,&[],2,false);
    observe_two(&mut out,70,0,4,&[],3,false);
    observe_two(&mut out,66,0,16,&[],0,true);
}
