// Appended to the existing frozen fold witness, instead of its fixture main.
// The full traversal and final selection body is inserted verbatim below.
#[derive(Clone)]
struct Packet {
    id: Hash,
    length: usize,
}
struct Selection<'a> {
    held: &'a HeldMemory,
    settings: &'a HeldSettings,
    lengths: &'a [(Hash, usize)],
    accesses: std::cell::RefCell<Vec<Hash>>,
}
impl Selection<'_> {
    fn history_page_ancestors(
        &self, start: Hash, after: Hash, window: &mut VecDeque<Hash>, limit: usize,
        decoder: &impl Fn(&rusqlite::Row<'_>, usize) -> Result<Record>,
    ) -> Result<(Hash, u64)> {
        self.held.history_page_ancestors(start, after, window, limit, decoder)
    }
    fn packet(&self, id: Hash) -> Result<Packet> {
        self.accesses.borrow_mut().push(id);
        let length = self.lengths.iter().find(|pair| pair.0 == id)
            .expect("synthetic length must be independently declared for exact ID").1;
        Ok(Packet { id, length })
    }
    fn select(
        &self, tip: Hash, after: Hash, limit: usize,
        progress: &mut dyn FnMut(u64) -> Result<()>,
        packet_length: impl Fn(&Packet) -> Result<usize>,
        record_decoder: impl Fn(&rusqlite::Row<'_>, usize) -> Result<Record>,
    ) -> Result<Vec<Packet>> {
        // EXACT_ORIGINAL_TRAVERSAL_AND_SELECTION
    }
}
fn held_id(n: u64) -> Hash {
    // Equal leading 24 bytes make truncated-key handoffs distinguishable.
    let mut h = [0x87; 32];
    h[24..].copy_from_slice(&n.wrapping_mul(0x9e3779b97f4a7c15).to_be_bytes());
    h
}

fn observe(out: &mut Vec<u8>, name: &str, tip: u64, after: u64, mode: usize) {
    let fault = [(1, 0, Value::Null)];
    let held = fixture(65, None, if mode == 4 { &fault } else { &[] });
    let before = held.db.total_changes();
    let tip = id(tip);
    let after = id(after);
    let limit = 16;
    let mut lengths = Vec::new();
    for n in 1..=65 {
        let length = match (mode, n) {
            (1, 1 | 2) => 400_000,
            (2, 1) => 400_000,
            (2, 2) => 400_001,
            (3, 1) => 1_048_576,
            _ => 49_508 + n as usize,
        };
        lengths.push((id(n), length));
    }
    // Different declaration order ensures values are never joined by traversal index.
    lengths.reverse();
    let selection = Selection {
        held: &held, settings: &held.settings, lengths: &lengths,
        accesses: std::cell::RefCell::new(Vec::new()),
    };
    let mut progress = Vec::new();
    let length_trace = std::cell::RefCell::new(Vec::new());
    let result = selection.select(
        tip, after, limit,
        &mut |links| { progress.push(links); Ok(()) },
        |p| { length_trace.borrow_mut().push(p.id); Ok(p.length) },
        inline_record,
    );
    let mut selected = Vec::new();
    let status = match result {
        Ok(packets) => {
            put(&mut selected, packets.len() as u64);
            put(&mut selected, packets.iter().map(|p| p.length as u64).sum());
            for p in packets { selected.extend(p.id); }
            0
        }
        Err(e) => status(&e),
    };
    let accesses = selection.accesses.into_inner();
    assert_eq!(accesses, length_trace.into_inner());
    let exact = held.history_page_read_counters.get();
    held.history_page_read_counters.set(HistoryPageReadCounters::default());

    // Re-observe exactly the same held SQL rows without instrumenting or
    // moving the original Row/Statement owner. The native runner gets these
    // observations, and must bind the second one's start to its own cursor.
    let mut frames = Vec::new();
    let mut current = tip;
    let mut window = VecDeque::new();
    let mut checked = Vec::new();
    let mut recapture_status = 0;
    while current != after {
        assert!(frames.len() < 2);
        let seed = window.iter().copied().collect::<Vec<_>>();
        frames.push(capture(&held, current, after, &seed, limit));
        match held.history_page_ancestors(current, after, &mut window, limit, &inline_record) {
            Ok((cursor, links)) => {
                let mut response = Vec::new();
                let counters = held.history_page_read_counters.get();
                put(&mut response, links);
                response.extend(cursor);
                put(&mut response, window.len() as u64);
                put(&mut response, 1);
                put(&mut response, links);
                put(&mut response, counters.retained_ids_high_water);
                for id in &window { response.extend(id); }
                checked.push(response);
                current = cursor;
            }
            Err(e) => {
                recapture_status = self::status(&e);
                checked.push(Vec::new());
                break;
            }
        }
    }
    assert_eq!(status, recapture_status);
    assert_eq!(held.history_page_read_counters.get(), exact);
    assert_eq!(held.db.total_changes(), before);
    assert_eq!(held.db.query_row("PRAGMA query_only", [], |r| r.get::<_, u8>(0)).unwrap(), 1);

    for n in [name.len(), frames.len(), lengths.len(), selected.len(), accesses.len(), progress.len()] {
        put(out, n as u64);
    }
    put(out, status);
    out.extend(tip);
    out.extend(after);
    out.extend(name.as_bytes());
    for (h, n) in lengths {
        out.extend(h);
        put(out, n as u64);
    }
    for (frame, expected) in frames.into_iter().zip(checked) {
        put(out, frame.len() as u64);
        put(out, expected.len() as u64);
        out.extend(frame);
        out.extend(expected);
    }
    out.extend(selected);
    for h in accesses { out.extend(h); }
    for n in progress { put(out, n); }
}

fn main() {
    let mut capture = Vec::new();
    observe(&mut capture, "maximum-window", 65, 0, 0);
    observe(&mut capture, "exact-byte-limit", 65, 0, 1);
    observe(&mut capture, "plus-one", 65, 0, 2);
    observe(&mut capture, "first-over-limit", 65, 0, 3);
    observe(&mut capture, "second-fold-refusal", 65, 0, 4);
    observe(&mut capture, "empty-no-select", 1, 1, 0);
    io::stdout().lock().write_all(&capture).unwrap();
}
