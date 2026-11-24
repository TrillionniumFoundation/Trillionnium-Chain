// The unchanged Rust model loader and real serde_json Value are linked by the test.
#[derive(Default)]
struct Fixture {
    rows: State,
}
impl FactorState for Fixture {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.rows.get(key).cloned()
    }
    fn put(&mut self, _: String, _: Value) {
        panic!("read-only fixture");
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.rows
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}
fn main() -> io::Result<()> {
    use std::io::BufRead;
    let mut output = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let case: Value = serde_json::from_str(&line).unwrap();
        let id: Hash = hex::decode(case["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let family: Hash = hex::decode(case["family"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut fixture = Fixture::default();
        for (name, modern) in [("old", false), ("new", true)] {
            let namespace = prefix(id, modern);
            for (k, v) in case[name].as_object().unwrap() {
                fixture.rows.insert(format!("{namespace}{k}"), v.clone());
            }
        }
        match load_model(&mut fixture, id, family) {
            Ok(value) => {
                output.write_all(&[0])?;
                output.write_all(&value.id())?;
                output.write_all(&value.encode())?;
            }
            Err(err) => {
                let code = match err {
                    "FACTOR_MODEL_COLLISION" => 1,
                    "FACTOR_MODEL_MISSING" => 2,
                    "FACTOR_MODEL_METADATA" => 3,
                    "FACTOR_MODEL_CHUNK" => 4,
                    "FACTOR_MODEL_LENGTH" => 5,
                    "FACTOR_MODEL_VERSION" => 6,
                    "FACTOR_MODEL_CONTEXT" => 7,
                    "EVOLUTION_GRAPH" => 8,
                    "FACTOR_MODEL_RANGE" => 9,
                    "FACTOR_MODEL_HASH" => 10,
                    _ => panic!("unexpected original runtime outcome: {err}"),
                };
                output.write_all(&[code])?;
            }
        }
    }
    Ok(())
}
