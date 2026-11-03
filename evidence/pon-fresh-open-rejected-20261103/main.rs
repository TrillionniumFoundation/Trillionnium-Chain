#![allow(dead_code, unused_imports)]

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

mod observed_production_reader;

fn main() -> Result<()> {
    observed_production_reader::kernel_parent::fresh_open_component_probe()
}
