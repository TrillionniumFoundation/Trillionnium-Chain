use super::*;

pub(crate) fn emit_runtime_summary(runtime: &RuntimeState, metrics: &RuntimeMetrics) {
    println!("{}", build_runtime_summary_line(runtime, metrics));
}
