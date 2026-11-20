//! Qualification transport around the entire unchanged original Bench source.
//! The normal command route calls its actual main, including both clocks and
//! the real persistence owner. Other routes expose its private date/persistence
//! functions and independent Rust standard integer/binary64 formatting.
use std::io::{self, BufRead};

#[allow(dead_code)]
mod original {
    include!(env!("TRNM_BENCH_SOURCE"));

    pub fn run_main() {
        main();
    }

    pub fn text(words: &[u64]) -> String {
        assert_eq!(words.len(), 4);
        let width = words[3] as usize;
        match words[0] {
            0 => format!("{:0width$}", words[1]),
            1 => format!("{:0width$}", words[1] as i64),
            2 => format!(
                "{:0width$}",
                (u128::from(words[2]) << 64) | u128::from(words[1])
            ),
            3 => chrono_like_iso(
                UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(words[1]))
                    .expect("test timestamp must fit the real SystemTime domain"),
            ),
            _ => panic!("unknown text observation"),
        }
    }

    pub fn persist(path: &std::path::Path, epoch: u64, text: &str) -> String {
        let mut lines = text
            .strip_suffix('\n')
            .expect("report has a terminal LF")
            .split('\n')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let result = persist_profile_report_into(&mut lines, path, epoch);
        let (ok, file) = match result {
            Ok(path) => (true, fs::read(path).expect("read actual persisted bytes")),
            Err(error) => {
                lines.push(format!("profile.report.persist_error={error}"));
                (false, Vec::new())
            }
        };
        let field = |prefix: &str| {
            lines
                .iter()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap_or("")
                .as_bytes()
                .to_vec()
        };
        [
            u8::from(ok).to_string(),
            hex_digest(format!("{}\n", lines.join("\n"))),
            hex_digest(file),
            hex_digest(field("profile.report.path=")),
            hex_digest(field("profile.report.artifact_basename=")),
            hex_digest(field("profile.report.persist_error=")),
        ]
        .join("\t")
    }
}

fn decode(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "--reference-text" => {
            for line in io::stdin().lock().lines() {
                let words = line
                    .unwrap()
                    .split_whitespace()
                    .map(|word| word.parse::<u64>().unwrap())
                    .collect::<Vec<_>>();
                println!("{}", original::text(&words));
            }
        }
        "--reference-metrics" => {
            for line in io::stdin().lock().lines() {
                let words = line
                    .unwrap()
                    .split_whitespace()
                    .map(|word| word.parse::<u64>().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(words.len(), 4);
                let [keys, n, groups, grouped] = words[..] else {
                    unreachable!()
                };
                let n = n.max(1);
                let keys = keys.max(1);
                // The same Rust operations and their order as original main;
                // these synthetic magnitudes do not allocate impossible workloads.
                let conflict = 1.0_f64 - (keys as f64 / n as f64).min(1.0);
                let coverage = grouped as f64 / n as f64;
                let per_thousand = groups as f64 * 1000.0 / n as f64;
                let efficiency = if groups == 0 {
                    0.0
                } else {
                    grouped as f64 / groups as f64
                };
                println!("{conflict:.4}\t{coverage:.4}\t{per_thousand:.4}\t{efficiency:.4}");
            }
        }
        "--reference-persist" => {
            use std::os::unix::ffi::OsStringExt;
            for line in io::stdin().lock().lines() {
                let line = line.unwrap();
                let fields = line.split('\t').collect::<Vec<_>>();
                assert_eq!(fields.len(), 3);
                let path =
                    std::path::PathBuf::from(std::ffi::OsString::from_vec(decode(fields[0])));
                let epoch = fields[1].parse().unwrap();
                let text = String::from_utf8(decode(fields[2])).unwrap();
                println!("{}", original::persist(&path, epoch, &text));
            }
        }
        _ => original::run_main(),
    }
}
