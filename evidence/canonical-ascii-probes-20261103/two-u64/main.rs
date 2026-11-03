mod baseline;
mod candidate;
use std::hint::black_box;
use std::time::Instant;

#[repr(C)]
struct Timespec { sec: i64, nsec: i64 }
unsafe extern "C" { fn clock_gettime(clock: i32, stamp: *mut Timespec) -> i32; }
fn thread_cpu_ns() -> u64 {
    assert!(cfg!(all(target_os = "linux", target_pointer_width = "64")));
    let mut stamp = Timespec { sec: 0, nsec: 0 };
    assert_eq!(unsafe { clock_gettime(3, &mut stamp) }, 0);
    assert!(stamp.sec >= 0 && (0..1_000_000_000).contains(&stamp.nsec));
    (stamp.sec as u64) * 1_000_000_000 + stamp.nsec as u64
}
fn oracle(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..=0x7f).contains(b) && *b != b'"' && *b != b'\\')
}
fn verify(bytes: &[u8], count: &mut usize) {
    let expected = oracle(bytes);
    assert_eq!(baseline::unescaped_ascii_json(bytes), expected, "baseline: {bytes:?}");
    assert_eq!(candidate::unescaped_ascii_json(bytes), expected, "candidate: {bytes:?}");
    *count += 1;
}
fn correctness() -> usize {
    let mut count = 0;
    for len in 0..=48 {
        let mut bytes = vec![b'x'; len];
        verify(&bytes, &mut count);
        for at in 0..len {
            for byte in 0..=255u8 { bytes[at] = byte; verify(&bytes, &mut count); }
            bytes[at] = b'x';
        }
    }
    for len in [63, 64, 65, 127, 128, 129, 255, 256, 257, 1024, 4080, 4096] {
        let mut bytes = vec![b'x'; len];
        for at in [0, 7, 8, 15, 16, 31, 32, len - 2, len - 1] {
            for byte in 0..=255u8 { bytes[at] = byte; verify(&bytes, &mut count); }
            bytes[at] = b'x';
        }
    }
    for boundary in [7, 15, 31] {
        let mut bytes = [b'x'; 48];
        for first in 0..=255u8 {
            for second in 0..=255u8 {
                bytes[boundary] = first; bytes[boundary + 1] = second;
                verify(&bytes, &mut count);
            }
        }
    }
    let mut random = 0x61a3f0db29e7c458u64;
    for case in 0..20000 {
        random ^= random << 13; random ^= random >> 7; random ^= random << 17;
        let len = (random as usize) % 257;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            random ^= random << 13; random ^= random >> 7; random ^= random << 17;
            bytes.push(if case % 2 == 0 { (random as u8) & 0x7f } else { random as u8 });
        }
        verify(&bytes, &mut count);
    }
    count
}
fn observe(label: &str, inputs: &[Vec<u8>], repetitions: usize) {
    let bytes_per_pass: usize = inputs.iter().map(Vec::len).sum();
    for round in 0..16 {
        for (sample, arm) in ["A", "B", "B", "A"].iter().enumerate() {
            let function: fn(&[u8]) -> bool = if *arm == "A" { baseline::unescaped_ascii_json } else { candidate::unescaped_ascii_json };
            let function = black_box(function);
            let begin_cpu = thread_cpu_ns(); let begin = Instant::now();
            let mut complete = 0;
            for _ in 0..repetitions {
                for bytes in inputs { complete += usize::from(function(black_box(bytes.as_slice()))); }
            }
            let wall_ns = begin.elapsed().as_nanos(); let cpu_ns = thread_cpu_ns() - begin_cpu;
            assert_eq!(complete, inputs.len() * repetitions);
            black_box(complete);
            println!("{{\"type\":\"sample\",\"workload\":\"{label}\",\"round\":{round},\"sample\":{sample},\"arm\":\"{arm}\",\"complete_calls\":{complete},\"input_bytes\":{},\"thread_cpu_ns\":{cpu_ns},\"wall_ns\":{wall_ns}}}",bytes_per_pass * repetitions);
        }
    }
}
fn main() {
    let checks = correctness();
    println!("{{\"type\":\"correctness\",\"cases\":{checks},\"passed\":true}}");
    let large = vec![vec![b'x'; 4080]; 2100];
    observe("large", &large, 1);
    let sizes = [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 127, 128];
    let short: Vec<Vec<u8>> = (0..2100).map(|n| vec![b'x'; sizes[n % sizes.len()]]).collect();
    observe("short", &short, 64);
}
