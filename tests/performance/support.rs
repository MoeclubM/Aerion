use std::hint::black_box;
use std::time::{Duration, Instant};

// Both revisions run this exact harness on the same runner. This measures codec
// CPU/allocation costs, not network throughput or handshake latency.
pub fn measure(label: &str, bytes: usize, mut action: impl FnMut()) -> u64 {
    for _ in 0..128 {
        action();
    }
    let start = Instant::now();
    let mut iterations = 0u64;
    loop {
        for _ in 0..64 {
            action();
        }
        iterations += 64;
        if start.elapsed() >= Duration::from_millis(250) {
            break;
        }
    }
    let mib = bytes as f64 * iterations as f64 / start.elapsed().as_secs_f64() / 1048576.0;
    println!("PERF {label} {mib:.3}");
    black_box(iterations + 128)
}
