//! cargo run --release --example workload -- 2
//! CPU and allocation work on the main thread and dynamically created threads.
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn work(seconds: u64) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut value = 1u64;
    while Instant::now() < deadline {
        let mut bytes = vec![0u8; 1024 * 1024];
        for (i, b) in bytes.iter_mut().enumerate() {
            value = value
                .wrapping_mul(6364136223846793005)
                .wrapping_add(i as u64);
            *b = (value >> 32) as u8;
        }
        black_box(bytes);
    }
}
fn main() {
    let seconds = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let threads: Vec<_> = (0..2)
        .map(|i| {
            std::thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || work(seconds))
                .unwrap()
        })
        .collect();
    work(seconds);
    for thread in threads {
        thread.join().unwrap();
    }
}
