//! Fixed-work CPU/allocation/syscall fixture for scripts/benchmark.py.
use std::hint::black_box;
fn main() {
    let rounds: u64 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "2000".into())
        .parse()
        .unwrap();
    let mut value = 17u64;
    for _ in 0..rounds {
        let mut buffer = vec![0u64; 8192];
        for (i, slot) in buffer.iter_mut().enumerate() {
            value = value
                .wrapping_mul(6364136223846793005)
                .wrapping_add(i as u64);
            *slot = black_box(value);
        }
        black_box(buffer);
        black_box(unsafe { libc::getpid() });
    }
    println!("{}", black_box(value));
}
