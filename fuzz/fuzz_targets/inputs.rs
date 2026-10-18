#![no_main]
use libfuzzer_sys::fuzz_target;
use poortrace::{btf::Database, language, perf::{Capture, decode_record}, recording};

fuzz_target!(|data: &[u8]| {
    // Every target is bounded, read-only, and independent of current target processes.
    if data.len() > 1024 * 1024 { return; }
    let Some((&selector, bytes)) = data.split_first() else { return; };
    match selector % 5 {
        0 => { if let Ok(source) = std::str::from_utf8(bytes) { let _ = language::parse(source); } }
        1 => { for bits in 0..16 {
            let _ = decode_record(bytes, Capture {
                callchain: bits & 1 != 0, raw: bits & 2 != 0,
                branches: bits & 4 != 0, dwarf_stack: if bits & 8 != 0 { 32768 } else { 0 },
                ..Default::default()
            });
        } }
        2 => { let _ = recording::read_from(std::io::Cursor::new(bytes)); }
        3 => { let _ = Database::parse(bytes); }
        _ => { if let Ok(text) = std::str::from_utf8(bytes) { let _ = poortrace::usdt::encoded(text); } }
    }
});
