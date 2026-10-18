//! Permission-free baseline: cargo bench --bench pipeline > pipeline.json
use poortrace::{
    codegen::Program,
    recording::{self, Recorder},
    runtime::Event,
};
use std::{hint::black_box, time::Instant};

fn rss_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|s| s.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn main() {
    let source = "BEGIN { @[tid]=count(); @bytes=sum(period); }";
    let iterations = std::env::var("POORTRACE_BENCH_EVENTS")
        .ok()
        .map(|s| s.parse::<u64>().expect("positive integer events"))
        .unwrap_or(100_000);
    assert!(iterations > 0);
    let mut compile_ns = Vec::new();
    for _ in 0..20 {
        let start = Instant::now();
        black_box(Program::compile(black_box(source)).unwrap());
        compile_ns.push(start.elapsed().as_nanos() as u64);
    }
    compile_ns.sort_unstable();
    let program = Program::compile(source).unwrap();
    let mut event = Event::new(c"benchmark", c"BEGIN");
    event.pid = std::process::id() as u64;
    event.tid = event.pid;
    event.period = 100;
    let mut state = program.state(std::io::sink());
    let start = Instant::now();
    for _ in 0..iterations {
        program.invoke(0, black_box(&mut state), black_box(&event));
    }
    let handler_ns = start.elapsed().as_nanos() as u64;
    state.flush().unwrap();
    let mut growing = program.state(std::io::sink());
    let growth_before = rss_kib();
    let growth_entries = iterations.min(16_384);
    for tid in 1..=growth_entries {
        event.tid = tid;
        program.invoke(0, &mut growing, &event);
    }
    growing.flush().unwrap();
    let growth_after = rss_kib();
    drop(growing);
    event.tid = event.pid;
    let path = std::env::temp_dir().join(format!("poortrace-bench-{}.jsonl", std::process::id()));
    let count = iterations.min(10_000);
    let mut state = program.state(std::io::sink());
    state.recorder = Some(Recorder::create(&path, source).unwrap());
    let start = Instant::now();
    for _ in 0..count {
        program.invoke(0, &mut state, &event);
    }
    state.recorder.as_mut().unwrap().flush().unwrap();
    let recording_ns = start.elapsed().as_nanos() as u64;
    drop(state);
    let bytes = std::fs::metadata(&path).unwrap().len();
    let start = Instant::now();
    let recorded = recording::read_full(&path).unwrap();
    let read_ns = start.elapsed().as_nanos() as u64;
    let mut state = program.state(std::io::sink());
    let start = Instant::now();
    for saved in &recorded.events {
        state.replay_helpers(saved.helpers.clone());
        program.invoke(saved.clause, &mut state, &event);
    }
    let replay_ns = start.elapsed().as_nanos() as u64;
    state.flush().unwrap();
    std::fs::remove_file(path).unwrap();
    let memory = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let peak_rss_kib = memory
        .lines()
        .find(|s| s.starts_with("VmHWM:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok());
    let rustc =
        std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .arg("--version")
            .output()
            .unwrap();
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "schema_version":1,"architecture":std::env::consts::ARCH,
        "map_memory":{"entries":growth_entries,"rss_before_kib":growth_before,"rss_after_kib":growth_after},
        "llvm":env!("POORTRACE_LLVM_VERSION"),"rustc":String::from_utf8_lossy(&rustc.stdout).trim(),
        "compile":{"runs":20,"median_ns":compile_ns[10],"p95_ns":compile_ns[18]},
        "handler":{"events":iterations,"elapsed_ns":handler_ns,"events_per_second":iterations as f64*1e9/handler_ns.max(1) as f64},
        "recording":{"events":count,"bytes":bytes,"elapsed_ns":recording_ns,"bytes_per_second":bytes as f64*1e9/recording_ns.max(1) as f64},
        "archive_read":{"elapsed_ns":read_ns},"replay":{"events":count,"elapsed_ns":replay_ns},"peak_rss_kib":peak_rss_kib
    })).unwrap());
}
