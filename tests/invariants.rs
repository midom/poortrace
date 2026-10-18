//! Deterministic generated checks run on stable Rust without host tracing permissions.
use poortrace::{
    codegen::Program,
    perf::{Sample, UserRegs},
    recording,
    runtime::{Event, StackMode},
};

#[test]
fn jit_arithmetic_matches_wrapping_reference_over_generated_inputs() {
    let program = Program::compile(r#"BEGIN { printf("%d %d %d %d %d %d\n", arg0+arg1, arg0*arg1, arg0/arg1, arg0%arg1, arg0<<arg1, arg0>>arg1); }"#).unwrap();
    let mut output = Vec::new();
    let mut expected = String::new();
    {
        let mut state = program.state(&mut output);
        let mut seed = 0x1234_5678_9abc_def0u64;
        let edges = [0i64, 1, -1, i64::MIN, i64::MAX, 63, 64, 65];
        for i in 0..512 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let a = if i < 64 { edges[i / 8] } else { seed as i64 };
            let b = if i < 64 {
                edges[i % 8]
            } else {
                seed.rotate_left(29) as i64
            };
            let mut event = Event::new(c"test", c"BEGIN");
            event.args[..2].copy_from_slice(&[a as u64, b as u64]);
            program.invoke(0, &mut state, &event);
            expected.push_str(&format!(
                "{} {} {} {} {} {}\n",
                a.wrapping_add(b),
                a.wrapping_mul(b),
                if b == 0 { 0 } else { a.wrapping_div(b) },
                if b == 0 { 0 } else { a.wrapping_rem(b) },
                a.wrapping_shl(b as u32),
                a.wrapping_shr(b as u32)
            ));
        }
        state.flush().unwrap();
    }
    assert_eq!(String::from_utf8(output).unwrap(), expected);
}

#[test]
fn frame_pointer_mode_keeps_callchains_when_raw_bytes_and_recording_are_present() {
    let program = Program::compile("BEGIN {}").unwrap();
    let mut state = program.state(std::io::sink());
    state.stack_mode = StackMode::FramePointer;
    let sample = Sample {
        ip: 0x111,
        callchain: vec![0x111, 0x222, 0x333],
        regs: Some(UserRegs {
            ip: 0x111,
            sp: 0x1000,
            fp: 0x1000,
            ..Default::default()
        }),
        stack: vec![0; 64],
        ..Default::default()
    };
    assert_eq!(state.unwind_sample(&sample), sample.callchain);
    state.stack_mode = StackMode::Dwarf;
    // No readable image for PID zero: CFI cannot reconstruct the kernel FP callchain.
    assert_eq!(state.unwind_sample(&sample), [sample.ip]);
    state.stack_mode = StackMode::FramePointer;
    let file = std::env::temp_dir().join(format!("poortrace-fp-mode-{}.jsonl", std::process::id()));
    state.recorder = Some(recording::Recorder::create(&file, "BEGIN {}").unwrap());
    assert_eq!(state.unwind_sample(&sample), sample.callchain);
    assert_eq!(state.js_snapshot.as_ref().unwrap().1, sample.stack);
    drop(state);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn captured_frame_pointer_walk_is_bounded_and_never_follows_external_memory() {
    let program = Program::compile("BEGIN {}").unwrap();
    let mut state = program.state(std::io::sink());
    let mut sample = Sample {
        ip: 1,
        callchain: vec![1],
        regs: Some(UserRegs {
            ip: 1,
            sp: 0x1000,
            fp: 0x1000,
            ..Default::default()
        }),
        stack: [0x1010u64, 2, 0x1010, 3]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect(),
        ..Default::default()
    };
    assert_eq!(state.unwind_sample(&sample), [1, 2, 3]);
    sample.stack.truncate(15);
    assert_eq!(state.unwind_sample(&sample), [1]);
    sample.regs.as_mut().unwrap().fp = u64::MAX;
    assert_eq!(state.unwind_sample(&sample), [1]);
}

#[test]
fn arbitrary_truncated_decoder_inputs_do_not_panic() {
    let mut seed = 71u64;
    for len in 0..256 {
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect();
        let _ = poortrace::perf::decode_record(&bytes, Default::default());
        let _ = poortrace::btf::Database::parse(&bytes);
        let _ = recording::read_from(std::io::Cursor::new(&bytes));
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = poortrace::language::parse(text);
        }
    }
}
