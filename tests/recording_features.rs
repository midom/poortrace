use poortrace::{
    codegen::Program,
    recording::{self, Helper, Saved},
    runtime::Event,
};

fn saved(time: u64, tid: u64, frames: &[u64]) -> Saved {
    serde_json::from_value(serde_json::json!({"clause":0,"stopped":false,"pid":77,"tid":tid,"cpu":0,"nsecs":time,"ip":0,"period":1,"comm":"worker","probe":"profile:hz:99","syscall":"","addr":0,"offcpu_ns":0,"preempt":0,"sysno":0,"retval":0,"latency":0,"args":[0,0,0,0,0,0],"helpers":[],"stack":frames})).unwrap()
}
#[test]
fn timeline_preserves_chronology_and_thread_identity() {
    let events = vec![
        saved(30, 2, &[3, 1]),
        saved(10, 2, &[2, 1]),
        saved(20, 3, &[4]),
        saved(10, 2, &[2, 1]),
    ];
    let json: serde_json::Value =
        serde_json::from_str(&recording::timeline_speedscope(&events).unwrap()).unwrap();
    let profiles = json["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0]["weights"], serde_json::json!([20, 1]));
    assert_eq!(profiles[0]["startValue"], 10);
    assert_eq!(profiles[0]["endValue"], 31);
    let sample = profiles[0]["samples"][0].as_array().unwrap();
    assert_eq!(
        json["shared"]["frames"][sample[0].as_u64().unwrap() as usize]["name"],
        "0x1"
    );
    assert_eq!(
        json["shared"]["frames"][sample[1].as_u64().unwrap() as usize]["name"],
        "0x2"
    );
    assert!(recording::timeline_speedscope(&[]).is_err());
}
#[test]
fn alternate_replay_reuses_captured_values_and_recomputes_strings() {
    let program = Program::compile(
        r#"BEGIN { printf("%s%s %d\n", strcat("captured", ":"), ustack, strlen("new script")); }"#,
    )
    .unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        state.replay_captured_helpers(vec![Helper {
            op: 100,
            value: 127,
            length: 0,
            number: 0,
            text: Some("    leaf\n".into()),
            error: None,
            descriptor: None,
        }]);
        program.invoke(0, &mut state, &Event::new(c"gone", c"BEGIN"));
        state.flush().unwrap();
    }
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "captured:    leaf\n 10\n"
    );
    let missing = Program::compile("BEGIN { printf(\"%s\", pystack); }").unwrap();
    let mut state = missing.state(Vec::new());
    state.replay_captured_helpers(Vec::new());
    missing.invoke(0, &mut state, &Event::new(c"gone", c"BEGIN"));
    assert!(state.flush().is_err());
}
#[test]
fn new_recording_preserves_native_context_without_live_memory() {
    let path = std::env::temp_dir().join(format!(
        "poortrace-recording-v2-{}.jsonl",
        std::process::id()
    ));
    let program = Program::compile("BEGIN { @x = count(); }").unwrap();
    {
        let mut state = program.state(Vec::new());
        state.recorder =
            Some(recording::Recorder::create(&path, "BEGIN { @x = count(); }").unwrap());
        state.js_snapshot = Some((
            poortrace::perf::UserRegs {
                ip: 1,
                sp: 2,
                fp: 3,
                lr: 4,
                runtime_g: 0,
            },
            vec![7; 8192],
        ));
        let branches = [poortrace::perf::Branch { from: 5, to: 6 }];
        let event = Event::new(c"gone", c"BEGIN")
            .with_ustack(&[1, 4])
            .with_branches(&branches);
        program.invoke(0, &mut state, &event);
        state.recorder.as_mut().unwrap().flush().unwrap();
    }
    let (header, events) = recording::read(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(header.version, 3);
    assert_eq!(events[0].stack, vec![1, 4]);
    assert_eq!(events[0].branches, vec![[5, 6]]);
    assert_eq!(events[0].raw.as_ref().unwrap().registers, [1, 2, 3, 4]);
    assert_eq!(events[0].raw.as_ref().unwrap().stack_bytes.len(), 8192);
}

#[test]
fn alternate_observations_merge_handler_copies_without_merging_distinct_samples() {
    let mut a = saved(10, 2, &[3, 1]);
    a.helpers.push(Helper {
        op: 100,
        value: 127,
        length: 0,
        number: 0,
        text: Some("leaf\nroot\n".into()),
        error: None,
        descriptor: None,
    });
    let mut b = saved(10, 2, &[]);
    b.clause = 1;
    b.helpers.push(Helper {
        op: 0,
        value: 17,
        length: 5,
        number: 0,
        text: Some("memory".into()),
        error: None,
        descriptor: None,
    });
    let c = saved(11, 2, &[3, 1]);
    let merged = recording::coalesce(vec![a, b, c]).unwrap();
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].helpers.len(), 2);
    assert_eq!(merged[0].stack, vec![3, 1]);
}

#[test]
fn wildcard_syscall_observations_merge_with_named_selectors() {
    let mut a = saved(10, 2, &[1]);
    a.probe = "syscall:enter:*".into();
    a.syscall = "write".into();
    let mut b = saved(10, 2, &[1]);
    b.probe = "syscall:enter:write".into();
    b.syscall = "write".into();
    assert_eq!(a.actual_probe(), b.actual_probe());
    assert_eq!(recording::coalesce(vec![a, b]).unwrap().len(), 1);
}

#[test]
fn alternate_replay_uses_raw_addresses_and_captured_stack_prefixes() {
    let program = Program::compile("BEGIN { printf(\"%s%s\", ustack(1), branches); }").unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        state.replay_captured_helpers(Vec::new());
        let branches = [poortrace::perf::Branch {
            from: 0x111,
            to: 0x222,
        }];
        program.invoke(
            0,
            &mut state,
            &Event::new(c"gone", c"BEGIN")
                .with_ustack(&[0xabc, 0xdef])
                .with_branches(&branches),
        );
        state.flush().unwrap();
    }
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "    0xabc\n    0x111 -> 0x222\n"
    );
    let program = Program::compile("BEGIN { printf(\"%s\", ustack(1)); }").unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        state.replay_captured_helpers(vec![Helper {
            op: 100,
            value: 127,
            length: 0,
            number: 0,
            text: Some("    named_leaf\n    named_caller\n".into()),
            error: None,
            descriptor: None,
        }]);
        program.invoke(0, &mut state, &Event::new(c"gone", c"BEGIN"));
        state.flush().unwrap();
    }
    assert_eq!(String::from_utf8(output).unwrap(), "    named_leaf\n");
}

fn replay_script(events: &[Saved], original: &str, alternate: &str) -> String {
    use std::io::Write;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "poortrace-alternate-replay-{}-{}.jsonl",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    {
        let mut file = std::fs::File::create(&path).unwrap();
        serde_json::to_writer(
            &mut file,
            &recording::Header {
                capture_mode: None,
                provenance: None,
                version: 2,
                architecture: None,
                endianness: None,
                source: original.into(),
            },
        )
        .unwrap();
        writeln!(file).unwrap();
        for event in events {
            serde_json::to_writer(&mut file, event).unwrap();
            writeln!(file).unwrap();
        }
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--no-print-maps", "--replay"])
        .arg(&path)
        .args(["-e", alternate])
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn alternate_exit_skips_later_handlers_and_observations_but_runs_end() {
    let events = [saved(10, 1, &[]), saved(20, 1, &[]), saved(30, 1, &[])];
    let text = replay_script(
        &events,
        "profile:hz:99 {}",
        r#"
        BEGIN { printf("begin\n"); }
        profile:hz:99 { printf("event=%d\n",nsecs); if(nsecs==20) { exit(); } }
        profile:hz:99 { printf("after=%d\n",nsecs); }
        END { printf("end\n"); }
        "#,
    );
    assert_eq!(text, "begin\nevent=10\nafter=10\nevent=20\nend\n");
    let text = replay_script(
        &events,
        "profile:hz:99 {}",
        r#"
        BEGIN { printf("begin\n"); exit(); }
        BEGIN { printf("later BEGIN must be skipped\n"); }
        profile:hz:99 { printf("observation must be skipped\n"); }
        END { printf("end\n"); }
        "#,
    );
    assert_eq!(text, "begin\nend\n");
}

#[test]
fn alternate_numeric_syscall_selectors_match_saved_native_numbers() {
    let write = poortrace::syscall::number("write").unwrap() as u64;
    let read = poortrace::syscall::number("read").unwrap() as u64;
    let mut events = Vec::new();
    for (time, enter, number, name) in [
        (10, true, write, "write"),
        (20, false, write, "write"),
        (30, true, read, "read"),
        (40, false, read, "read"),
    ] {
        let mut event = saved(time, 1, &[]);
        event.probe = format!("syscall:{}:*", if enter { "enter" } else { "exit" });
        event.syscall = name.into();
        event.sysno = number;
        events.push(event);
    }
    let alternate = format!(
        r#"
        syscall:enter:{write} {{ printf("number:%s:%d\n",syscall,sysno); }}
        syscall:exit:write {{ printf("named-exit:%s\n",syscall); }}
        syscall:enter:read {{ printf("named-read:%d\n",sysno); }}
        "#
    );
    assert_eq!(
        replay_script(&events, "syscall:enter:* {} syscall:exit:* {}", &alternate),
        format!("number:write:{write}\nnamed-exit:write\nnamed-read:{read}\n")
    );
}

#[test]
fn alternate_lifecycle_handlers_reuse_captured_memory_helpers() {
    let mut begin = Saved::lifecycle("BEGIN", 77, 1, 10);
    let mut end = Saved::lifecycle("END", 77, 1, 30);
    for (event, address, text) in [
        (&mut begin, 0xfeed, "captured-begin"),
        (&mut end, 0xbeef, "captured-end"),
    ] {
        event.helpers.push(Helper {
            op: 1,
            value: address,
            length: 256,
            number: 0,
            text: Some(text.into()),
            error: None,
            descriptor: None,
        });
    }
    assert_eq!(
        replay_script(
            &[begin, saved(20, 1, &[]), end],
            "BEGIN {} profile:hz:99 {} END {}",
            r#"BEGIN { printf("begin:%s\n",str(0xfeed)); } END { printf("end:%s\n",str(0xbeef)); }"#
        ),
        "begin:captured-begin\nend:captured-end\n"
    );
}

#[test]
fn captured_memory_reads_merge_regions_and_never_cross_holes() {
    use recording::MemoryRegion;
    let regions = vec![
        MemoryRegion {
            address: 100,
            bytes: b"ab\0".to_vec(),
        },
        MemoryRegion {
            address: 103,
            bytes: b"cd".to_vec(),
        },
    ];
    assert_eq!(
        recording::read_memory(&regions, 101, 4, false).unwrap(),
        b"b\0cd"
    );
    assert_eq!(
        recording::read_memory(&regions, 103, 8, true).unwrap(),
        b"cd"
    );
    assert!(recording::read_memory(&regions, 103, 8, false).is_err());
    assert!(recording::read_memory(&regions, 99, 8, true).is_err());
    assert!(recording::read_memory(&regions, u64::MAX, 2, true).is_err());
    assert!(recording::read_memory(&regions, 100, 4097, true).is_err());
}

#[test]
fn metadata_roundtrip_retains_binary_output_perf_records_and_exit_status() {
    use recording::Metadata;
    let path =
        std::env::temp_dir().join(format!("poortrace-metadata-{}.jsonl", std::process::id()));
    {
        let mut recorder = recording::Recorder::create(&path, "BEGIN {}").unwrap();
        recorder
            .metadata(&Metadata::Output {
                pid: 42,
                nsecs: 1,
                stream: "stdout".into(),
                bytes: vec![0, 255, 10],
            })
            .unwrap();
        recorder
            .metadata(&Metadata::Output {
                pid: 42,
                nsecs: 2,
                stream: "stderr".into(),
                bytes: b"error".to_vec(),
            })
            .unwrap();
        recorder
            .metadata(&Metadata::RawPerf {
                pid: 42,
                tid: 43,
                cpu: 1,
                nsecs: 3,
                probe: "profile:hz:99".into(),
                bytes: vec![1, 2, 3],
                capture: None,
            })
            .unwrap();
        recorder
            .metadata(&Metadata::Exit {
                pid: 42,
                nsecs: 4,
                status: 7,
            })
            .unwrap();
        assert!(
            recorder
                .metadata(&Metadata::Output {
                    pid: 42,
                    nsecs: 1,
                    stream: "unknown".into(),
                    bytes: vec![]
                })
                .is_err()
        );
        recorder.flush().unwrap();
    }
    let capture = recording::read_full(&path).unwrap();
    assert_eq!(capture.header.version, 3);
    assert_eq!(capture.metadata.len(), 4);
    assert!(matches!(&capture.metadata[0],Metadata::Output{bytes,..}if bytes==&[0,255,10]));
    assert!(matches!(
        &capture.metadata[3],
        Metadata::Exit { status: 7, .. }
    ));
    assert!(recording::read(&path).unwrap().1.is_empty());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn scheduler_timelines_require_proven_complete_lossless_matching_switches() {
    use recording::{Metadata, Recording};
    let switch = |time, prev, next| {
        let mut event = saved(time, prev, &[]);
        event.cpu = 0;
        event.probe = "tracepoint:sched:sched_switch".into();
        event
            .trace_fields
            .insert("prev_pid".into(), poortrace::kernel::Value::Integer(prev));
        event
            .trace_fields
            .insert("next_pid".into(), poortrace::kernel::Value::Integer(next));
        event.trace_fields.insert(
            "next_comm".into(),
            poortrace::kernel::Value::String(format!("task{next}")),
        );
        event
    };
    let mut recording = Recording {
        header: recording::Header {
            capture_mode: None,
            provenance: None,
            version: 3,
            architecture: None,
            endianness: None,
            source: "tracepoint:sched:sched_switch {}".into(),
        },
        events: vec![switch(10, 0, 42), switch(20, 42, 43), switch(30, 43, 0)],
        metadata: vec![],
    };
    assert!(recording::scheduler_speedscope(&recording).is_err());
    recording.metadata.push(Metadata::SchedulerCoverage {
        cpus: vec![0],
        start: 1,
        end: 40,
        complete: true,
        clause: Some(0),
    });
    let report: serde_json::Value =
        serde_json::from_str(&recording::scheduler_speedscope(&recording).unwrap()).unwrap();
    assert_eq!(report["profiles"][0]["type"], "evented");
    assert_eq!(report["profiles"][0]["startValue"], 10);
    assert_eq!(report["profiles"][0]["endValue"], 30);
    assert_eq!(report["profiles"][0]["events"].as_array().unwrap().len(), 4);
    // A second clause owns an independent perf stream with different sample
    // timestamps. Only the stream named by the coverage proof is authoritative.
    let secondary: Vec<_> = recording
        .events
        .iter()
        .cloned()
        .map(|mut event| {
            event.clause = 1;
            event.nsecs += 1;
            event
                .trace_fields
                .insert("prev_pid".into(), poortrace::kernel::Value::Integer(999));
            event
        })
        .collect();
    recording.events.extend(secondary);
    assert!(recording::scheduler_speedscope(&recording).is_ok());
    recording.metadata.push(Metadata::Discontinuity {
        cpu: 0,
        nsecs: 25,
        reason: "sampling throttle".into(),
    });
    assert!(
        recording::scheduler_speedscope(&recording)
            .unwrap_err()
            .contains("discontinuity")
    );
    recording.metadata.pop();
    recording.metadata.push(Metadata::Lost {
        cpu: 0,
        nsecs: 25,
        count: 1,
    });
    assert!(
        recording::scheduler_speedscope(&recording)
            .unwrap_err()
            .contains("loss")
    );
    recording.metadata.pop();
    recording.events[1]
        .trace_fields
        .insert("prev_pid".into(), poortrace::kernel::Value::Integer(99));
    assert!(
        recording::scheduler_speedscope(&recording)
            .unwrap_err()
            .contains("unmatched")
    );
    recording.events[1]
        .trace_fields
        .insert("prev_pid".into(), poortrace::kernel::Value::Integer(42));
    recording.metadata = vec![Metadata::SchedulerCoverage {
        cpus: vec![0, 1],
        start: 1,
        end: 40,
        complete: true,
        clause: Some(0),
    }];
    assert!(
        recording::scheduler_speedscope(&recording)
            .unwrap_err()
            .contains("CPU 1")
    );
}

#[test]
fn coalesced_memory_keeps_other_handlers_and_rejects_conflicts_or_overflow() {
    use recording::MemoryRegion;
    let mut a = saved(10, 2, &[]);
    a.memory = vec![MemoryRegion {
        address: 100,
        bytes: b"abc".to_vec(),
    }];
    let mut b = saved(10, 2, &[]);
    b.clause = 1;
    b.memory = vec![MemoryRegion {
        address: 102,
        bytes: b"cde".to_vec(),
    }];
    let merged = recording::coalesce(vec![a.clone(), b]).unwrap();
    assert_eq!(
        recording::read_memory(&merged[0].memory, 100, 5, false).unwrap(),
        b"abcde"
    );
    let mut changed = saved(10, 2, &[]);
    changed.clause = 2;
    changed.memory = vec![MemoryRegion {
        address: 101,
        bytes: b"X".to_vec(),
    }];
    let conflicted = recording::coalesce(vec![a.clone(), changed]).unwrap();
    assert!(
        recording::read_memory(&conflicted[0].memory, 100, 3, false)
            .unwrap_err()
            .contains("conflicting")
    );
    a.memory = (0..256)
        .map(|address| MemoryRegion {
            address,
            bytes: vec![1],
        })
        .collect();
    let mut extra = saved(10, 2, &[]);
    extra.clause = 3;
    extra.memory = vec![MemoryRegion {
        address: 1000,
        bytes: vec![2],
    }];
    assert!(recording::coalesce(vec![a, extra]).is_err());
}

#[test]
fn coalesced_kernel_stacks_preserve_captures_and_reject_conflicting_frames() {
    let a = saved(10, 2, &[]);
    let mut b = saved(10, 2, &[]);
    b.clause = 1;
    b.kernel_stack = vec![0xffff1234];
    let merged = recording::coalesce(vec![a, b.clone()]).unwrap();
    assert_eq!(merged[0].kernel_stack, vec![0xffff1234]);
    let mut changed = b.clone();
    changed.clause = 2;
    changed.kernel_stack = vec![0xffff5678];
    assert!(
        recording::coalesce(vec![b, changed])
            .err()
            .unwrap()
            .contains("kernel stacks")
    );
}

#[test]
fn raw_perf_observations_decode_archived_formats_and_preserve_handler_captures() {
    use recording::{MemoryRegion, Metadata, Recording};
    let layout = poortrace::perf::Capture {
        addr: true,
        callchain: true,
        kernel_callchain: true,
        raw: true,
        branches: true,
        ..Default::default()
    };
    let format=poortrace::kernel::Format::parse("ID: 7\nfield:unsigned int value; offset:0; size:4; signed:0;\nfield:char comm[4]; offset:4; size:4; signed:1;").unwrap();
    let descriptor = serde_json::json!({"architecture":std::env::consts::ARCH,"endianness":if cfg!(target_endian="little"){"little"}else{"big"},"layout":layout,"trace_format":format,"clause":3});
    let raw = |time: u64| {
        let mut payload = Vec::new();
        for value in [
            0x111u64,
            (43u64 << 32) | 42,
            time,
            0xabc,
            5,
            7,
            5,
            (-128i64) as u64,
            0xffff1234,
            (-512i64) as u64,
            0x111,
            0x222,
        ] {
            payload.extend(value.to_ne_bytes());
        }
        payload.extend(8u32.to_ne_bytes());
        payload.extend(17u32.to_ne_bytes());
        payload.extend(b"abc\0");
        while (payload.len() + 8) % 8 != 0 {
            payload.push(0);
        }
        for value in [1u64, 0x111, 0x222, 0] {
            payload.extend(value.to_ne_bytes());
        }
        let mut record = 9u32.to_ne_bytes().to_vec();
        record.extend(1u16.to_ne_bytes());
        record.extend(((payload.len() + 8) as u16).to_ne_bytes());
        record.extend(payload);
        record
    };
    let mut old = saved(100, 43, &[]);
    old.pid = 42;
    old.probe = "tracepoint:test:sample".into();
    old.memory = vec![MemoryRegion {
        address: 0x999,
        bytes: vec![5],
    }];
    old.comm = "known".into();
    let mut recording = Recording {
        header: recording::Header {
            capture_mode: None,
            provenance: None,
            version: 3,
            source: "tracepoint:test:sample {}".into(),
            architecture: Some(std::env::consts::ARCH.into()),
            endianness: Some(
                if cfg!(target_endian = "little") {
                    "little"
                } else {
                    "big"
                }
                .into(),
            ),
        },
        events: vec![old],
        metadata: vec![],
    };
    for time in [100, 100, 200] {
        recording.metadata.push(Metadata::RawPerf {
            pid: 42,
            tid: 43,
            cpu: 5,
            nsecs: time,
            probe: "tracepoint:test:sample".into(),
            bytes: raw(time),
            capture: Some(descriptor.clone()),
        });
    }
    let observations = recording::observations_from_raw(&recording).unwrap();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].memory[0].address, 0x999);
    assert_eq!(observations[0].comm, "known");
    assert_eq!(observations[0].stack, vec![0x111, 0x222]);
    assert_eq!(observations[0].kernel_stack, vec![0xffff1234]);
    assert_eq!(
        observations[1].trace_fields["value"],
        poortrace::kernel::Value::Integer(17)
    );
    assert_eq!(observations[1].branches, vec![[0x111, 0x222]]);
    assert_eq!(observations[1].period, 7);
    assert_eq!(observations[1].addr, 0xabc);
    assert_eq!(observations[1].clause, 3);
    if let Metadata::RawPerf {
        capture: Some(capture),
        ..
    } = &mut recording.metadata[0]
    {
        capture["architecture"] = "unsupported".into();
    }
    assert!(
        recording::observations_from_raw(&recording)
            .err()
            .unwrap()
            .contains("architecture")
    );
}

#[test]
fn raw_offcpu_pairs_are_cleared_by_throttle_and_recorded_discontinuities() {
    use recording::{Metadata, Recording};
    let layout = poortrace::perf::Capture {
        offcpu: true,
        ..Default::default()
    };
    let descriptor = serde_json::json!({"architecture":std::env::consts::ARCH,"endianness":if cfg!(target_endian="little"){"little"}else{"big"},"layout":layout,"trace_format":null,"clause":0});
    let raw = |kind: u32, misc: u16, time: u64| {
        let mut payload = Vec::new();
        if kind == 5 || kind == 6 {
            for value in [time, 1, 2] {
                payload.extend(value.to_ne_bytes());
            }
        }
        for value in [(43u64 << 32) | 42, time, 0] {
            payload.extend(value.to_ne_bytes());
        }
        let mut bytes = kind.to_ne_bytes().to_vec();
        bytes.extend(misc.to_ne_bytes());
        bytes.extend(((payload.len() + 8) as u16).to_ne_bytes());
        bytes.extend(payload);
        Metadata::RawPerf {
            pid: 42,
            tid: 43,
            cpu: 0,
            nsecs: time,
            probe: "offcpu".into(),
            bytes,
            capture: Some(descriptor.clone()),
        }
    };
    let mut recording = Recording {
        header: recording::Header {
            capture_mode: None,
            provenance: None,
            version: 3,
            source: "offcpu {}".into(),
            architecture: None,
            endianness: None,
        },
        events: vec![],
        metadata: vec![raw(14, 1 << 13, 10), raw(14, 0, 20)],
    };
    let observations = recording::observations_from_raw(&recording).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].offcpu_ns, 10);
    recording.metadata.insert(1, raw(5, 0, 15));
    assert!(
        recording::observations_from_raw(&recording)
            .unwrap()
            .is_empty()
    );
    recording.metadata[1] = Metadata::Discontinuity {
        cpu: 0,
        nsecs: 15,
        reason: "throttle".into(),
    };
    assert!(
        recording::observations_from_raw(&recording)
            .unwrap()
            .is_empty()
    );
}
