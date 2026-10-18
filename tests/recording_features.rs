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
    assert_eq!(header.version, 2);
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
    let merged = recording::coalesce(vec![a, b, c]);
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
    assert_eq!(recording::coalesce(vec![a, b]).len(), 1);
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
                version: 2,
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
