use std::process::Command;
fn trace(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn kernel_syntax_and_target_modes_are_explicit() {
    for source in [
        "tracepoint:sched:sched_wakeup { @wake[tp(\"pid\")]=count(); }",
        "kprobe:do_sys_openat2 { @calls=count(); }",
        "kretprobe:do_sys_openat2 { @ret=hist(retval); }",
    ] {
        let out = trace(&["--check", "-e", source]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for args in [
        vec!["--system-wide", "-p", "1", "-e", "BEGIN {}"],
        vec!["--system-wide", "-e", "syscall:enter:write {}"],
        vec!["--track-loads", "-e", "BEGIN {}"],
        vec!["--output-format", "speedscope-timeline", "-e", "BEGIN {}"],
    ] {
        let out = trace(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
    }
}
#[test]
fn alternate_tracepoint_replay_and_timeline_need_no_live_kernel_access() {
    let dir = std::env::temp_dir().join(format!("poortrace-raw-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("capture.jsonl");
    let source = "tracepoint:sched:sched_wakeup { @original=count(); }";
    let header = serde_json::json!({"version":2,"source":source});
    let event = serde_json::json!({"clause":0,"stopped":false,"pid":42,"tid":43,"cpu":0,"nsecs":100,"ip":4660,"period":1,"comm":"demo","probe":"tracepoint:sched:sched_wakeup","syscall":"","addr":0,"offcpu_ns":0,"preempt":0,"sysno":0,"retval":0,"latency":0,"args":[0,0,0,0,0,0],"helpers":[],"stack":[4660,8192],"branches":[[4660,8192]],"trace_fields":{"pid":{"Integer":101},"comm":{"String":"demo"}}});
    let mut second = event.clone();
    second["nsecs"] = 200.into();
    std::fs::write(&path, format!("{header}\n{event}\n{second}\n")).unwrap();
    let path = path.to_str().unwrap();
    let out = trace(&[
        "-q",
        "--replay",
        path,
        "-e",
        "tracepoint:sched:sched_wakeup { @new[tp(\"pid\"),tpstr(\"comm\")]=count(); printf(\"%s\",ustack(1)); }",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("@new[101, \"demo\"]: 2"), "{text}");
    assert!(text.contains("0x1234"), "{text}");
    let out = trace(&["--replay", path, "--output-format", "speedscope-timeline"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["profiles"][0]["type"], "sampled");
    assert_eq!(
        report["profiles"][0]["samples"].as_array().unwrap().len(),
        2
    );
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
#[ignore = "requires permitted tracefs formats and kernel perf events"]
fn live_kernel_tracepoint_fields() {
    let out = trace(&[
        "-q",
        "-e",
        "tracepoint:syscalls:sys_enter_write { @writes= count(); @fd[tp(\"fd\")]=count(); }",
        "--",
        "/bin/echo",
        "kernel",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("@writes:"));
}

#[test]
fn system_wide_stat_reaches_counter_validation_without_a_process() {
    let out = trace(&[
        "--system-wide",
        "--stat",
        "--include-kernel",
        "--stat-events",
        "tracepoint:sched:sched_switch",
        "-d",
        "0.01",
    ]);
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("counter events must be"), "{error}");
    assert!(!error.contains("cannot be used with"), "{error}");
    assert!(
        poortrace::counters::Group::open_on_cpu(-1, &["software:cpu-clock".into()], false).is_err()
    );
    assert!(
        poortrace::counters::Group::open_on_cpu(1048576, &["software:cpu-clock".into()], false)
            .is_err()
    );
    assert!(poortrace::counters::Group::open_on_cpu(0, &[], false).is_err());
}

#[test]
#[ignore = "requires permitted system-wide software perf counting"]
fn live_system_wide_stat_reports_cpu_counters_for_the_requested_duration() {
    let start = std::time::Instant::now();
    let out = trace(&[
        "--system-wide",
        "--stat",
        "--stat-events",
        "software:cpu-clock",
        "--output-format",
        "json",
        "-d",
        "0.05",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(start.elapsed() >= std::time::Duration::from_millis(45));
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows["rows"][0]["event"], "software:cpu-clock");
    assert!(rows["rows"][0]["raw"].as_u64().unwrap() > 0);
    assert!(rows["rows"][0]["enabled_ns"].as_u64().unwrap() > 0);
    assert!(rows["rows"][0]["running_ns"].as_u64().unwrap() > 0);
}
