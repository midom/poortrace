use std::{
    process::{Command, Stdio},
    time::Duration,
};

fn trace(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(args)
        .output()
        .unwrap()
}
fn output(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}
fn errors(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn begin_end_and_compilation_modes() {
    let out = trace(&[
        "-q",
        "-e",
        r#"BEGIN { printf("start\n"); } END { printf("end\n"); }"#,
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert_eq!(output(&out), "start\nend\n");
    let out = trace(&["--check", "-e", "profile:hz:99 { @x = count(); }"]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("OK:"));
    let out = trace(&["--emit-llvm", "-e", "BEGIN { @x++; }"]);
    assert!(out.status.success());
    assert!(output(&out).contains("define void @probe_0"));
    assert!(trace(&["--list"]).status.success());
}

#[test]
fn interval_exit_and_finalization() {
    let out = trace(&[
        "-q",
        "-e",
        r#"interval:ms:5 { @ticks++; if (@ticks == 3) { exit(); } } END { printf("finished\n"); }"#,
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert_eq!(output(&out), "finished\n@ticks: 3\n");
    let out = trace(&["-q", "--duration", "0.04", "-e", "interval:ms:5 { @x++; }"]);
    assert!(out.status.success());
    assert!(output(&out).contains("@x:"));
}

#[test]
fn launched_command_exit_status_and_gate() {
    let out = trace(&[
        "-q",
        "-e",
        r#"BEGIN { printf("begin\n"); } END { printf("end\n"); }"#,
        "--",
        "/bin/sh",
        "-c",
        "exit 7",
    ]);
    assert_eq!(out.status.code(), Some(7), "{}", errors(&out));
    assert_eq!(output(&out), "begin\nend\n");
    let out = trace(&[
        "-q",
        "-e",
        "BEGIN { exit(); }",
        "--",
        "/bin/echo",
        "should-not-start",
    ]);
    assert!(out.status.success());
    assert!(output(&out).is_empty());
    let out = trace(&["-q", "-c", "exit 9", "-e", "BEGIN {}"]);
    assert_eq!(out.status.code(), Some(9), "{}", errors(&out));
    let out = trace(&[
        "-q",
        "-e",
        r#"BEGIN { printf("begin\n"); } END { printf("end\n"); }"#,
        "--",
        "/bin/echo",
        "command",
    ]);
    assert!(out.status.success());
    assert_eq!(output(&out), "begin\ncommand\nend\n");
}

#[test]
fn interrupt_runs_end_and_releases_launched_process_group() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "-q",
            "-e",
            r#"END { printf("interrupted\n"); }"#,
            "--",
            "/bin/sleep",
            "30",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    // Bound the test, including regressions in shutdown.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            panic!("tracer did not stop on SIGINT");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", errors(&out));
    assert_eq!(output(&out), "interrupted\n");
}

#[test]
fn invalid_cli_and_scripts_fail_cleanly() {
    for args in [
        vec!["-e", "software:page-faults:1 { @x++; }"],
        vec!["-e", "BEGIN {", "--check"],
        vec!["-e", "BEGIN {}", "--mmap-pages", "3"],
        vec!["-e", "BEGIN {}", "--duration", "nan"],
        vec!["-e", "BEGIN {}", "-p", "2147483647"],
    ] {
        let out = trace(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(!errors(&out).contains("panicked"));
    }
}

#[test]
#[ignore = "requires host permission for unprivileged software perf sampling"]
fn live_perf_launch_and_existing_pid() {
    let out = trace(&[
        "-q",
        "--duration",
        "0.3",
        "-e",
        "profile:hz:99 { @samples = count(); @period = sum(period); }",
        "--",
        "/bin/sh",
        "-c",
        "while :; do :; done",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@samples:"), "{}", output(&out));
    assert!(output(&out).contains("@period:"));
    let mut workload = Command::new("/bin/sh")
        .args(["-c", "while :; do :; done"])
        .spawn()
        .unwrap();
    let out = trace(&[
        "-q",
        "-p",
        &workload.id().to_string(),
        "--duration",
        "0.3",
        "-e",
        "software:cpu-clock:1000000 { @[comm] = count(); }",
    ]);
    workload.kill().unwrap();
    workload.wait().unwrap();
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@[\"sh\"]:"), "{}", output(&out));
}
