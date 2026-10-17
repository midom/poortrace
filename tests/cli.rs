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
    let out = trace(&["--check", "-e", "profile:hz:99 { @[ustack] = count(); }"]);
    assert!(out.status.success(), "{}", errors(&out));
    let out = trace(&["-q", "-e", r#"BEGIN { printf("%s", ustack); }"#]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("<no user stack>"));
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

#[test]
#[ignore = "requires host permission for unprivileged software perf sampling"]
fn live_user_stack_capture_and_resolution() {
    let directory = std::env::temp_dir().join(format!("poortrace-stack-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("stack-fixture");
    let compile = Command::new("cc")
        .args([
            "-O1",
            "-fno-omit-frame-pointer",
            "-mno-omit-leaf-frame-pointer",
            "-fno-optimize-sibling-calls",
            "-fPIE",
            "-pie",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stack.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    let out = trace(&[
        "-q",
        "-d",
        "0.3",
        "-e",
        "profile:hz:99 { @[ustack(8)] = count(); }",
        "--",
        binary.to_str().unwrap(),
    ]);
    std::fs::remove_dir_all(directory).unwrap();
    assert!(out.status.success(), "{}", errors(&out));
    let text = output(&out);
    assert!(text.contains("@[\n    "), "{text}");
    assert!(text.contains("/"), "expected resolved module paths: {text}");
    assert!(text.contains("stack_leaf+0x"), "{text}");
    assert!(text.contains("stack_caller+0x"), "{text}");
    assert!(!text.contains("<no user stack>"), "{text}");
}

#[test]
fn new_probe_syntax_and_json_reporting() {
    for source in [
        "offcpu { @x = sum(offcpu_ns); }",
        "watchpoint:0x1000:8:w { @[addr]++; }",
        "raw:0x1234:100 { @x++; }",
        "cache:l1d:read:miss:100 { @x++; }",
        "hardware:branches:100 { @[branches]++; }",
        "syscall:enter:openat { @files[str(arg1)]++; } syscall:exit:* { @lat[syscall] = hist(latency); }",
    ] {
        let out = trace(&["--check", "-e", source]);
        assert!(out.status.success(), "{source}: {}", errors(&out));
    }
    for source in [
        "watchpoint:0x1001:8:w {}",
        "cache:bad:read:miss {}",
        "syscall:enter:nosuchcall {}",
        "raw:bad {}",
    ] {
        let out = trace(&["--check", "-e", source]);
        assert!(!out.status.success(), "{source}");
    }
    let out = trace(&[
        "-q",
        "--output-format",
        "json",
        "--top",
        "1",
        "-e",
        r#"BEGIN { @x["a"] = 4; @x["b"] = 2; }"#,
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    let rows: serde_json::Value = serde_json::from_str(&output(&out)).unwrap();
    assert_eq!(rows[0]["value"], 4);
    assert_eq!(rows.as_array().unwrap().len(), 1);
    let out = trace(&[
        "-q",
        "--window",
        "0.03",
        "-d",
        "0.08",
        "-e",
        "interval:ms:5 { @x++; }",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).matches("@x:").count() >= 2);
}

#[test]
#[ignore = "requires host permission for unprivileged perf events"]
fn live_stat_and_offcpu() {
    let out = trace(&[
        "--stat",
        "--stat-events",
        "software:cpu-clock,software:page-faults",
        "--output-format",
        "json",
        "--",
        "/bin/sh",
        "-c",
        "i=0; while [ $i -lt 2000 ]; do i=$((i+1)); done",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    let rows: serde_json::Value = serde_json::from_str(&output(&out)).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert!(rows[0]["raw"].as_u64().unwrap() > 0);
    let out = trace(&[
        "-q",
        "-e",
        "offcpu { @wait = sum(offcpu_ns); }",
        "--",
        "/bin/sleep",
        "0.05",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@wait:"), "{}", output(&out));
}

#[test]
#[ignore = "requires ptrace access to launched commands"]
fn live_syscalls_memory_and_exit_status() {
    let out = trace(&[
        "-q",
        "-d",
        "2",
        "-e",
        r#"syscall:enter:write { @calls[syscall]++; printf("buffer=%s\n",str(arg1,64)); } syscall:exit:write { @ret = sum(retval); @lat = hist(latency); } END { printf("done\n"); }"#,
        "--",
        "/bin/sh",
        "-c",
        "printf hello; exit 7",
    ]);
    assert_eq!(out.status.code(), Some(7), "{}", errors(&out));
    let text = output(&out);
    for expected in ["buffer=hello", "@calls[\"write\"]: 1", "@ret: 5", "done"] {
        assert!(text.contains(expected), "{text}");
    }
}

#[test]
#[ignore = "requires perf user-register/stack sampling and a C compiler"]
fn live_dwarf_unwinds_without_frame_pointers() {
    let directory = std::env::temp_dir().join(format!("poortrace-dwarf-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("fixture");
    let compile = Command::new("cc")
        .args([
            "-O2",
            "-g",
            "-fomit-frame-pointer",
            "-fno-optimize-sibling-calls",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stack.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    let debug = binary.with_extension("debug");
    for command in [
        Command::new("objcopy")
            .arg("--only-keep-debug")
            .arg(&binary)
            .arg(&debug)
            .output()
            .unwrap(),
        Command::new("strip")
            .arg("--strip-all")
            .arg(&binary)
            .output()
            .unwrap(),
        Command::new("objcopy")
            .arg(format!("--add-gnu-debuglink={}", debug.display()))
            .arg(&binary)
            .output()
            .unwrap(),
    ] {
        assert!(command.status.success(), "{}", errors(&command));
    }
    let out = trace(&[
        "-q",
        "--stack-mode",
        "dwarf",
        "--mmap-pages",
        "128",
        "-d",
        "0.3",
        "-e",
        "profile:hz:99 { @[ustack] = count(); }",
        "--",
        binary.to_str().unwrap(),
    ]);
    std::fs::remove_dir_all(directory).unwrap();
    assert!(out.status.success(), "{}", errors(&out));
    let text = output(&out);
    assert!(
        text.contains("stack_leaf") && text.contains("stack_caller") && text.contains("stack.c:"),
        "{text}"
    );
}

#[test]
#[ignore = "requires hardware watchpoint support and perf access"]
fn live_watchpoints() {
    use std::io::BufRead;
    let directory = std::env::temp_dir().join(format!("poortrace-watch-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("fixture");
    let compile = Command::new("cc")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/watch.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    let mut target = Command::new(&binary)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(target.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let probe = format!(
        "watchpoint:0x{}:8:w {{ @writes[addr] = count(); }}",
        line.trim()
    );
    let out = trace(&[
        "-q",
        "-p",
        &target.id().to_string(),
        "-d",
        "0.1",
        "-e",
        &probe,
    ]);
    target.kill().unwrap();
    target.wait().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@writes["), "{}", output(&out));
}

fn compile_functions(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "poortrace-functions-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    // Exercise quoted paths containing spaces as well as bare path syntax.
    let binary = directory.join("function fixture");
    let compile = Command::new("cc")
        .args([
            "-O1",
            "-g",
            "-pthread",
            "-fno-omit-frame-pointer",
            "-fno-optimize-sibling-calls",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/functions.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    (directory, binary)
}

#[test]
#[ignore = "requires ptrace access to native commands and C/C++ compilers"]
fn live_uprobes_arguments_returns_threads_and_forks() {
    let (directory, binary) = compile_functions("calls");
    let source = format!(
        "uprobe:{:?}:traced_add {{ @entry=count(); @first=sum(arg0); @sixth=sum(arg5); }} uretprobe:{:?}:traced_add {{ @returns=sum(retval); @exit=count(); }}",
        binary.to_str().unwrap(),
        binary.to_str().unwrap()
    );
    for (mode, count, returns) in [
        ("", 3, 66),
        ("threads", 9, 198),
        ("fork", 3, 66),
        ("vfork", 3, 66),
        ("shared", 3, 66),
    ] {
        let mut args = vec![
            "-q",
            "-d",
            "3",
            "-e",
            &source,
            "--",
            binary.to_str().unwrap(),
        ];
        if !mode.is_empty() {
            args.push(mode);
        }
        let out = trace(&args);
        assert!(out.status.success(), "{mode}: {}", errors(&out));
        let text = output(&out);
        for expected in [
            format!("@entry: {count}"),
            format!("@exit: {count}"),
            format!("@returns: {returns}"),
        ] {
            assert!(text.contains(&expected), "{mode}: {text}");
        }
    }
    let source = format!(
        "uretprobe:{:?}:traced_recursive {{ @returns=sum(retval); @exit=count(); }}",
        binary.to_str().unwrap()
    );
    let out = trace(&[
        "-q",
        "-d",
        "3",
        "-e",
        &source,
        "--",
        binary.to_str().unwrap(),
        "recursive",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(
        output(&out).contains("@returns: 14") && output(&out).contains("@exit: 4"),
        "{}",
        output(&out)
    );
    let cpp = directory.join("operator fixture");
    let compile = Command::new("c++")
        .args(["-O1", "-g"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/functions.cpp"
        ))
        .arg("-o")
        .arg(&cpp)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    let source = format!(
        "uprobe:{:?}:\"ns::operator+(ns::Number, ns::Number)\" {{ @operators=count(); }}",
        cpp.to_str().unwrap()
    );
    let out = trace(&["-q", "-d", "3", "-e", &source, "--", cpp.to_str().unwrap()]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@operators: 1"), "{}", output(&out));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires ptrace access to an opted-in target and a C compiler"]
fn live_uprobes_restore_attached_text_and_launch_gate() {
    use std::io::BufRead;
    let (directory, binary) = compile_functions("cleanup");
    let mut target = Command::new(&binary)
        .arg("attach")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(target.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let address = u64::from_str_radix(line.trim(), 16).unwrap();
    let original = poortrace::memory::read(target.id(), address, 16, false).unwrap();
    let source = format!(
        "uprobe:{:?}:traced_add {{ @seen=count(); exit(); }}",
        binary.to_str().unwrap()
    );
    let out = trace(&[
        "-q",
        "-d",
        "1",
        "-p",
        &target.id().to_string(),
        "-e",
        &source,
    ]);
    let after = poortrace::memory::read(target.id(), address, 16, false);
    let alive = target.try_wait().unwrap().is_none();
    let status =
        std::fs::read_to_string(format!("/proc/{}/status", target.id())).unwrap_or_default();
    unsafe {
        libc::kill(target.id() as i32, libc::SIGSTOP);
    }
    std::thread::sleep(Duration::from_millis(10));
    let stopped = trace(&[
        "-q",
        "-d",
        "0.05",
        "-p",
        &target.id().to_string(),
        "-e",
        &source,
    ]);
    let stopped_status =
        std::fs::read_to_string(format!("/proc/{}/status", target.id())).unwrap_or_default();
    unsafe {
        libc::kill(target.id() as i32, libc::SIGCONT);
    }
    target.kill().unwrap();
    target.wait().unwrap();
    assert!(stopped.status.success(), "{}", errors(&stopped));
    assert!(
        !output(&stopped).contains("@seen:"),
        "group-stopped task was resumed: {}",
        output(&stopped)
    );
    assert!(
        stopped_status
            .lines()
            .any(|line| line.starts_with("State:") && line.split_whitespace().nth(1) == Some("T")),
        "{stopped_status}"
    );
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@seen:"), "{}", output(&out));
    assert!(alive);
    assert_eq!(after.unwrap(), original);
    assert!(
        status.lines().any(|line| line
            .strip_prefix("TracerPid:")
            .is_some_and(|value| value.trim() == "0")),
        "{status}"
    );
    let source = format!(
        "BEGIN {{ exit(); }} uprobe:{:?}:traced_add {{ @seen++; }}",
        binary.to_str().unwrap()
    );
    let out = trace(&["-q", "-e", &source, "--", binary.to_str().unwrap()]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(!output(&out).contains("total="), "{}", output(&out));
    std::fs::remove_dir_all(directory).unwrap();
}
