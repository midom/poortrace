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
    use std::io::BufRead;

    let mut child = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "-q",
            "-e",
            r#"END { printf("interrupted\n"); }"#,
            "--",
            "/bin/sh",
            "-c",
            r#"printf 'ready:%s\n' "$$"; exec /bin/sleep 30"#,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    // The workload can print only after startup, signal-handler installation,
    // JIT compilation, and release of the launch gate. A fixed sleep races with
    // shared LLVM loading on busy CI runners.
    let ready = match receiver.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(line)) => line,
        result => {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "workload did not become ready: {result:?}; status={}; {}",
                out.status,
                errors(&out)
            );
        }
    };
    let workload: i32 = ready.strip_prefix("ready:").unwrap().parse().unwrap();
    assert!(workload > 0);
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    // Bound shutdown independently of the startup deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            unsafe {
                libc::kill(-workload, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("tracer did not stop on SIGINT");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "status={}; {}",
        out.status,
        errors(&out)
    );
    assert_eq!(
        receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap(),
        "interrupted"
    );
    // EOF also proves that the workload no longer holds the output pipe open.
    let eof = receiver.recv_timeout(Duration::from_secs(3));
    if !matches!(eof, Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) {
        unsafe {
            libc::kill(-workload, libc::SIGKILL);
        }
        panic!("workload output pipe remained open or had unexpected output: {eof:?}");
    }
    assert_eq!(unsafe { libc::kill(workload, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
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
    assert_eq!(rows["rows"][0]["value"], 4);
    assert_eq!(rows["rows"].as_array().unwrap().len(), 1);
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
    assert_eq!(rows["rows"].as_array().unwrap().len(), 2);
    assert!(rows["rows"][0]["raw"].as_u64().unwrap() > 0);
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
#[ignore = "requires ptrace access and a C compiler"]
fn live_syscalls_default_and_maximum_stack_capture() {
    let directory =
        std::env::temp_dir().join(format!("poortrace-stack-size-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("stack.c");
    let binary = directory.join("stack");
    std::fs::write(
        &source,
        r#"
#include <unistd.h>
__attribute__((noinline)) void leaf(void) {
    volatile char padding[8192];
    for (int i = 0; i < 8192; i++) padding[i] = 1;
    write(1, "marker\n", 7);
    if (padding[0] == 42) _exit(1);
}
__attribute__((noinline)) void caller(void) { leaf(); }
int main(void) { caller(); return 0; }
"#,
    )
    .unwrap();
    let compile = Command::new("cc")
        .args(["-O0", "-g", "-fno-omit-frame-pointer", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    for maximum in [false, true] {
        let recording = directory.join(if maximum {
            "maximum.jsonl"
        } else {
            "default.jsonl"
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_poortrace"));
        command.args(["-q", "-d", "10", "--record"]).arg(&recording);
        if maximum {
            command.args(["--stack-bytes", "32768"]);
        }
        let out = command
            .args(["-e", "syscall:enter:write { printf(\"%s\",ustack); }", "--"])
            .arg(&binary)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", errors(&out));
        let text = output(&out);
        assert!(text.contains("leaf") && text.contains("caller"), "{text}");
        let (_, events) = poortrace::recording::read(&recording).unwrap();
        assert!(
            events.iter().any(|event| event
                .raw
                .as_ref()
                .is_some_and(|raw| raw.stack_bytes.len() > 4096)),
            "raw stack capture was truncated to helper bounds"
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
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

#[test]
fn recording_roundtrip_and_corrupt_helper_types() {
    let directory =
        std::env::temp_dir().join(format!("poortrace-recording-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("events.jsonl");
    let path = path.to_str().unwrap();
    let script = r#"fn label($s)=strcat($s,"!"); BEGIN { $s=label("record"); repeat(3){ @calls[$s]++; } printf("%s %d\n",$s,strlen($s)); } END {printf("end\n");}"#;
    let live = trace(&["-q", "--record", path, "-e", script]);
    assert!(live.status.success(), "{}", errors(&live));
    let replay = trace(&["-q", "--replay", path]);
    assert!(replay.status.success(), "{}", errors(&replay));
    assert_eq!(output(&live), output(&replay));
    let data = std::fs::read_to_string(path).unwrap();
    let mut lines: Vec<serde_json::Value> = data
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines[1]["helpers"][0]["text"] = serde_json::Value::Null;
    std::fs::write(
        path,
        lines
            .into_iter()
            .map(|line| line.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let out = trace(&["--replay", path]);
    assert_eq!(out.status.code(), Some(1), "{}", errors(&out));
    assert!(errors(&out).contains("wrong type"), "{}", errors(&out));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires ptrace, perf software sampling, and C compiler"]
fn live_mixed_probes_forks_and_discovery() {
    native_tree_cases("mixed", true);
}
#[test]
#[ignore = "requires ptrace and C compiler"]
fn live_process_tree_exec_and_wakeups() {
    native_tree_cases("tree", false);
}
fn native_tree_cases(label: &str, perf: bool) {
    let (directory, binary) = compile_functions(label);
    let path = binary.to_str().unwrap();
    let listing = trace(&["--list-functions", path, "--function-filter", "traced_*"]);
    assert!(listing.status.success(), "{}", errors(&listing));
    assert!(output(&listing).contains("traced_add"));
    let script = format!(
        "uprobe:{path:?}:traced_a* {{ @calls=count(); }} uretprobe:{path:?}:traced_add {{ @returns=sum(retval); }} syscall:enter:write {{ @writes=count(); @stack[ustack(3)]=count(); }} software:cpu-clock:100000 {{ @samples=count(); }}"
    );
    let script = if perf {
        script
    } else {
        script.replace(" software:cpu-clock:100000 { @samples=count(); }", "")
    };
    for (mode, calls, returns) in [
        ("fork", 6, 132),
        ("threads", 9, 198),
        ("shared", 6, 132),
        ("vfork", 3, 66),
    ] {
        let out = trace(&["-q", "-f", "-d", "5", "-e", &script, "--", path, mode]);
        assert!(out.status.success(), "{mode}: {}", errors(&out));
        let text = output(&out);
        assert!(text.contains(&format!("@calls: {calls}")), "{mode}: {text}");
        assert!(
            text.contains(&format!("@returns: {returns}")),
            "{mode}: {text}"
        );
        assert!(!text.contains("<no user stack>"), "{text}");
    }
    for (mode, code) in [("orphan-exec", 7), ("thread-exec", 0)] {
        let script = format!(
            "uprobe:{path:?}:traced_add {{ @calls=count(); }} syscall:enter:write {{ @writes=count(); }}"
        );
        let out = trace(&["-q", "-f", "-d", "5", "-e", &script, "--", path, mode]);
        assert_eq!(out.status.code(), Some(code), "{mode}: {}", errors(&out));
        assert!(
            output(&out).contains("@calls: 3"),
            "{mode}: {}",
            output(&out)
        );
    }
    let out = trace(&[
        "-q",
        "-f",
        "-d",
        "0.2",
        "-e",
        "syscall:enter:write { @writes=count(); }",
        "--",
        path,
        "orphan-sleep",
    ]);
    assert_eq!(out.status.code(), Some(7), "{}", errors(&out));
    let text = output(&out);
    let pid = text
        .lines()
        .find_map(|line| line.strip_prefix("orphan="))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "owned orphan {pid} was not reaped: {text}"
    );
    let out = trace(&[
        "-q",
        "-e",
        "wakeup:ms:2 { @observed=count(); @time=hist(latency); }",
        "--",
        path,
        "wait",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(output(&out).contains("@observed:"), "{}", output(&out));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires ptrace and C compiler"]
fn live_usdt_and_typed_arguments() {
    let directory = std::env::temp_dir().join(format!("poortrace-typed-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for fixture in ["usdt", "typed"] {
        let binary = directory.join(fixture);
        let source = format!("{}/tests/fixtures/{fixture}.c", env!("CARGO_MANIFEST_DIR"));
        let compile = Command::new("cc")
            .args(["-g", "-O1", "-no-pie", &source, "-o"])
            .arg(&binary)
            .output()
            .unwrap();
        assert!(compile.status.success(), "{}", errors(&compile));
        let path = binary.to_str().unwrap();
        let script = if fixture == "usdt" {
            format!(
                "usdt:{path}:poortrace:* {{ @calls=count(); @sum=sum(arg0); @small=sum(arg1); @memory=sum(arg2); }}"
            )
        } else {
            format!(
                "uprobe:{path}:inspect {{ @quantity=field(arg0,\"Payload\",\"quantity\"); @nested=field(arg0,\"Payload\",\"nested.value\"); printf(\"ratio=%s\\n\",fieldstr(arg0,\"Payload\",\"ratio\")); }} uprobe:{path}:floating {{ printf(\"args=%s,%s\\n\",farg(0,\"f64\"),farg(1,\"f32\")); }} uprobe:{path}:stack_words {{ @stackword=sarg(0); }}"
            )
        };
        let out = trace(&[
            "-q",
            "-d",
            "5",
            "--record",
            directory.join("capture.jsonl").to_str().unwrap(),
            "-e",
            &script,
            "--",
            path,
        ]);
        assert!(out.status.success(), "{fixture}: {}", errors(&out));
        let text = output(&out);
        if fixture == "usdt" {
            assert!(
                text.contains("@calls: 3")
                    && text.contains("@sum: 6")
                    && text.contains("semaphore=1")
                    && text.contains("@small: -15")
                    && text.contains("@memory: -297"),
                "{text}"
            );
        } else {
            for expected in [
                "@quantity: -7",
                "@nested: 42",
                "ratio=1.25",
                "args=1.25,1.5",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
            #[cfg(target_arch = "x86_64")]
            assert!(text.contains("@stackword: 7"), "{text}");
            #[cfg(target_arch = "aarch64")]
            assert!(text.contains("@stackword: 9"), "{text}");
        }
        let replay = trace(&[
            "-q",
            "--replay",
            directory.join("capture.jsonl").to_str().unwrap(),
        ]);
        assert!(replay.status.success(), "{}", errors(&replay));
        if fixture == "usdt" {
            use std::io::BufRead;
            struct Target(std::process::Child);
            impl Drop for Target {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut target = Target(
                Command::new(path)
                    .arg("attach")
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let mut reader = std::io::BufReader::new(target.0.stdout.take().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let address = u64::from_str_radix(line.trim(), 16).unwrap();
            let out = trace(&[
                "-q",
                "-d",
                "0.05",
                "-p",
                &target.0.id().to_string(),
                "-e",
                &script,
            ]);
            assert!(out.status.success(), "{}", errors(&out));
            let bytes = poortrace::memory::read(target.0.id(), address, 2, false).unwrap();
            assert_eq!(u16::from_ne_bytes(bytes.try_into().unwrap()), 0);
            assert!(target.0.try_wait().unwrap().is_none());
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires CPython 3.12 and ptrace"]
fn live_python_frames_and_wait_snapshots() {
    let code =
        "import os\ndef leaf():\n os.write(1,b'MARKER\\n')\ndef caller():\n leaf()\ncaller()";
    let out = trace(&[
        "-q",
        "-d",
        "10",
        "-e",
        "syscall:enter:write { printf(\"%s\",pystack); }",
        "--",
        "/usr/bin/python3.12",
        "-c",
        code,
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    let text = output(&out);
    assert!(
        text.contains("leaf (") && text.contains("caller ("),
        "{text}"
    );
    let out = trace(&[
        "-q",
        "-e",
        "wait:ms:5 { @wait[wait_reason]=count(); }",
        "--",
        "/bin/sleep",
        "0.1",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    assert!(
        output(&out).contains("syscall=clock_nanosleep"),
        "{}",
        output(&out)
    );
}

#[test]
#[ignore = "requires Node 22 (V8 12.4) and ptrace"]
fn live_node_javascript_frames_and_replay() {
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .expect("Node must be installed for this opt-in test");
    assert!(node.status.success());
    let node = String::from_utf8(node.stdout).unwrap();
    let node = node.trim();
    let directory = std::env::temp_dir().join(format!("poortrace-node-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("events.jsonl");
    let path = path.to_str().unwrap();
    let code = r#"const fs=require('fs'); function leaf(){fs.writeSync(1,'MARKER\n');} function caller(){leaf();} caller();"#;
    for flags in [vec![], vec!["--jitless"], vec!["--allow-natives-syntax"]] {
        let optimized = r#"const fs=require('fs'); const fd=fs.openSync('/dev/null','w'); function leaf(fd){fs.writeSync(fd,'MARKER\n');} function caller(){leaf(1);} %PrepareFunctionForOptimization(leaf); for(let i=0;i<30;i++)leaf(fd); %OptimizeFunctionOnNextCall(leaf); caller();"#;
        let code = if flags.contains(&"--allow-natives-syntax") {
            optimized
        } else {
            code
        };
        let mut args = vec![
            "-q",
            "--record",
            path,
            "-e",
            "syscall:enter:write /arg0 == 1/ { printf(\"%s\",jsstack); @frames[jsstack(2)]=count(); }",
            "--",
            node,
        ];
        args.extend(flags);
        args.extend(["-e", code]);
        let live = trace(&args);
        assert!(live.status.success(), "{}", errors(&live));
        let text = output(&live);
        assert!(
            text.contains("leaf ([eval])") && text.contains("caller ([eval])"),
            "{text}"
        );
        let replay = trace(&["-q", "--replay", path]);
        assert!(replay.status.success(), "{}", errors(&replay));
        assert_eq!(text.replace("MARKER\n", ""), output(&replay));
    }
    let worker = trace(&[
        "-q",
        "--track-threads",
        "-e",
        "syscall:enter:write /arg0==1/ { printf(\"%s\",jsstack); }",
        "--",
        node,
        "-e",
        r#"const {Worker}=require('worker_threads');new Worker(String.raw`function workerLeaf(){require('fs').writeSync(1,'WORKER\n')} function workerCaller(){workerLeaf()} workerCaller()`,{eval:true});"#,
    ]);
    assert!(worker.status.success(), "{}", errors(&worker));
    let text = output(&worker);
    assert!(
        text.contains("workerLeaf (") && text.contains("workerCaller ("),
        "{text}"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires Node 22 (V8 12.4) and software perf sampling"]
fn live_perf_node_javascript_frames() {
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(node.status.success());
    let node = String::from_utf8(node.stdout).unwrap();
    let node = node.trim();
    // Perf uses the sampled FP and stack bytes, rather than ptrace registers.
    let sampled = trace(&[
        "-q",
        "-d",
        "2",
        "--mmap-pages",
        "128",
        "-e",
        "profile:hz:49 { @frames[jsstack(12)]=count(); }",
        "--",
        node,
        "-e",
        "function leaf(){let x=0;for(let i=0;i<50000000;i++)x+=Math.sqrt(i);return x;} function caller(){while(true)leaf();} caller();",
    ]);
    assert!(sampled.status.success(), "{}", errors(&sampled));
    let text = output(&sampled);
    assert!(
        text.contains("leaf ([eval])") && text.contains("caller ([eval])"),
        "{text}"
    );
}

#[test]
#[ignore = "requires a native C compiler"]
fn live_usdt_discovery_for_pid() {
    use std::io::{BufRead, BufReader};
    let directory =
        std::env::temp_dir().join(format!("poortrace-usdt-discovery-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("fixture");
    let compile = Command::new("cc")
        .args(["-g", "-O1", "-no-pie"])
        .arg(format!(
            "{}/tests/fixtures/usdt.c",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", errors(&compile));
    let mut child = Command::new(&binary)
        .arg("attach")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    struct Fixture(Child);
    use std::process::Child;
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut fixture = Fixture(child);
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert!(!ready.is_empty());
    let out = trace(&[
        "-l",
        "-p",
        &fixture.0.id().to_string(),
        "--function-filter",
        "poortrace:work",
    ]);
    assert!(out.status.success(), "{}", errors(&out));
    let expected = format!("usdt:{}:poortrace:work\n", binary.display());
    assert_eq!(output(&out), expected);
    poortrace::language::parse(&format!("{} {{ @calls=count(); }}", expected.trim())).unwrap();
    assert!(fixture.0.try_wait().unwrap().is_none());
    drop(fixture);
    std::fs::remove_dir_all(directory).unwrap();
}
