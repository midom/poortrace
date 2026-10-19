use poortrace::functions::{Spec, Tracer};
use std::{
    io::{BufRead, BufReader, Read},
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Target(Child, Option<i32>);
impl Drop for Target {
    fn drop(&mut self) {
        if let Some(child) = self.1 {
            unsafe {
                libc::kill(child, libc::SIGKILL);
            }
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn read(pid: u32, address: u64) -> u64 {
    u64::from_ne_bytes(
        poortrace::memory::read(pid, address, 8, false)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

#[test]
#[ignore = "requires ptrace and a C compiler"]
fn ordinary_stops_and_captured_handlers_allow_sibling_progress() {
    let directory = std::env::temp_dir().join(format!(
        "poortrace-function-scheduling-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("target");
    assert!(
        Command::new("cc")
            .args(["-O0", "-g", "-pthread", "-fno-omit-frame-pointer"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/function_scheduling.c"
            ))
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let mut target = Target(
        Command::new(&binary)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
        None,
    );
    let mut line = String::new();
    BufReader::new(target.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addresses: Vec<_> = line
        .split_whitespace()
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();
    let pid = target.0.id();
    let tids: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    assert_eq!(tids.len(), 4);
    let mut tracer = Tracer::seize(
        pid as i32,
        tids,
        &[Spec {
            path: binary.to_str().unwrap().into(),
            function: "dormant".into(),
            ret: false,
        }],
        false,
    )
    .unwrap();
    tracer.trace_syscalls(true);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let events = tracer.poll().unwrap();
        if events.iter().any(|event| event.syscall.is_some()) {
            assert_eq!(
                tracer.snapshot_registers().unwrap().len(),
                1,
                "ordinary syscall stopped siblings"
            );
            let before = read(pid, addresses[0]);
            std::thread::sleep(Duration::from_millis(5));
            assert_ne!(
                before,
                read(pid, addresses[0]),
                "siblings did not run during syscall handler"
            );
            // Reliable mode can still explicitly acquire a complete pause.
            tracer.pause_for_snapshot().unwrap();
            assert_eq!(tracer.snapshot_registers().unwrap().len(), 4);
            let before = read(pid, addresses[0]);
            std::thread::sleep(Duration::from_millis(5));
            assert_eq!(before, read(pid, addresses[0]));
            break;
        }
        assert!(Instant::now() < deadline, "no syscall event");
        tracer.wait_ready(Duration::from_millis(1)).unwrap();
    }
    tracer.detach();

    // Backpressure keeps printf blocked long enough to inspect both the hitting
    // thread and its siblings. No timing threshold is used to claim a speedup.
    for (live_read, reliable, stack, resumed) in [
        (false, false, false, true),
        (false, false, true, true),
        (true, false, false, false),
        (false, true, false, false),
    ] {
        let before_completion = read(pid, addresses[1]);
        let expression = if live_read {
            "$value=read_u64(arg0);"
        } else {
            "$value=arg0;"
        };
        let capture_stack = if stack {
            "@stacks[ustack]=count(); @ips[reg(\"ip\")]=count();"
        } else {
            ""
        };
        let padding = "x".repeat(100_000);
        let script = format!(
            "BEGIN {{ printf(\"armed\\n\"); }} u:{:?}:observed {{ {expression} {capture_stack} printf(\"handler\\n\"); printf(\"{padding}%d\\n\",$value); }}",
            binary.to_str().unwrap()
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_poortrace"));
        command.args(["-q", "-p", &pid.to_string(), "-d", "0.3", "-e", &script]);
        if reliable {
            command.arg("--reliable");
        }
        let mut trace = Target(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
            None,
        );
        let stdout = trace.0.stdout.take().unwrap();
        assert!(unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } > 0);
        let mut output = BufReader::new(stdout);
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "armed\n");
        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGUSR1) }, 0);
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "handler\n");
        let before_heartbeat = read(pid, addresses[0]);
        if resumed {
            let deadline = Instant::now() + Duration::from_secs(1);
            while read(pid, addresses[1]) == before_completion
                || read(pid, addresses[0]) == before_heartbeat
            {
                assert!(
                    Instant::now() < deadline,
                    "captured handler held the target during output"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
            assert_eq!(read(pid, addresses[1]), before_completion);
            assert_eq!(read(pid, addresses[0]), before_heartbeat);
        }
        let mut rest = Vec::new();
        output.read_to_end(&mut rest).unwrap();
        if stack {
            assert!(
                String::from_utf8_lossy(&rest).contains("observed"),
                "captured stack lost its entry frame"
            );
        }
        let status = trace.0.wait().unwrap();
        let mut errors = String::new();
        trace
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        assert!(status.success(), "{errors}");
    }
    drop(target);
    let mut target = Target(
        Command::new(&binary)
            .arg("fork")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
        None,
    );
    line.clear();
    BufReader::new(target.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addresses: Vec<_> = line
        .split_whitespace()
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();
    target.1 = Some(addresses[2] as i32);
    let pid = target.0.id();
    let mut tracer = Tracer::seize_tree(
        pid as i32,
        [pid as i32],
        &[Spec {
            path: binary.to_str().unwrap().into(),
            function: "observed".into(),
            ret: false,
        }],
        false,
        true,
    )
    .unwrap();
    assert_eq!(tracer.targets().len(), 2);
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGUSR1) }, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let events = tracer.poll().unwrap();
        if !events.is_empty() {
            assert_eq!(events[0].tid, pid as i32);
            assert_eq!(
                tracer.snapshot_registers().unwrap().len(),
                1,
                "private fork was stopped for another address space's breakpoint"
            );
            let before = read(pid, addresses[0]);
            std::thread::sleep(Duration::from_millis(5));
            assert_ne!(before, read(pid, addresses[0]));
            tracer.pause_for_snapshot().unwrap();
            assert_eq!(tracer.snapshot_registers().unwrap().len(), 2);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no function event in followed tree"
        );
        tracer.wait_ready(Duration::from_millis(1)).unwrap();
    }
    tracer.detach();
    drop(target);
    std::fs::remove_dir_all(directory).unwrap();
}
