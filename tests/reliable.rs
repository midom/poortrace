use std::process::Command;

fn trace(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn reliable_modes_reject_asynchronous_or_external_snapshots_before_attachment() {
    for source in [
        "software:page-faults:1 {}",
        "offcpu {}",
        "wait:ms:10 {}",
        "tracepoint:sched:sched_switch {}",
        "profile:hz:99 { @[kstack]=count(); }",
    ] {
        let out = trace(&["--reliable", "-p", "2147483647", "-e", source]);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--reliable"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = trace(&[
        "--reliable",
        "--managed-snapshot",
        "/missing",
        "-p",
        "1",
        "-e",
        "BEGIN {}",
    ]);
    assert!(!out.status.success());
    let out = trace(&["--reliable", "-e", "interval:ms:10 {}"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires -p PID"));
}

#[test]
#[ignore = "requires ptrace access and a C compiler"]
fn stopped_handlers_freeze_sibling_writes_and_resume_attached_targets() {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
    };
    let dir = std::env::temp_dir().join(format!("poortrace-reliable-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("target.c");
    let binary = dir.join("target");
    std::fs::write(&source,r#"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
static volatile uint64_t counter;
static void *writer(void *unused) { (void)unused; for (;;) counter++; return 0; }
__attribute__((noinline)) void observed(volatile uint64_t *value) { asm volatile("" : : "r"(value) : "memory"); }
int main(void) {
 prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY,0,0,0);
 pthread_t thread; pthread_create(&thread,0,writer,0);
 printf("%llu\n",(unsigned long long)(uintptr_t)&counter); fflush(stdout);
 for (;;) { observed(&counter); usleep(1000); }
}
"#).unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-pthread"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let mut target = Command::new(&binary)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    struct KillOnDrop<'a>(&'a mut std::process::Child);
    impl Drop for KillOnDrop<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let guard = KillOnDrop(&mut target);
    let mut line = String::new();
    BufReader::new(guard.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let address = line.trim().parse::<u64>().unwrap();
    let pid = guard.0.id().to_string();
    // An incomplete initial thread list must fail closed before any handler.
    let mut incomplete =
        poortrace::functions::Tracer::seize(guard.0.id() as i32, [guard.0.id() as i32], &[], false)
            .unwrap();
    assert!(
        incomplete
            .pause_for_snapshot()
            .unwrap_err()
            .contains("untraced sibling")
    );
    drop(incomplete);
    for selector in [
        "profile:hz:99".to_owned(),
        "interval:ms:10".to_owned(),
        format!("uprobe:{}:observed", binary.display()),
    ] {
        let path = dir.join("capture.jsonl");
        let source = format!(
            "{selector} {{ $before=read_u64({address}); repeat(1024) {{ if(read_u64({address})!=$before) {{ @changed=count(); }} }} @hits=count(); }} END {{ printf(\"finished\\n\"); }}"
        );
        let out = trace(&[
            "-q",
            "--reliable",
            "-p",
            &pid,
            "-d",
            "0.12",
            "--record",
            path.to_str().unwrap(),
            "-e",
            &source,
        ]);
        assert!(
            out.status.success(),
            "{selector}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("@hits:")
                && stdout.contains("finished")
                && !stdout.contains("@changed:"),
            "{selector}: {stdout}"
        );
        let saved = poortrace::recording::read_full(&path).unwrap();
        assert_eq!(
            saved.header.capture_mode.as_deref(),
            Some("stopped-target-wall-clock")
        );
        assert!(guard.0.try_wait().unwrap().is_none());
        let before = poortrace::memory::read(guard.0.id(), address, 8, false).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let after = poortrace::memory::read(guard.0.id(), address, 8, false).unwrap();
        assert_ne!(before, after, "target did not resume after detach");
        let replay = trace(&["-q", "--replay", path.to_str().unwrap()]);
        assert!(
            replay.status.success(),
            "{}",
            String::from_utf8_lossy(&replay.stderr)
        );
        assert_eq!(replay.stdout, out.stdout);
    }
    drop(guard);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "requires ptrace access to launched commands"]
fn reliable_syscalls_exit_status_and_failure_cleanup() {
    let out = trace(&[
        "-q",
        "--reliable",
        "-e",
        "syscall:enter:write { @writes=count(); } END { printf(\"finished\\n\"); }",
        "--",
        "/bin/sh",
        "-c",
        "printf workload; exit 7",
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("workload") && stdout.contains("finished") && stdout.contains("@writes:"),
        "{stdout}"
    );
    let out = trace(&[
        "-q",
        "--reliable",
        "-e",
        "profile:hz:1001 { @hits=count(); exit(); } END { printf(\"finished\\n\"); }",
        "--",
        "/bin/sleep",
        "30",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("finished"));
}

#[test]
#[ignore = "requires ptrace access to launched commands"]
fn reliable_interrupt_runs_end_and_cleans_owned_target() {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
        time::{Duration, Instant},
    };
    let mut tracer = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "-q",
            "--reliable",
            "-e",
            "END { printf(\"finished\\n\"); }",
            "--",
            "/bin/sh",
            "-c",
            "printf 'ready:%s\\n' \"$$\"; exec /bin/sleep 30",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = tracer.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let line = match receiver.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(line)) => line,
        result => {
            let _ = tracer.kill();
            let _ = tracer.wait();
            panic!("reliable target did not become ready: {result:?}");
        }
    };
    let target: i32 = line.trim().strip_prefix("ready:").unwrap().parse().unwrap();
    assert_eq!(unsafe { libc::kill(tracer.id() as i32, libc::SIGINT) }, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if tracer.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-target, libc::SIGKILL);
            }
            let _ = tracer.kill();
            let _ = tracer.wait();
            panic!("reliable tracer did not stop after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let line = receiver
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(line, "finished");
    assert!(tracer.wait().unwrap().success());
    assert_eq!(unsafe { libc::kill(target, 0) }, -1, "owned target leaked");
}
