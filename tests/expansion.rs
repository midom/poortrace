use std::process::Command;
fn trace(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn raw_perf_archive_redecodes_samples_without_host_access() {
    let dir = std::env::temp_dir().join(format!("poortrace-raw-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("raw.jsonl");
    let mut payload = Vec::new();
    for value in [0x1234u64, (43u64 << 32) | 42, 100, 0, 1, 2, 0x10, 0x20] {
        payload.extend(value.to_ne_bytes());
    }
    let mut bytes = Vec::new();
    bytes.extend(9u32.to_ne_bytes());
    bytes.extend(2u16.to_ne_bytes());
    bytes.extend(((payload.len() + 8) as u16).to_ne_bytes());
    bytes.extend(payload);
    let capture = poortrace::perf::Capture {
        callchain: true,
        ..Default::default()
    };
    let mut recorder =
        poortrace::recording::Recorder::create(&path, "profile:hz:99 { @old=count(); }").unwrap();
    recorder.metadata(&poortrace::recording::Metadata::RawPerf{pid:42,tid:43,cpu:0,nsecs:100,probe:"profile:hz:99".into(),bytes,capture:Some(serde_json::json!({"architecture":std::env::consts::ARCH,"endianness":if cfg!(target_endian="little"){"little"}else{"big"},"layout":capture,"trace_format":null,"clause":0}))}).unwrap();
    recorder.flush().unwrap();
    drop(recorder);
    let out = trace(&[
        "-q",
        "--replay",
        path.to_str().unwrap(),
        "--replay-raw",
        "-e",
        "profile:hz:99 { printf(\"%d %s\",pid,ustack(1)); }",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"42     0x10\n");
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn archived_tracepoint_formats_reject_untrusted_offsets_and_widths() {
    for (offset, size, kind) in [
        (usize::MAX, 4, serde_json::json!("Integer")),
        (0, 32, serde_json::json!("Integer")),
        (
            0,
            2,
            serde_json::json!({"Dynamic":{"text":true,"relative":false}}),
        ),
    ] {
        let format:poortrace::kernel::Format=serde_json::from_value(serde_json::json!({"id":1,"fields":[{"name":"x","offset":offset,"size":size,"signed":false,"kind":kind}]})).unwrap();
        assert!(format.decode(&[0; 64]).is_err());
    }
}
#[test]
fn kernel_and_managed_helpers_compile_and_modes_validate() {
    for source in [
        "profile:hz:99 { @[kstack(8)]=count(); printf(\"%s\",ksym(ip)); }",
        "BEGIN { @size=btf_sizeof(\"task_struct\"); @offset=btf_offsetof(\"task_struct\",\"pid\"); }",
        "kprobe:do_sys_openat2 { @pid=kfield(arg0,\"task_struct\",\"pid\"); printf(\"%s\",kfieldstr(arg0,\"task_struct\",\"comm\")); }",
        "interval:ms:10 { @[asyncstack(8),jstack(8),dotnetstack(8),wasmstack(8)]=count(); }",
    ] {
        let out = trace(&["--check", "-e", source]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for args in [
        vec!["--record-raw", "-e", "BEGIN {}"],
        vec!["--record-output", "--record", "/dev/null", "-e", "BEGIN {}"],
        vec!["--output-format", "speedscope-scheduler", "-e", "BEGIN {}"],
        vec!["--stack-range", "1:0:4096", "-e", "BEGIN {}"],
    ] {
        let out = trace(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
    }
}

#[test]
#[ignore = "requires ptrace access to a launched command"]
fn live_recorded_memory_output_and_exit_status_are_replayed_offline() {
    let dir = std::env::temp_dir().join(format!("poortrace-record-io-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let path = path.to_str().unwrap();
    let out = trace(&[
        "-q",
        "--record",
        path,
        "--record-output",
        "--capture-memory",
        "arg1:8",
        "-e",
        "BEGIN { printf(\"begin\\n\"); } syscall:enter:write {} END { printf(\"end\\n\"); }",
        "--",
        "/bin/sh",
        "-c",
        "printf abcdef; printf err >&2; exit 7",
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "begin\nabcdefend\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "err");
    let recording = poortrace::recording::read_full(std::path::Path::new(path)).unwrap();
    assert_eq!(recording.header.version, 3);
    assert!(
        recording
            .events
            .iter()
            .any(|event| !event.memory.is_empty())
    );
    assert!(recording.metadata.iter().any(|entry| matches!(
        entry,
        poortrace::recording::Metadata::Exit { status: 7, .. }
    )));
    let alternate = trace(&[
        "-q",
        "--replay",
        path,
        "-e",
        "syscall:enter:write /arg0==1 && arg2==6/ { printf(\"%s\",str(arg1,6)); }",
    ]);
    assert!(
        alternate.status.success(),
        "{}",
        String::from_utf8_lossy(&alternate.stderr)
    );
    assert_eq!(alternate.stdout, b"abcdef");
    let replay = trace(&[
        "-q",
        "--replay",
        path,
        "--replay-output",
        "--replay-exit-status",
    ]);
    assert_eq!(
        replay.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(replay.stdout, out.stdout);
    assert_eq!(replay.stderr, out.stderr);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn captured_output_preserves_launch_gate_with_closed_stdout() {
    use std::os::unix::process::CommandExt;
    let path = std::env::temp_dir().join(format!(
        "poortrace-closed-stdout-{}.jsonl",
        std::process::id()
    ));
    let mut command = Command::new(env!("CARGO_BIN_EXE_poortrace"));
    command.args([
        "-q",
        "--no-print-maps",
        "--record",
        path.to_str().unwrap(),
        "--record-output",
        "-e",
        "BEGIN {}",
        "--",
        "/bin/sh",
        "-c",
        "printf error >&2",
    ]);
    unsafe {
        command.pre_exec(|| {
            libc::close(1);
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, b"error");
    let recording = poortrace::recording::read_full(&path).unwrap();
    assert!(recording.metadata.iter().any(|entry| matches!(entry,
        poortrace::recording::Metadata::Output {stream, bytes, ..} if stream == "stderr" && bytes == b"error")));
    std::fs::remove_file(path).unwrap();
}
