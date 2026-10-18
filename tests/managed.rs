//! Opt-in runtime compatibility checks. Override executables to test local builds.
use std::process::Command;

#[test]
#[ignore = "requires CPython 3.11/3.12/3.13/3.14 installations and ptrace"]
fn python_versions_and_current_source_lines() {
    let mut tested = 0;
    for (name, variable) in [
        ("python3.11", "POORTRACE_PYTHON311"),
        ("python3.12", "POORTRACE_PYTHON312"),
        ("python3.13", "POORTRACE_PYTHON313"),
        ("python3.14", "POORTRACE_PYTHON314"),
    ] {
        let python = std::env::var(variable).unwrap_or_else(|_| name.into());
        if Command::new(&python).arg("--version").output().is_err() {
            continue;
        }
        let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
            .args(["-q", "-d", "20", "-e", "syscall:enter:write /arg0==1/ { printf(\"%s\",pystack); }", "--", &python, "-c",
                "import os\ndef leaf():\n x=42\n os.write(1,b'MARKER\\n')\ndef caller():\n leaf()\ncaller()"])
            .output().unwrap();
        assert!(
            output.status.success(),
            "{python}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("leaf (<string>:4)") && text.contains("caller (<string>:6)"),
            "{python}: {text}"
        );
        tested += 1;
    }
    assert!(
        tested > 0,
        "install a supported Python or set POORTRACE_PYTHON311/312/313/314"
    );
}

#[test]
#[ignore = "requires Node 20/22/24 and ptrace"]
fn node_compatible_scope_layouts() {
    let node = std::env::var("POORTRACE_NODE_BIN").unwrap_or_else(|_| "node".into());
    // Resolve wrappers (including snap) before entering the ptrace launch gate.
    let executable = Command::new(&node)
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(
        executable.status.success(),
        "{}",
        String::from_utf8_lossy(&executable.stderr)
    );
    let node = String::from_utf8(executable.stdout).unwrap();
    let node = node.trim();
    let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "-d", "20", "-e", "syscall:enter:write /arg0==1/ { printf(\"%s\",jsstack); }", "--", node, "-e",
            "const fs=require('fs');\nfunction leaf(){\n fs.writeSync(1,'MARKER\\n')\n}\nfunction caller(){leaf()}\ncaller()"])
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        (text.contains("leaf ([eval]) [line 2; function start]")
            || text.contains("leaf ([eval]) [line 3; current]"))
            && (text.contains("caller ([eval]) [line 5; function start]")
                || text.contains("caller ([eval]) [line 5; current]")),
        "{text}"
    );
}

#[test]
#[ignore = "requires Node 22 (V8 12.4), exported builtin symbols, and ptrace"]
fn node_interpreted_current_source_lines() {
    let node = std::env::var("POORTRACE_NODE_BIN").unwrap_or_else(|_| "node".into());
    let version = Command::new(&node)
        .args(["-p", "process.versions.v8"])
        .output()
        .unwrap();
    if !version.status.success() || !String::from_utf8_lossy(&version.stdout).starts_with("12.4.") {
        eprintln!(
            "skipping V8 12.4-specific check on {}",
            String::from_utf8_lossy(&version.stdout).trim()
        );
        return;
    }

    let executable = Command::new(&node)
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(executable.status.success());
    let node = String::from_utf8(executable.stdout).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "-d", "20", "-e", "syscall:enter:write /arg0==1/ { printf(\"%s\",jsstack); }", "--", node.trim(), "--jitless", "--no-enable-lazy-source-positions", "-e",
            "const fs=require('fs');\nfunction leaf(){\n fs.writeSync(1,'MARKER\\n')\n}\nfunction caller(){leaf()}\ncaller()"])
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("leaf ([eval]) [line 3; current]")
            && text.contains("caller ([eval]) [line 5; current]"),
        "{text}"
    );
}

#[test]
#[ignore = "requires Go compiler, retained DWARF, and ptrace"]
fn go_running_goroutine_identity_and_frames() {
    let directory = std::env::temp_dir().join(format!("poortrace-go-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("go-stacks");
    let build = Command::new(std::env::var("GO").unwrap_or_else(|_| "go".into()))
        .args(["build", "-o"])
        .arg(&binary)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/go_stacks.go"
        ))
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let recording = directory.join("events.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--record"])
        .arg(&recording)
        .args([
            "-d",
            "20",
            "-e",
            "syscall:enter:write /arg0==1/ { printf(\"%s%s\",gostack,goroutines(8,16)); }",
            "--",
        ])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("goroutine 1")
            && text.contains("main.leaf")
            && text.contains("main.caller")
            && text.contains("main.parkedLeaf")
            && text.contains("main.parkedCaller"),
        "{text}"
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--replay"])
        .arg(&recording)
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        text.replace("GO_MARKER\n", ""),
        String::from_utf8_lossy(&replay.stdout)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires Go compiler, retained DWARF, and software perf sampling"]
fn go_perf_samples_keep_captured_goroutine() {
    let directory = std::env::temp_dir().join(format!("poortrace-go-perf-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("go-stacks");
    let build = Command::new(std::env::var("GO").unwrap_or_else(|_| "go".into()))
        .args(["build", "-o"])
        .arg(&binary)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/go_stacks.go"
        ))
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "-q",
            "--mmap-pages",
            "256",
            "-d",
            "15",
            "-e",
            "profile:hz:49 { @[gostack(8)]=count(); }",
            "--",
        ])
        .arg(&binary)
        .arg("profile")
        .env("GOMAXPROCS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("goroutine 1")
            && text.contains("main.busyLeaf")
            && text.contains("main.busyCaller"),
        "{text}"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires Node 22 (V8 12.4), optimizer metadata, and ptrace"]
fn node_optimized_inline_frames_and_replay() {
    let node = std::env::var("POORTRACE_NODE_BIN").unwrap_or_else(|_| "node".into());
    let version = Command::new(&node)
        .args(["-p", "process.versions.v8"])
        .output()
        .unwrap();
    if !version.status.success() || !String::from_utf8_lossy(&version.stdout).starts_with("12.4.") {
        eprintln!(
            "skipping V8 12.4-specific check on {}",
            String::from_utf8_lossy(&version.stdout).trim()
        );
        return;
    }

    let executable = Command::new(&node)
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(executable.status.success());
    let node = String::from_utf8(executable.stdout).unwrap();
    let directory = std::env::temp_dir().join(format!("poortrace-inline-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let recording = directory.join("events.jsonl");
    let code = "const fs=require('fs');\nconst fd=fs.openSync('/dev/null','w');\nfunction inlineLeaf(fd){fs.writeSync(fd,'INLINE_MARKER\\n');return fd+1;}\nfunction inlineMiddle(fd){return inlineLeaf(fd)+1;}\nfunction inlineCaller(fd){return inlineMiddle(fd)+1;}\n%PrepareFunctionForOptimization(inlineCaller);\nfor(let i=0;i<50;i++)inlineCaller(fd);\n%OptimizeFunctionOnNextCall(inlineCaller);\ninlineCaller(1);";
    let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--record"])
        .arg(&recording)
        .args([
            "-d",
            "60",
            "-e",
            "syscall:enter:write /arg0==1/ { printf(\"%s\",jsstack); }",
            "--",
            node.trim(),
            "--allow-natives-syntax",
            "--no-enable-lazy-source-positions",
            "-e",
            code,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("inlineLeaf ([eval]) [line 3; current; inlined]")
            && text.contains("inlineMiddle ([eval]) [line 4; current; inlined]")
            && text.contains("inlineCaller ([eval]) [line 5; current]"),
        "{text}"
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--replay"])
        .arg(&recording)
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        text.replace("INLINE_MARKER\n", ""),
        String::from_utf8_lossy(&replay.stdout)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
