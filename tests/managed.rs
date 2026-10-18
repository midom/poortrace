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
#[ignore = "requires Node 20/22/24, exported builtin symbols, and ptrace"]
fn node_interpreted_current_source_lines() {
    let node = std::env::var("POORTRACE_NODE_BIN").unwrap_or_else(|_| "node".into());
    let version = Command::new(&node)
        .args(["-p", "process.versions.v8"])
        .output()
        .unwrap();
    if !version.status.success()
        || !["11.3.", "12.4.", "13.6."]
            .iter()
            .any(|prefix| String::from_utf8_lossy(&version.stdout).starts_with(prefix))
    {
        eprintln!(
            "skipping unsupported V8 layout {}",
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
    go_stack_fixture(false, false);
}

#[test]
#[ignore = "requires Go 1.22–1.25 compiler and ptrace; ELF and DWARF stripped"]
fn go_stripped_pclntab_goroutines_and_replay() {
    go_stack_fixture(true, false);
}

#[test]
#[ignore = "requires Go 1.22–1.25 compiler, stripped PIE ELF, and ptrace"]
fn go_stripped_pie_pclntab_and_replay() {
    go_stack_fixture(true, true);
}

fn go_stack_fixture(stripped: bool, pie: bool) {
    let directory = std::env::temp_dir().join(format!(
        "poortrace-go-{stripped}-{pie}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("go-stacks");
    let mut compiler = Command::new(std::env::var("GO").unwrap_or_else(|_| "go".into()));
    compiler.arg("build");
    if pie {
        compiler.arg("-buildmode=pie");
    }
    if stripped {
        compiler.args(["-ldflags", "-s -w"]);
    }
    let build = compiler
        .arg("-o")
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
#[ignore = "requires Node 20/22/24, optimizer metadata, and ptrace"]
fn node_optimized_inline_frames_and_replay() {
    let node = std::env::var("POORTRACE_NODE_BIN").unwrap_or_else(|_| "node".into());
    let version = Command::new(&node)
        .args(["-p", "process.versions.v8"])
        .output()
        .unwrap();
    if !version.status.success()
        || !["11.3.", "12.4.", "13.6."]
            .iter()
            .any(|prefix| String::from_utf8_lossy(&version.stdout).starts_with(prefix))
    {
        eprintln!(
            "skipping unsupported V8 layout {}",
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

#[test]
#[ignore = "requires Python asyncio and cooperative snapshot adapter"]
fn cooperative_python_suspended_tasks_and_replay() {
    use std::{
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    let directory = std::env::temp_dir().join(format!("poortrace-async-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let snapshot = directory.join("snapshot.json");
    let mut child = Command::new(tool("PYTHON", "python3"))
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/adapters/python_async.py"
        ))
        .arg("--output")
        .arg(&snapshot)
        .arg("--")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/async_stacks.py"
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let start = Instant::now();
        loop {
            if let Ok(data) = std::fs::read_to_string(&snapshot) {
                if data.contains("async_leaf") && data.contains("async_caller") {
                    break;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "Python adapter did not produce suspended frames"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "Python adapter terminated early"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let recording = directory.join("events.jsonl");
        let output = Command::new(env!("CARGO_BIN_EXE_poortrace"))
            .args(["-q", "--pid"])
            .arg(child.id().to_string())
            .arg("--managed-snapshot")
            .arg(&snapshot)
            .arg("--record")
            .arg(&recording)
            .args(["-d", "0.1", "-e", "BEGIN { printf(\"%s\",asyncstack); }"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("async_leaf")
                && text.contains("async_caller")
                && text.contains("cooperative snapshot"),
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
        assert_eq!(text, String::from_utf8_lossy(&replay.stdout));
    }));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(directory);
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

struct ManagedTarget(std::process::Child);
impl Drop for ManagedTarget {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn tool(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.into())
}
fn managed_directory(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("poortrace-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn managed_checked(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{:?}\n{}\n{}",
        command,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn managed_line(reader: impl std::io::Read + Send + 'static) -> String {
    use std::io::BufRead;
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(reader).read_line(&mut line);
        let _ = send.send(result.map(|_| line));
    });
    receive
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("runtime readiness timeout")
        .unwrap()
}
fn managed_journal(
    directory: &std::path::Path,
    pid: u32,
    runtime: &str,
    helper: &str,
    needles: &[&str],
    native: bool,
) {
    use poortrace::{codegen::Program, recording::Recorder, runtime::Event};
    let path = directory.join("snapshot.json");
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(snapshot["pid"].as_u64(), Some(pid as u64));
    assert_eq!(snapshot["runtime"], runtime);
    let threads = snapshot["threads"].as_array().unwrap();
    let selected = threads
        .iter()
        .find(|thread| {
            needles
                .iter()
                .all(|name| thread["frames"].to_string().contains(name))
        })
        .unwrap_or_else(|| panic!("missing {needles:?} in {snapshot}"));
    let tid = selected["tid"].as_u64();
    if native {
        assert!(tid.is_some());
        assert!(std::path::Path::new(&format!("/proc/{pid}/task/{}", tid.unwrap())).exists());
    } else {
        assert!(tid.is_none());
    }
    let source = format!("BEGIN {{ printf(\"%s\",{helper}); }}");
    let program = Program::compile(&source).unwrap();
    let mut output = Vec::new();
    let record = directory.join("events.jsonl");
    {
        let mut state = program.state(&mut output);
        state.managed.configure(path).unwrap();
        state.recorder = Some(Recorder::create(&record, &source).unwrap());
        let mut event = Event::new(c"managed", c"BEGIN");
        event.pid = pid as u64;
        event.tid = tid.unwrap_or(pid as u64);
        program.invoke(0, &mut state, &event);
        state.flush().unwrap();
        state.recorder.as_mut().unwrap().flush().unwrap();
    }
    let text = String::from_utf8(output).unwrap();
    for needle in needles {
        assert!(text.contains(needle), "{text}");
    }
    assert!(
        text.contains(if native {
            "native TID"
        } else {
            "process-level"
        }),
        "{text}"
    );
    // Timers have no event thread: the explicit process-wide helper preserves
    // each actual thread identity instead of attributing it to the PID.
    let timer_record = directory.join("timer.jsonl");
    let timer = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--pid"])
        .arg(pid.to_string())
        .arg("--managed-snapshot")
        .arg(directory.join("snapshot.json"))
        .arg("--record")
        .arg(&timer_record)
        .args([
            "-d",
            "0.05",
            "-e",
            "interval:ms:10 { printf(\"%s\",managedstacks(8)); exit(); }",
        ])
        .output()
        .unwrap();
    assert!(
        timer.status.success(),
        "{}",
        String::from_utf8_lossy(&timer.stderr)
    );
    let timer_text = String::from_utf8_lossy(&timer.stdout);
    for needle in needles {
        assert!(timer_text.contains(needle), "{timer_text}");
    }
    let timer_replay = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--replay"])
        .arg(&timer_record)
        .output()
        .unwrap();
    assert!(
        timer_replay.status.success(),
        "{}",
        String::from_utf8_lossy(&timer_replay.stderr)
    );
    assert_eq!(timer_text, String::from_utf8_lossy(&timer_replay.stdout));
    // Replay after removing the live snapshot: results must come from the journal.
    std::fs::remove_file(directory.join("snapshot.json")).unwrap();
    let replay = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--replay"])
        .arg(record)
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(text, String::from_utf8_lossy(&replay.stdout));
}
#[test]
#[ignore = "requires JDK 21 javac/java/jcmd and explicit cooperative JVM diagnostics"]
fn cooperative_java_logical_stacks_and_replay() {
    let directory = managed_directory("cooperative-java");
    managed_checked(
        Command::new(tool("JAVAC", "javac"))
            .arg("-d")
            .arg(&directory)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ManagedStacks.java"
            )),
    );
    let mut target = ManagedTarget(
        Command::new(tool("JAVA", "java"))
            .arg("-cp")
            .arg(&directory)
            .arg("ManagedStacks")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(managed_line(target.0.stdout.take().unwrap()).contains("JAVA_READY"));
    managed_checked(
        Command::new(tool("PYTHON", "python3"))
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/adapters/vm_snapshot.py"
            ))
            .args(["java", "--pid"])
            .arg(target.0.id().to_string())
            .arg("--output")
            .arg(directory.join("snapshot.json"))
            .args(["--once", "--tool"])
            .arg(tool("JCMD", "jcmd")),
    );
    managed_journal(
        &directory,
        target.0.id(),
        "java",
        "jstack",
        &["ManagedStacks.leaf", "ManagedStacks.caller"],
        true,
    );
    drop(target);
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
#[ignore = "requires .NET 8 SDK and dotnet-stack diagnostic tool"]
fn cooperative_dotnet_logical_stacks_and_replay() {
    let directory = managed_directory("cooperative-dotnet");
    let build = directory.join("build");
    managed_checked(
        Command::new(tool("DOTNET", "dotnet"))
            .args(["build", "--nologo", "--output"])
            .arg(&build)
            .arg(format!(
                "-p:BaseIntermediateOutputPath={}/obj/",
                directory.display()
            ))
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/dotnet_stacks/ManagedStacks.csproj"
            )),
    );
    let mut target = ManagedTarget(
        Command::new(tool("DOTNET", "dotnet"))
            .arg(build.join("ManagedStacks.dll"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(managed_line(target.0.stdout.take().unwrap()).contains("DOTNET_READY"));
    managed_checked(
        Command::new(tool("PYTHON", "python3"))
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/adapters/vm_snapshot.py"
            ))
            .args(["dotnet", "--pid"])
            .arg(target.0.id().to_string())
            .arg("--output")
            .arg(directory.join("snapshot.json"))
            .args(["--once", "--tool"])
            .arg(tool("DOTNET_STACK", "dotnet-stack")),
    );
    managed_journal(
        &directory,
        target.0.id(),
        "dotnet",
        "dotnetstack",
        &["ManagedStacks.Leaf", "ManagedStacks.Caller"],
        true,
    );
    drop(target);
    std::fs::remove_dir_all(directory).unwrap();
}
fn cooperative_inspector(runtime: &str, fixture: &str, helper: &str, needles: &[&str]) {
    let directory = managed_directory(&format!("cooperative-{runtime}"));
    let node = tool("NODE", "node");
    let node = std::env::var("POORTRACE_NODE_BIN").unwrap_or(node);
    let mut target = ManagedTarget(
        Command::new(&node)
            .arg("--inspect-brk=127.0.0.1:0")
            .arg(format!(
                "{}/tests/fixtures/{fixture}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let line = managed_line(target.0.stderr.take().unwrap());
    let url = line
        .split_whitespace()
        .find(|word| word.starts_with("ws://"))
        .expect("Inspector endpoint missing");
    let mut adapter = Command::new(&node);
    adapter
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/adapters/node_inspector.mjs"
        ))
        .arg("--pid")
        .arg(target.0.id().to_string())
        .args(["--url", url, "--output"])
        .arg(directory.join("snapshot.json"))
        .args(["--runtime", runtime, "--run", "--resume", "--once"]);
    if runtime == "javascript" {
        adapter.args(["--match", "asyncLeaf"]);
    }
    managed_checked(&mut adapter);
    managed_journal(&directory, target.0.id(), runtime, helper, needles, false);
    drop(target);
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
#[ignore = "requires Node Inspector and explicit cooperative pause/resume"]
fn cooperative_node_async_ancestry_and_replay() {
    cooperative_inspector(
        "javascript",
        "async_stacks.js",
        "asyncstack",
        &["asyncLeaf", "asyncCaller", "--- async:"],
    );
}
#[test]
#[ignore = "requires Node WebAssembly Inspector and explicit cooperative pause/resume"]
fn cooperative_wasm_logical_frames_and_replay() {
    cooperative_inspector(
        "wasm",
        "wasm_stacks.js",
        "wasmstack",
        &["pauseFromWasm", "wasm:$run"],
    );
}
#[test]
#[ignore = "requires a Node20 pointer-compression build and ptrace (POORTRACE_NODE_BIN)"]
fn compressed_scope_live_function_frames() {
    let node = tool("POORTRACE_NODE_BIN", "node");
    let config = Command::new(&node)
        .args([
            "-p",
            "process.config.variables.v8_enable_pointer_compression",
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&config.stdout).trim(),
        "1",
        "use an actual pointer-compressed Node build"
    );
    node_compatible_scope_layouts();
}
