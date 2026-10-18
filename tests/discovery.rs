use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn poortrace_listing_target() -> u64 {
    std::hint::black_box(42)
}

#[test]
fn process_fixture() {
    if std::env::var_os("POORTRACE_LISTING_FIXTURE").is_some() {
        assert_eq!(poortrace_listing_target(), 42);
        println!("ready");
        // Exit on pipe EOF if the parent disappears; hold mappings until it finishes.
        use std::io::Read;
        let _ = std::io::stdin().read(&mut [0u8]);
    }
}

struct Fixture(Child);
impl Fixture {
    fn spawn(executable: &std::path::Path) -> Self {
        let mut command = Command::new(executable);
        command
            .args(["--exact", "process_fixture", "--nocapture"])
            .env("POORTRACE_LISTING_FIXTURE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut attempts = 0;
        let mut child = loop {
            match command.spawn() {
                Ok(child) => break child,
                // Parallel fixture children can briefly inherit a writable copy FD
                // before exec closes it, making Linux return ETXTBSY for this file.
                Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) && attempts < 20 => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => panic!("cannot launch discovery fixture: {error}"),
            }
        };
        let output = BufReader::new(child.stdout.take().unwrap());
        let fixture = Self(child);
        assert!(output.lines().any(|line| line.unwrap() == "ready"));
        fixture
    }
    fn list(&self, pattern: &str) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_poortrace"))
            .args([
                "-l",
                "-p",
                &self.0.id().to_string(),
                "--function-filter",
                pattern,
            ])
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn pid_listing_discovers_functions_and_shared_libraries_without_attachment() {
    let mut fixture = Fixture::spawn(&std::env::current_exe().unwrap());
    let out = fixture.list("poortrace_listing_target");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let output = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), 2, "{output}");
    assert!(lines[0].starts_with("uprobe:") && lines[0].ends_with(":poortrace_listing_target"));
    assert!(lines[1].starts_with("uretprobe:") && lines[1].ends_with(":poortrace_listing_target"));
    for line in &lines {
        poortrace::language::parse(&format!("{line} {{ @calls=count(); }}")).unwrap();
    }
    let out = fixture.list("malloc");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| line.starts_with("uprobe:") && line.ends_with(":malloc"))
    );
    let out = fixture.list("poortrace_nonexistent_symbol_12345");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(fixture.0.try_wait().unwrap().is_none());
}

#[test]
fn pid_listing_quotes_paths_for_scripts() {
    let dir = std::env::temp_dir().join(format!("poortrace listing {}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("fixture with spaces");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let fixture = Fixture::spawn(&executable);
    let out = fixture.list("poortrace_listing_target");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listing = String::from_utf8(out.stdout).unwrap();
    assert_eq!(listing.lines().count(), 2);
    for probe in listing.lines() {
        assert!(probe.contains("\"/"), "{probe}");
        let parsed = poortrace::language::parse(&format!("{probe} {{}}")).unwrap();
        let poortrace::language::Probe::Uprobe { path, function, .. } = &parsed[0].probes[0].1
        else {
            panic!()
        };
        assert_eq!(path, executable.to_str().unwrap());
        assert_eq!(function, "poortrace_listing_target");
        poortrace::uprobe::locate(fixture.0.id() as i32, path, function, false).unwrap();
    }
    drop(fixture);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_pid_listing_fails_instead_of_printing_generic_probe_families() {
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-l", "-p", "2147483647"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot inspect PID"));
}

#[test]
fn replaced_executable_path_is_not_advertised_as_the_loaded_image() {
    let dir = std::env::temp_dir().join(format!(
        "poortrace-deleted-discovery-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("fixture");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let fixture = Fixture::spawn(&executable);
    std::fs::remove_file(&executable).unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let out = fixture.list("poortrace_listing_target");
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("deleted"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(fixture);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn batch_native_resolution_preserves_order_offsets_and_validation() {
    let executable = std::env::current_exe().unwrap();
    let path = executable.to_str().unwrap();
    let pid = std::process::id() as i32;
    // Resolve a large batch of named and exact-offset bindings from one image.
    let functions = poortrace::uprobe::functions(pid, path, "poortrace_listing_target").unwrap();
    let offset = format!("0x{:x}", functions[0].offset);
    let mut requests = vec![(path, "poortrace_listing_target", false); 2048];
    requests[1] = (path, &offset, true);
    let resolved = poortrace::uprobe::locate_many(pid, &requests).unwrap();
    assert_eq!(resolved.len(), requests.len());
    for probe in &resolved {
        assert_eq!(probe.offset, functions[0].offset);
        assert!(probe.path.to_str().unwrap().ends_with(path));
    }
    let error = poortrace::uprobe::locate_many(pid, &[(path, "poortrace_listing_target+1", true)])
        .err()
        .unwrap();
    assert!(error.contains("omit the symbol offset"), "{error}");
    let error = poortrace::uprobe::locate_many(pid, &[(path, "0xffffffffffffffff", false)])
        .err()
        .unwrap();
    assert!(error.contains("outside executable segments"), "{error}");
}
