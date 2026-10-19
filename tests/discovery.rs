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
fn pid_listing_accepts_large_elf_and_rejects_images_above_the_limit() {
    let dir =
        std::env::temp_dir().join(format!("poortrace-large-discovery-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = std::env::current_exe().unwrap();
    let source_size = std::fs::metadata(&source).unwrap().len();
    // Static system libraries can contribute unsupported SDT notes. Padding and
    // relocating ELF tables must preserve the original lookup result, including
    // an explicit unsupported-note error.
    let expected_sites =
        poortrace::usdt::sites(std::process::id() as i32, source.to_str().unwrap())
            .map(|sites| serde_json::to_value(sites).unwrap());
    // Cover the production executable and the inclusive 4 GiB file boundary.
    for (size, accepted) in [
        (241_740_568u64.max(source_size), true),
        (4 * 1024 * 1024 * 1024, true),
        (4 * 1024 * 1024 * 1024 + 1, false),
    ] {
        let executable = dir.join(format!("fixture-{size}"));
        std::fs::copy(&source, &executable).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap()
            .set_len(size)
            .unwrap();
        if size == 4 * 1024 * 1024 * 1024 {
            move_elf_tables_above_three_gib(&executable);
        }
        let fixture = Fixture::spawn(&executable);
        let out = fixture.list("poortrace_listing_target");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.success(), accepted, "{stderr}");
        if accepted {
            assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 2);
            let functions = poortrace::uprobe::functions(
                fixture.0.id() as i32,
                executable.to_str().unwrap(),
                "poortrace_listing_target",
            )
            .unwrap();
            assert_eq!(functions.len(), 1);
            poortrace::uprobe::locate(
                fixture.0.id() as i32,
                executable.to_str().unwrap(),
                "poortrace_listing_target",
                false,
            )
            .unwrap();
            assert_eq!(
                poortrace::usdt::sites(fixture.0.id() as i32, executable.to_str().unwrap())
                    .map(|sites| serde_json::to_value(sites).unwrap()),
                expected_sites,
                "SDT lookup changed for {size}-byte fixture"
            );
        } else {
            assert!(out.stdout.is_empty());
            assert!(stderr.contains("exceeds 4 GiB"), "{stderr}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

// Keep load segments intact so the fixture still executes. Move section and
// symbol/string tables above the signed 32-bit offset range in a sparse file.
fn move_elf_tables_above_three_gib(path: &std::path::Path) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut header = [0u8; 64];
    file.read_exact(&mut header).unwrap();
    assert_eq!(&header[..6], b"\x7fELF\x02\x01");
    let section_offset = u64::from_le_bytes(header[40..48].try_into().unwrap());
    let section_size = u16::from_le_bytes(header[58..60].try_into().unwrap()) as usize;
    let section_count = u16::from_le_bytes(header[60..62].try_into().unwrap()) as usize;
    assert!(section_count > 0 && section_size >= 64);
    let mut sections = vec![0u8; section_size * section_count];
    file.seek(SeekFrom::Start(section_offset)).unwrap();
    file.read_exact(&mut sections).unwrap();
    let mut destination = 3 * 1024 * 1024 * 1024u64;
    for section in sections.chunks_exact_mut(section_size) {
        let kind = u32::from_le_bytes(section[4..8].try_into().unwrap());
        if ![2, 3, 11].contains(&kind) {
            continue;
        }
        let offset = u64::from_le_bytes(section[24..32].try_into().unwrap());
        let size = u64::from_le_bytes(section[32..40].try_into().unwrap());
        let mut bytes = vec![0u8; usize::try_from(size).unwrap()];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        file.seek(SeekFrom::Start(destination)).unwrap();
        file.write_all(&bytes).unwrap();
        section[24..32].copy_from_slice(&destination.to_le_bytes());
        destination = (destination + size + 7) & !7;
    }
    assert!(destination + sections.len() as u64 <= 4 * 1024 * 1024 * 1024);
    file.seek(SeekFrom::Start(destination)).unwrap();
    file.write_all(&sections).unwrap();
    header[40..48].copy_from_slice(&destination.to_le_bytes());
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&header).unwrap();
}

#[test]
#[ignore = "requires ptrace access to a launched command"]
fn live_four_gib_function_probes_and_symbolized_stacks() {
    let dir = std::env::temp_dir().join(format!("poortrace-large-tracing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("fixture");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&executable)
        .unwrap()
        .set_len(4 * 1024 * 1024 * 1024)
        .unwrap();
    move_elf_tables_above_three_gib(&executable);
    let probe = poortrace::discovery::function_probe_name(
        executable.to_str().unwrap(),
        "poortrace_listing_target",
        false,
    )
    .unwrap();
    let script = format!("{probe} {{ printf(\"%s\",ustack(8)); }}");
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .env("POORTRACE_LISTING_FIXTURE", "1")
        .args(["-q", "-e", &script, "--"])
        .arg(&executable)
        .args(["--exact", "process_fixture", "--nocapture"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("poortrace_listing_target"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
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

#[test]
fn flat_index_reuse_matches_native_listing_and_probe_resolution() {
    let dir = std::env::temp_dir().join(format!("poortrace-index-reuse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("fixture");
    let index = dir.join("fixture.ptidx");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    // Keep ELF tables above signed 32-bit offsets, as in the large binary test.
    move_elf_tables_above_three_gib(&binary);
    let pid = std::process::id() as i32;
    let path = binary.to_str().unwrap();
    let direct = poortrace::uprobe::functions(pid, path, "poortrace_listing*").unwrap();
    assert!(!direct.is_empty());
    let built = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--build-index",
            path,
            "--index-output",
            index.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    poortrace::binary_index::configure(std::slice::from_ref(&index)).unwrap();
    assert_eq!(
        poortrace::uprobe::functions(pid, path, "poortrace_listing*").unwrap(),
        direct
    );
    assert_eq!(
        poortrace::uprobe::functions(pid, path, "*listing_target").unwrap(),
        direct
            .iter()
            .filter(|f| f.name.ends_with("listing_target"))
            .cloned()
            .collect::<Vec<_>>()
    );
    let exact = poortrace::uprobe::functions(pid, path, "poortrace_listing_target").unwrap();
    assert_eq!(exact.len(), 1);
    let instruction_size = if cfg!(target_arch = "aarch64") { 4 } else { 1 };
    let offset_function = format!("poortrace_listing_target+{instruction_size}");
    let probes = poortrace::uprobe::locate_many(
        pid,
        &[
            (path, "poortrace_listing_target", false),
            (path, &offset_function, false),
        ],
    )
    .unwrap();
    assert_eq!(probes[0].offset, exact[0].offset);
    assert_eq!(probes[1].offset, exact[0].offset + instruction_size);
    assert!(poortrace::uprobe::locate(pid, path, &offset_function, true).is_err());
    poortrace::binary_index::configure(&[]).unwrap();
    let indexed = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--binary-index",
            index.to_str().unwrap(),
            "--list-functions",
            path,
            "--function-filter",
            "poortrace_listing_target",
        ])
        .output()
        .unwrap();
    assert!(
        indexed.status.success(),
        "{}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    assert_eq!(
        String::from_utf8(indexed.stdout).unwrap(),
        format!(
            "0x{:x} {} [{}]\n",
            exact[0].offset, exact[0].name, exact[0].demangled
        )
    );
    let fixture = Fixture::spawn(&binary);
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--binary-index",
            index.to_str().unwrap(),
            "-l",
            "-p",
            &fixture.0.id().to_string(),
            "--function-filter",
            "poortrace_listing_target",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, fixture.list("poortrace_listing_target").stdout);
    drop(fixture);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn flat_index_rejects_stale_replaced_truncated_files_and_binary_output() {
    let dir =
        std::env::temp_dir().join(format!("poortrace-index-validation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("fixture");
    let index = dir.join("fixture.ptidx");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let pid = std::process::id() as i32;
    let path = binary.to_str().unwrap();
    assert!(
        poortrace::binary_index::build(pid, path, &binary)
            .unwrap_err()
            .contains("differ")
    );
    poortrace::binary_index::build(pid, path, &index).unwrap();
    let lookup = || {
        Command::new(env!("CARGO_BIN_EXE_poortrace"))
            .args([
                "--binary-index",
                index.to_str().unwrap(),
                "--list-functions",
                path,
                "--function-filter",
                "poortrace_listing_target",
            ])
            .output()
            .unwrap()
    };
    let size = std::fs::metadata(&binary).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&binary)
        .unwrap()
        .set_len(size + 1)
        .unwrap();
    let out = lookup();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("stale binary index"));
    // Building again must work even if an old index exists.
    poortrace::binary_index::build(pid, path, &index).unwrap();
    assert!(lookup().status.success());
    std::fs::rename(&binary, dir.join("old-fixture")).unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let out = lookup();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("replaced"));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&index)
        .unwrap()
        .set_len(159)
        .unwrap();
    let out = lookup();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("index size"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "requires ptrace and a C compiler"]
fn live_flat_index_native_stacks_and_sdt_arguments() {
    let dir = std::env::temp_dir().join(format!("poortrace-index-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("usdt");
    let index = dir.join("usdt.ptidx");
    let compiled = Command::new("cc")
        .args([
            "-O1",
            "-fno-inline",
            "-no-pie",
            "tests/fixtures/usdt.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let path = binary.to_str().unwrap();
    poortrace::binary_index::build(std::process::id() as i32, path, &index).unwrap();
    let direct = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["--list-usdt", path])
        .output()
        .unwrap();
    let indexed = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--binary-index",
            index.to_str().unwrap(),
            "--list-usdt",
            path,
        ])
        .output()
        .unwrap();
    assert!(direct.status.success() && indexed.status.success());
    assert_eq!(direct.stdout, indexed.stdout);
    assert!(String::from_utf8_lossy(&indexed.stdout).contains("poortrace:work"));
    let script = format!(
        "usdt:{path:?}:poortrace:work {{ @calls=count(); @sum=sum(arg0); @small=sum(arg1); @memory=sum(arg2); printf(\"%s\",ustack(8)); }}"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--binary-index",
            index.to_str().unwrap(),
            "-q",
            "-e",
            &script,
            "--",
            path,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    for expected in [
        "@calls: 3",
        "@sum: 6",
        "@small: -15",
        "@memory: -297",
        "fire",
        "semaphore=1",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    // Keep an unsupported SDT descriptor explicit without losing native names.
    let mut bytes = std::fs::read(&binary).unwrap();
    let marker = b"poortrace\0work\0-8@";
    let at = bytes
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    bytes[at + marker.len() - 2] = b'9';
    std::fs::write(&binary, bytes).unwrap();
    poortrace::binary_index::build(std::process::id() as i32, path, &index).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--binary-index",
            index.to_str().unwrap(),
            "--list-functions",
            path,
            "--function-filter",
            "fire",
        ])
        .output()
        .unwrap();
    assert!(out.status.success() && !out.stdout.is_empty());
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args([
            "--binary-index",
            index.to_str().unwrap(),
            "--list-usdt",
            path,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("SDT argument sizes"));
    std::fs::remove_dir_all(dir).unwrap();
}
