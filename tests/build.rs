#[path = "../build_support.rs"]
mod build_support;

use build_support::{Probe, candidates, cxx_variables, registered_toolsets, select};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT: AtomicU64 = AtomicU64::new(0);
static FIXTURES: Mutex<()> = Mutex::new(());

struct Fixture {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}
impl Fixture {
    fn new() -> Self {
        // A concurrent spawn can inherit another fixture's open script writer
        // until exec closes it, causing intermittent ETXTBSY on that script.
        // Keep fixture creation and compiler execution in one critical section.
        let guard = FIXTURES.lock().unwrap_or_else(|error| error.into_inner());
        let path = std::env::temp_dir().join(format!(
            "poortrace-build-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self {
            path,
            _guard: guard,
        }
    }

    fn compiler(&self, name: &str, link_status: u8) -> OsString {
        let script = self.path.join(name);
        let libraries = self.path.join("compiler libraries");
        fs::create_dir_all(&libraries).unwrap();
        for library in ["libstdc++.so", "libstdc++.a"] {
            fs::write(libraries.join(library), b"fixture").unwrap();
        }
        // Derive fixture paths from the executable itself. No shell expansion
        // of interpolated filenames or compiler arguments is needed.
        let body = format!(
            "#!/bin/sh\n\
             compiler_dir=${{0%/*}}\n\
             case \"$1\" in\n\
             -print-file-name=*) printf '%s/compiler libraries/%s\\n' \"$compiler_dir\" \"${{1#*=}}\"; exit 0;;\n\
             esac\n\
             printf '%s\\n' \"$@\" > \"$compiler_dir/{name}.args\"\n\
             echo 'fixture linker result' >&2\n\
             exit {link_status}\n"
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script.into_os_string()
    }

    fn probe(&self, static_crt: bool) -> Probe<'_> {
        Probe {
            directory: &self.path,
            architecture: "x86_64",
            llvm_directory: &self.path,
            llvm_libraries: "-lLLVMCore -lLLVMX86CodeGen",
            system_libraries: "-lz -ldl",
            static_crt,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn explicit_cxx_failure_never_falls_back_and_reports_linker_output() {
    let fixture = Fixture::new();
    let bad = fixture.compiler("bad", 13);
    let good = fixture.compiler("good", 0);
    let error = match select(Some(bad), vec![good], &fixture.probe(false)) {
        Ok(_) => panic!("explicit failing CXX was ignored"),
        Err(error) => error,
    };
    assert!(error.contains("configured CXX"));
    assert!(error.contains("fixture linker result"), "{error}");
    assert!(error.contains("LLVM_CONFIG"));
    assert!(!fixture.path.join("good.args").exists());
    assert!(fixture.path.join("llvm-link-probe.log").exists());
}

#[test]
fn automatic_selection_skips_bad_compilers_and_retains_the_library_directory() {
    let fixture = Fixture::new();
    let bad = fixture.compiler("bad", 13);
    let good = fixture.compiler("good compiler", 0);
    let selected = select(None, vec![bad, good.clone()], &fixture.probe(false)).unwrap();
    assert_eq!(selected.compiler, good);
    assert_eq!(
        selected.library_directory,
        fixture.path.join("compiler libraries")
    );
    let arguments = fs::read_to_string(fixture.path.join("good compiler.args")).unwrap();
    assert!(arguments.contains("-lLLVMX86CodeGen"));
    assert!(arguments.contains("-lz"));
    assert!(!arguments.lines().any(|arg| arg == "-static"));
    let source = fs::read_to_string(fixture.path.join("llvm-link-probe.cpp")).unwrap();
    assert!(source.contains("LLVMInitializeX86AsmPrinter();"));
    assert!(source.contains("LLVMLinkInMCJIT();"));
}

#[test]
fn static_crt_checks_a_static_link_and_requires_the_cpp_archive() {
    let fixture = Fixture::new();
    let compiler = fixture.compiler("good", 0);
    let probe = fixture.probe(true);
    select(Some(compiler.clone()), Vec::new(), &probe).unwrap();
    let arguments = fs::read_to_string(fixture.path.join("good.args")).unwrap();
    assert!(arguments.lines().any(|arg| arg == "-static"));
    fs::remove_file(fixture.path.join("compiler libraries/libstdc++.a")).unwrap();
    let error = probe.library_directory(&compiler).unwrap_err();
    assert!(error.contains("libstdc++.a"));
}

#[test]
fn target_selection_does_not_use_host_toolsets_for_cross_builds() {
    assert_eq!(
        cxx_variables("host", "target-triplet"),
        vec![
            "CXX_target-triplet",
            "CXX_target_triplet",
            "TARGET_CXX",
            "CXX",
        ]
    );
    let compilers = candidates("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu");
    assert!(compilers.contains(&OsString::from("aarch64-linux-gnu-g++")));
    assert!(
        compilers
            .iter()
            .all(|compiler| !Path::new(compiler).is_absolute())
    );
}

#[test]
fn toolset_registration_supplies_roots_and_sorts_versions_numerically() {
    let fixture = Fixture::new();
    let registry = fixture.path.join("registry");
    let prefix = fixture.path.join("registered root");
    fs::create_dir(&registry).unwrap();
    for name in ["gcc-toolset-9", "gcc-toolset-15", "devtoolset-12"] {
        let compiler = prefix.join(name).join("root/usr/bin/g++");
        fs::create_dir_all(compiler.parent().unwrap()).unwrap();
        fs::write(&compiler, b"fixture").unwrap();
        fs::write(registry.join(name), prefix.to_str().unwrap()).unwrap();
    }
    fs::write(
        registry.join("gcc-toolset-invalid"),
        prefix.to_str().unwrap(),
    )
    .unwrap();
    let compilers = registered_toolsets(&registry);
    assert_eq!(compilers.len(), 3);
    assert!(Path::new(&compilers[0]).starts_with(prefix.join("gcc-toolset-15")));
    assert!(Path::new(&compilers[1]).starts_with(prefix.join("devtoolset-12")));
    assert!(Path::new(&compilers[2]).starts_with(prefix.join("gcc-toolset-9")));
}
