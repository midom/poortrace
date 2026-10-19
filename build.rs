mod build_support;
use std::process::Command;

fn llvm(config: &str, args: &[&str]) -> String {
    let output = Command::new(config)
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!("cannot run {config}: {e}; install LLVM development packages or set LLVM_CONFIG")
        });
    assert!(
        output.status.success(),
        "{config} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("llvm-config output is UTF-8")
        .trim()
        .into()
}

fn main() {
    println!("cargo:rerun-if-env-changed=LLVM_CONFIG");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    let host = std::env::var("HOST").expect("Cargo supplies HOST");
    let target = std::env::var("TARGET").expect("Cargo supplies TARGET");
    let cxx_variables = build_support::cxx_variables(&host, &target);
    for variable in &cxx_variables {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let config = std::env::var("LLVM_CONFIG").unwrap_or_else(|_| "llvm-config".into());
    let version = llvm(&config, &["--version"]);
    let major: u32 = version.split('.').next().unwrap().parse().unwrap();
    assert!(
        major >= 15,
        "LLVM 15 or newer is required (found {version})"
    );
    let libdir = llvm(&config, &["--libdir"]);
    println!("cargo:rustc-link-search=native={libdir}");
    let static_crt = std::env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .any(|feature| feature == "crt-static");
    let static_llvm = static_crt || std::env::var_os("CARGO_FEATURE_STATIC_LLVM").is_some();
    let mode = if static_llvm {
        "--link-static"
    } else {
        "--link-shared"
    };
    let kind = if static_llvm { "static" } else { "dylib" };
    let libraries = llvm(
        &config,
        &[
            mode,
            "--libs",
            "core",
            "irreader",
            "executionengine",
            "mcjit",
            "native",
        ],
    );
    for flag in libraries.split_whitespace() {
        if let Some(name) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={kind}={name}");
        }
    }
    if static_llvm {
        let system_libraries = llvm(&config, &[mode, "--system-libs"]);
        let directory =
            std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
        let architecture =
            std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo supplies target architecture");
        let explicit = cxx_variables.iter().find_map(std::env::var_os);
        let probe = build_support::Probe {
            directory: &directory,
            architecture: &architecture,
            llvm_directory: std::path::Path::new(&libdir),
            llvm_libraries: &libraries,
            system_libraries: &system_libraries,
            static_crt,
        };
        let selection =
            build_support::select(explicit, build_support::candidates(&host, &target), &probe)
                .unwrap_or_else(|error| panic!("static LLVM {version}: {error}"));
        println!(
            "cargo:warning=LLVM {version} link test passed with {}",
            selection.compiler.to_string_lossy(),
        );
        // Retain the selected C++ search path in library metadata so binaries,
        // integration tests, and downstream crates use the same linker script.
        println!(
            "cargo:rustc-link-search=native={}",
            selection.library_directory.display(),
        );
        // LLVM's component archives do not include its system dependencies or
        // the C++ standard library. Keep system libraries dynamic unless the
        // executable itself is being linked statically.
        // With crt-static, let the linker find archives in its default system
        // search paths (which are not necessarily in rustc's archive search path).
        let system_kind = if static_crt { "" } else { "dylib=" };
        for flag in system_libraries.split_whitespace() {
            if let Some(name) = flag.strip_prefix("-l") {
                println!("cargo:rustc-link-lib={system_kind}{name}");
            } else if let Some(path) = flag.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={path}");
            } else if std::path::Path::new(flag).is_absolute() {
                // Preserve dependencies in the library's metadata so integration
                // tests and other consumers receive them too.
                let path = std::path::Path::new(flag);
                let archive = path.extension().is_some_and(|ext| ext == "a");
                assert!(
                    !static_crt || archive,
                    "llvm-config reported a shared system library for a fully static build: {flag}; use an LLVM installation configured with static system dependencies"
                );
                let kind = if archive { "static" } else { "dylib" };
                let directory = path.parent().unwrap().display();
                let filename = path.file_name().unwrap().to_str().unwrap();
                println!("cargo:rustc-link-search=native={directory}");
                println!("cargo:rustc-link-lib={kind}:+verbatim={filename}");
            } else {
                panic!("unsupported llvm-config system library flag: {flag}");
            }
        }
        println!("cargo:rustc-link-lib={system_kind}stdc++");
    } else {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{libdir}");
    }
    println!("cargo:rustc-env=POORTRACE_LLVM_VERSION={version}");
}
