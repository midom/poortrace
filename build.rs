use std::process::Command;

fn llvm(config: &str, args: &[&str]) -> String {
    let output = Command::new(config)
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!("cannot run {config}: {e}; install LLVM development packages or set LLVM_CONFIG")
        });
    assert!(output.status.success(), "{config} {args:?} failed");
    String::from_utf8(output.stdout)
        .expect("llvm-config output is UTF-8")
        .trim()
        .into()
}

fn main() {
    println!("cargo:rerun-if-env-changed=LLVM_CONFIG");
    let config = std::env::var("LLVM_CONFIG").unwrap_or_else(|_| "llvm-config".into());
    let version = llvm(&config, &["--version"]);
    let major: u32 = version.split('.').next().unwrap().parse().unwrap();
    assert!(
        major >= 15,
        "LLVM 15 or newer is required (found {version})"
    );
    let libdir = llvm(&config, &["--libdir"]);
    println!("cargo:rustc-link-search=native={libdir}");
    for flag in llvm(
        &config,
        &[
            "--link-shared",
            "--libs",
            "core",
            "irreader",
            "executionengine",
            "mcjit",
            "native",
        ],
    )
    .split_whitespace()
    {
        if let Some(name) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={name}");
        }
    }
    println!("cargo:rustc-env=POORTRACE_LLVM_VERSION={version}");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{libdir}");
}
