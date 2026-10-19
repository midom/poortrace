//! C++ compiler selection and link checks for the Cargo build script.
use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn cxx_variables(host: &str, target: &str) -> Vec<String> {
    let mut variables = vec![
        format!("CXX_{target}"),
        format!("CXX_{}", target.replace('-', "_")),
        if host == target {
            "HOST_CXX"
        } else {
            "TARGET_CXX"
        }.into(),
        "CXX".into(),
    ];
    variables.dedup();
    variables
}

fn toolset_version(name: &str) -> Option<u64> {
    name.strip_prefix("gcc-toolset-")
        .or_else(|| name.strip_prefix("devtoolset-"))?
        .parse()
        .ok()
}

/// Discover optional GCC toolsets from their registration files. Installation
/// roots come from the files; no compiler version or installation root is fixed.
pub fn registered_toolsets(registry: &Path) -> Vec<OsString> {
    let Ok(entries) = fs::read_dir(registry) else {
        return Vec::new();
    };
    let mut toolsets = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(version) = name.to_str().and_then(toolset_version) else {
            continue;
        };
        let Ok(prefix) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let prefix = Path::new(prefix.trim());
        if !prefix.is_absolute() {
            continue;
        }
        let compiler = prefix.join(&name).join("root/usr/bin/g++");
        if compiler.is_file() {
            toolsets.push((version, compiler));
        }
    }
    toolsets.sort_by(|a, b| b.cmp(a));
    toolsets.into_iter()
        .map(|(_, path)| path.into_os_string())
        .collect()
}

pub fn candidates(host: &str, target: &str) -> Vec<OsString> {
    if host != target {
        // Cross builds must use a target compiler, never an available host
        // toolset. An explicit target CXX remains the preferred choice.
        return vec![
            format!("{target}-g++").into(),
            format!("{}-g++", target.replace("-unknown", "")).into(),
        ];
    }
    let mut compilers = vec!["c++".into(), "g++".into(), "clang++".into()];
    compilers.extend(registered_toolsets(Path::new("/etc/scl/prefixes")));
    compilers
}

pub struct Probe<'a> {
    pub directory: &'a Path,
    pub architecture: &'a str,
    pub llvm_directory: &'a Path,
    pub llvm_libraries: &'a str,
    pub system_libraries: &'a str,
    pub static_crt: bool,
}

impl Probe<'_> {
    pub fn library_directory(&self, compiler: &OsStr) -> Result<PathBuf, String> {
        let library = if self.static_crt {
            "libstdc++.a"
        } else {
            "libstdc++.so"
        };
        let result = Command::new(compiler)
            .arg(format!("-print-file-name={library}"))
            .output()
            .map_err(|e| format!("cannot query {}: {e}", compiler.to_string_lossy()))?;
        if !result.status.success() {
            return Err(format!(
                "{} cannot locate {library}: {}",
                compiler.to_string_lossy(), String::from_utf8_lossy(&result.stderr),
            ));
        }
        let output = String::from_utf8(result.stdout)
            .map_err(|_| "C++ compiler library path is not UTF-8")?;
        let path = Path::new(output.trim());
        if !path.is_absolute() || !path.is_file() {
            return Err(format!(
                "{} did not locate a usable {library}; install its C++ development libraries",
                compiler.to_string_lossy(),
            ));
        }
        path.parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "C++ library directory is missing".into())
    }

    pub fn check(&self, compiler: &OsStr) -> Result<(), String> {
        let target = match self.architecture {
            "x86_64" => "X86",
            "aarch64" => "AArch64",
            other => return Err(format!("unsupported LLVM link probe architecture: {other}")),
        };
        let source = self.directory.join("llvm-link-probe.cpp");
        let executable = self.directory.join("llvm-link-probe");
        let code = format!(
            "extern \"C\" {{\nvoid LLVMLinkInMCJIT();\n\
             void LLVMInitialize{target}TargetInfo();\n\
             void LLVMInitialize{target}Target();\n\
             void LLVMInitialize{target}TargetMC();\n\
             void LLVMInitialize{target}AsmPrinter();\n}}\n\
             int main() {{\nLLVMLinkInMCJIT();\n\
             LLVMInitialize{target}TargetInfo();\nLLVMInitialize{target}Target();\n\
             LLVMInitialize{target}TargetMC();\nLLVMInitialize{target}AsmPrinter();\n\
             return 0;\n}}\n"
        );
        fs::write(&source, code).map_err(|e| format!("cannot write LLVM link probe: {e}"))?;
        let mut command = Command::new(compiler);
        command.arg(&source).arg("-o").arg(&executable);
        if self.static_crt {
            command.arg("-static");
        }
        command.arg("-L")
            .arg(self.llvm_directory)
            .args(self.llvm_libraries.split_whitespace())
            .args(self.system_libraries.split_whitespace());
        let result = command.output()
            .map_err(|e| format!("cannot run {}: {e}", compiler.to_string_lossy()))?;
        if result.status.success() {
            return Ok(());
        }
        // Retain the complete linker output for diagnosis without printing a
        // potentially very long list of unresolved archive symbols in Cargo.
        let log = self.directory.join("llvm-link-probe.log");
        let mut output = result.stderr;
        output.extend(result.stdout);
        fs::write(&log, &output).map_err(|e| format!("cannot write LLVM link probe log: {e}"))?;
        let detail = String::from_utf8_lossy(&output);
        let detail: String = detail.chars().take(4000).collect();
        Err(format!(
            "{} failed the LLVM link test ({}):\n{detail}\nFull output: {}",
            compiler.to_string_lossy(), result.status, log.display(),
        ))
    }
}

pub struct Selection {
    pub compiler: OsString,
    pub library_directory: PathBuf,
}

pub fn select(
    explicit: Option<OsString>,
    candidates: Vec<OsString>,
    probe: &Probe<'_>,
) -> Result<Selection, String> {
    let explicit_set = explicit.is_some();
    let candidates = explicit.map_or(candidates, |compiler| vec![compiler]);
    let mut failures = Vec::new();
    for compiler in candidates {
        match probe.library_directory(&compiler).and_then(|library_directory| {
            probe.check(&compiler).map(|()| library_directory)
        }) {
            Ok(library_directory) => return Ok(Selection {
                compiler,
                library_directory,
            }),
            Err(error) => failures.push(error),
        }
    }
    let heading = if explicit_set {
        "The configured CXX cannot link the selected LLVM archives."
    } else {
        "No available C++ compiler can link the selected LLVM archives."
    };
    Err(format!("{heading}\nInstall a compatible C++ development toolchain or set CXX to its compiler executable.\nCheck LLVM_CONFIG and the target architecture.\n{}", failures.join("\n\n")))
}
