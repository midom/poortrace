#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("poortrace requires 64-bit Linux");
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("poortrace supports AArch64 and x86-64");

pub mod binary_index;
pub mod codegen;
pub mod counters;
mod elf_image;
mod file_identity;
pub mod language;
mod llvm;
pub mod memory;
pub mod perf;
pub mod report;
pub mod runtime;
mod symbols;
pub mod syscall;

pub type Result<T> = std::result::Result<T, String>;

pub mod uprobe;

pub mod functions;

pub mod recording;

pub mod usdt;

pub mod python;

pub mod types;

pub mod wait;

pub mod javascript;

pub mod golang;

pub mod kernel;

pub mod arguments;

pub mod btf;
pub mod managed_bridge;

pub mod capture;

pub mod native_args;

pub mod discovery;

mod builtins;
