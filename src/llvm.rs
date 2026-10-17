//! Minimal, version-stable LLVM C API surface; llvm-config selects the libraries.
use crate::{Result, runtime};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    ptr,
    sync::Once,
};

type Ref = *mut c_void;
unsafe extern "C" {
    fn LLVMContextCreate() -> Ref;
    fn LLVMContextDispose(ctx: Ref);
    fn LLVMCreateMemoryBufferWithMemoryRangeCopy(
        data: *const c_char,
        len: usize,
        name: *const c_char,
    ) -> Ref;
    fn LLVMParseIRInContext(ctx: Ref, buf: Ref, module: *mut Ref, error: *mut *mut c_char)
    -> c_int;
    fn LLVMVerifyModule(module: Ref, action: c_uint, error: *mut *mut c_char) -> c_int;
    fn LLVMDisposeModule(module: Ref);
    fn LLVMDisposeMessage(msg: *mut c_char);
    fn LLVMLinkInMCJIT();
    fn LLVMInitializeMCJITCompilerOptions(options: *mut Options, len: usize);
    fn LLVMCreateMCJITCompilerForModule(
        engine: *mut Ref,
        module: Ref,
        options: Ref,
        len: usize,
        error: *mut *mut c_char,
    ) -> c_int;
    fn LLVMDisposeExecutionEngine(engine: Ref);
    fn LLVMGetNamedFunction(module: Ref, name: *const c_char) -> Ref;
    fn LLVMAddGlobalMapping(engine: Ref, value: Ref, address: Ref);
    fn LLVMGetFunctionAddress(engine: Ref, name: *const c_char) -> u64;
    #[cfg(target_arch = "aarch64")]
    fn LLVMInitializeAArch64TargetInfo();
    #[cfg(target_arch = "aarch64")]
    fn LLVMInitializeAArch64Target();
    #[cfg(target_arch = "aarch64")]
    fn LLVMInitializeAArch64TargetMC();
    #[cfg(target_arch = "aarch64")]
    fn LLVMInitializeAArch64AsmPrinter();
    #[cfg(target_arch = "x86_64")]
    fn LLVMInitializeX86TargetInfo();
    #[cfg(target_arch = "x86_64")]
    fn LLVMInitializeX86Target();
    #[cfg(target_arch = "x86_64")]
    fn LLVMInitializeX86TargetMC();
    #[cfg(target_arch = "x86_64")]
    fn LLVMInitializeX86AsmPrinter();
}

#[repr(C)]
#[derive(Default)]
struct Options {
    opt_level: c_uint,
    code_model: c_uint,
    no_frame_pointer_elim: c_int,
    enable_fast_isel: c_int,
    memory_manager: Ref,
}

pub(crate) struct Engine {
    engine: Ref,
    context: Ref,
}
pub(crate) type Handler = unsafe extern "C" fn(*mut runtime::State<'_>, *const runtime::Event<'_>);
impl Engine {
    pub fn compile(ir: &str, count: usize) -> Result<(Self, Vec<Handler>)> {
        static INIT: Once = Once::new();
        INIT.call_once(|| unsafe {
            LLVMLinkInMCJIT();
            #[cfg(target_arch = "aarch64")]
            {
                LLVMInitializeAArch64TargetInfo();
                LLVMInitializeAArch64Target();
                LLVMInitializeAArch64TargetMC();
                LLVMInitializeAArch64AsmPrinter();
            }
            #[cfg(target_arch = "x86_64")]
            {
                LLVMInitializeX86TargetInfo();
                LLVMInitializeX86Target();
                LLVMInitializeX86TargetMC();
                LLVMInitializeX86AsmPrinter();
            }
        });
        // Engine owns the parsed module; context must outlive it. ParseIR consumes
        // its memory buffer on both success and failure.
        unsafe {
            let context = LLVMContextCreate();
            let buf = LLVMCreateMemoryBufferWithMemoryRangeCopy(
                ir.as_ptr().cast(),
                ir.len(),
                c"poortrace".as_ptr(),
            );
            let mut module = ptr::null_mut();
            let mut error = ptr::null_mut();
            if LLVMParseIRInContext(context, buf, &mut module, &mut error) != 0 {
                let message = take_message(error);
                LLVMContextDispose(context);
                return Err(format!("LLVM IR: {message}"));
            }
            if LLVMVerifyModule(module, 2, &mut error) != 0 {
                let message = take_message(error);
                LLVMDisposeModule(module);
                LLVMContextDispose(context);
                return Err(format!("LLVM verification: {message}"));
            }
            if !error.is_null() {
                LLVMDisposeMessage(error);
            }
            error = ptr::null_mut();
            let mut engine = ptr::null_mut();
            let mut options = Options::default();
            LLVMInitializeMCJITCompilerOptions(&mut options, size_of::<Options>());
            options.opt_level = 2;
            if LLVMCreateMCJITCompilerForModule(
                &mut engine,
                module,
                (&mut options as *mut Options).cast(),
                size_of::<Options>(),
                &mut error,
            ) != 0
            {
                let message = take_message(error);
                // MCJIT takes ownership of the module even if engine creation fails.
                LLVMContextDispose(context);
                return Err(format!("LLVM JIT: {message}"));
            }
            let owner = Self { engine, context };
            let mappings: &[(&CStr, Ref)] = &[
                (c"pt_ustack", runtime::ustack as *const () as Ref),
                (c"pt_map_update", runtime::map_update as *const () as Ref),
                (c"pt_map_get", runtime::map_get as *const () as Ref),
                (c"pt_printf", runtime::print as *const () as Ref),
                (c"pt_map_action", runtime::map_action as *const () as Ref),
                (c"pt_exit", runtime::stop as *const () as Ref),
                (c"pt_stopped", runtime::stopped as *const () as Ref),
                (c"pt_streq", runtime::streq as *const () as Ref),
            ];
            for (name, address) in mappings {
                LLVMAddGlobalMapping(
                    engine,
                    LLVMGetNamedFunction(module, name.as_ptr()),
                    *address,
                );
            }
            let mut handlers = Vec::new();
            for i in 0..count {
                let name = CString::new(format!("probe_{i}")).unwrap();
                let address = LLVMGetFunctionAddress(engine, name.as_ptr());
                if address == 0 {
                    return Err(format!("LLVM JIT did not produce probe_{i}"));
                }
                handlers.push(std::mem::transmute::<usize, Handler>(address as usize));
            }
            Ok((owner, handlers))
        }
    }
}
unsafe fn take_message(msg: *mut c_char) -> String {
    if msg.is_null() {
        return "unknown LLVM error".into();
    }
    let result = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        LLVMDisposeMessage(msg);
    }
    result
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            LLVMDisposeExecutionEngine(self.engine);
            LLVMContextDispose(self.context);
        }
    }
}
