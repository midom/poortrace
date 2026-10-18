//! Launch gating, owned-process cleanup, signals, and task discovery.

use super::{cli::Args, events::monotonic_ns};
use poortrace::{Result, runtime::State};
use std::{
    collections::BTreeSet,
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
pub(super) fn install_signals() -> Result<()> {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = interrupt as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }
    }
    Ok(())
}
pub(super) fn threads(pid: i32) -> Result<BTreeSet<i32>> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map_err(|e| format!("cannot inspect PID {pid}: {e}"))?
        .map(|entry| {
            entry.map_err(|e| e.to_string()).and_then(|e| {
                e.file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .map_err(|e| e.to_string())
            })
        })
        .collect()
}
pub(super) fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .is_some_and(|(_, rest)| !rest.starts_with(" Z") && !rest.starts_with(" X"))
    })
}

pub(super) struct Child {
    pub(super) pid: i32,
    gate: Option<OwnedFd>,
    pub(super) status: Option<i32>,
    descendants: std::collections::BTreeMap<i32, OwnedFd>,
    output: Option<TargetOutput>,
    pub(super) terminated_by_tracer: bool,
}
struct TargetOutput {
    pipes: [OwnedFd; 2],
}
fn output_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut pair = [0; 2];
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut owned = [unsafe { OwnedFd::from_raw_fd(pair[0]) }, unsafe {
        OwnedFd::from_raw_fd(pair[1])
    }];
    for descriptor in &mut owned {
        if descriptor.as_raw_fd() < 3 {
            let fd = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            *descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
        }
    }
    let [read, write] = owned;
    Ok((read, write))
}
impl Child {
    pub(super) fn spawn(args: &[String], follow: bool, capture_output: bool) -> Result<Self> {
        if follow && unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
            return Err(format!(
                "enabling owned descendant reaping: {}",
                io::Error::last_os_error()
            ));
        }
        let args: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_str()).map_err(|_| "command contains NUL".to_string()))
            .collect::<Result<_>>()?;
        let mut argv: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());
        let output = if capture_output {
            Some([output_pipe()?, output_pipe()?])
        } else {
            None
        };
        // Keep the gate clear of dup2 destinations even when the caller closed
        // standard descriptors before starting the tracer.
        let (read, write) = output_pipe()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", io::Error::last_os_error()));
        }
        if pid == 0 {
            // Only async-signal-safe operations between fork and exec. The pipe
            // gate holds the child until perf streams and BEGIN handlers are ready.
            unsafe {
                libc::setpgid(0, 0);
                if let Some(pipes) = &output {
                    for (index, (read, write)) in pipes.iter().enumerate() {
                        if libc::dup2(write.as_raw_fd(), index as i32 + 1) < 0 {
                            libc::_exit(125);
                        }
                        libc::close(read.as_raw_fd());
                        libc::close(write.as_raw_fd());
                    }
                }
                libc::close(write.as_raw_fd());
                let mut byte = 0u8;
                loop {
                    let n = libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                    if n == 1 {
                        break;
                    }
                    if n < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    libc::_exit(125);
                }
                libc::close(read.as_raw_fd());
                // Restore dispositions changed by the tracer before exec.
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::execvp(args[0].as_ptr(), argv.as_ptr());
                let msg = b"poortrace: cannot execute command\n";
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(127);
            }
        }
        unsafe {
            libc::setpgid(pid, pid);
        }
        drop(read);
        let output = if let Some([(read_out, write_out), (read_err, write_err)]) = output {
            drop(write_out);
            drop(write_err);
            for fd in [&read_out, &read_err] {
                let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
                if flags < 0
                    || unsafe {
                        libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    } < 0
                {
                    let error = io::Error::last_os_error();
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                    return Err(error.to_string());
                }
            }
            Some(TargetOutput {
                pipes: [read_out, read_err],
            })
        } else {
            None
        };
        Ok(Self {
            pid,
            gate: Some(write),
            status: None,
            descendants: std::collections::BTreeMap::new(),
            output,
            terminated_by_tracer: false,
        })
    }
    pub(super) fn poll_output(
        &mut self,
        mut recorder: Option<&mut poortrace::recording::Recorder>,
    ) -> Result<()> {
        let Some(output) = &self.output else {
            return Ok(());
        };
        for (index, fd) in output.pipes.iter().enumerate() {
            let mut buffer = [0u8; 4096];
            for _ in 0..256 {
                let n =
                    unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if n == 0 {
                    break;
                }
                if n < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(format!("target output: {error}"));
                }
                let bytes = &buffer[..n as usize];
                let mut offset = 0;
                while offset < bytes.len() {
                    let written = unsafe {
                        libc::write(
                            index as i32 + 1,
                            bytes[offset..].as_ptr().cast(),
                            bytes.len() - offset,
                        )
                    };
                    if written < 0
                        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    if written <= 0 {
                        return Err(format!(
                            "forwarding target output: {}",
                            io::Error::last_os_error()
                        ));
                    }
                    offset += written as usize;
                }
                if let Some(recorder) = recorder.as_deref_mut() {
                    recorder.metadata(&poortrace::recording::Metadata::Output {
                        pid: self.pid as u64,
                        nsecs: monotonic_ns(),
                        stream: if index == 0 { "stdout" } else { "stderr" }.into(),
                        bytes: bytes.to_vec(),
                    })?;
                }
            }
        }
        Ok(())
    }
    fn kill_descendants(&self) {
        for fd in self.descendants.values() {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
        }
    }
    pub(super) fn start(&mut self) -> Result<()> {
        if let Some(fd) = self.gate.take() {
            let byte = 1u8;
            if unsafe { libc::write(fd.as_raw_fd(), (&byte as *const u8).cast(), 1) } != 1 {
                return Err(format!("starting command: {}", io::Error::last_os_error()));
            }
        }
        Ok(())
    }
    pub(super) fn check(&mut self) -> Result<Option<i32>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                return Ok(None);
            }
            return Err(format!("waitpid: {}", io::Error::last_os_error()));
        }
        if result == self.pid {
            self.status = Some(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
            // Also release any background descendants left in this owned group.
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
        Ok(self.status)
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        self.kill_descendants();
        if self.status.is_none() {
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
                libc::kill(self.pid, libc::SIGKILL);
            }
            loop {
                if unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) } >= 0
                    || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
        if !self.descendants.is_empty() {
            loop {
                let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) };
                if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
        }
    }
}

pub(super) fn command_for(args: &Args) -> Vec<String> {
    args.shell_command
        .as_ref()
        .map(|s| vec!["/bin/sh".into(), "-c".into(), s.clone()])
        .unwrap_or_else(|| args.command.clone())
}
pub(super) fn finalize_recorded_child(
    state: &mut State<'_>,
    child: Option<&mut Child>,
) -> Result<()> {
    if state.recorder.is_none() {
        return Ok(());
    }
    let Some(child) = child else {
        return Ok(());
    };
    if child.status.is_none() {
        child.terminated_by_tracer = true;
        child.kill_descendants();
        unsafe {
            libc::kill(-child.pid, libc::SIGKILL);
            libc::kill(child.pid, libc::SIGKILL);
        }
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(child.pid, &mut status, 0) };
            if result == child.pid {
                child.status = Some(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("reaping recorded command: {error}"));
        }
    }
    child.poll_output(state.recorder.as_mut())?;
    if let Some(status) = child.status {
        state
            .recorder
            .as_mut()
            .unwrap()
            .metadata(&poortrace::recording::Metadata::Exit {
                pid: child.pid as u64,
                nsecs: monotonic_ns(),
                status,
            })?;
    }
    Ok(())
}
pub(super) fn kill_owned_descendants(child: Option<&Child>, follow: bool, _targets: BTreeSet<i32>) {
    if follow {
        if let Some(child) = child {
            child.kill_descendants();
        }
    }
}
pub(super) fn track_owned_descendants(
    child: &mut Option<Child>,
    follow: bool,
    targets: BTreeSet<i32>,
) -> Result<()> {
    if !follow {
        return Ok(());
    }
    let Some(child) = child else {
        return Ok(());
    };
    child.descendants.retain(|pid, fd| {
        if targets.contains(pid) {
            return true;
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        (unsafe { libc::poll(&mut poll, 1, 0) }) <= 0 || poll.revents & libc::POLLIN == 0
    });
    for pid in targets {
        if pid == child.pid || child.descendants.contains_key(&pid) {
            continue;
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(format!("pidfd_open for owned descendant {pid}: {error}"));
        }
        child
            .descendants
            .insert(pid, unsafe { OwnedFd::from_raw_fd(fd as i32) });
    }
    Ok(())
}
