//! Bounded, read-only target memory access; Linux performs the ptrace access check.
use crate::Result;

pub fn read(pid: u32, address: u64, length: usize, partial: bool) -> Result<Vec<u8>> {
    read_bounded(pid, address, length, partial, 4096)
}

/// Stack snapshots have a separate bound from script-visible memory helpers.
/// Partial reads retain the accessible prefix when the stack ends at a guard page.
pub fn read_stack(pid: u32, address: u64, length: usize) -> Result<Vec<u8>> {
    read_bounded(pid, address, length, true, 32768)
}

fn read_bounded(
    pid: u32,
    address: u64,
    length: usize,
    partial: bool,
    limit: usize,
) -> Result<Vec<u8>> {
    if length == 0 || length > limit || address.checked_add(length as u64).is_none() {
        return Err(format!(
            "memory reads require 1..{limit} bytes and a valid address range"
        ));
    }
    let mut bytes = vec![0; length];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: length,
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: length,
    };
    let count = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if count < 0 {
        return Err(format!(
            "read memory PID {pid} at 0x{address:x}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if !partial && count as usize != length {
        return Err(format!("short memory read: {count} of {length} bytes"));
    }
    bytes.truncate(count as usize);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_stack_capture_retains_independent_helper_bounds() {
        let data = vec![0x5au8; 32768];
        let address = std::hint::black_box(data.as_ptr()) as u64;
        let pid = std::process::id();
        assert_eq!(read_stack(pid, address, 16384).unwrap(), data[..16384]);
        assert_eq!(read_stack(pid, address, 32768).unwrap(), data);
        assert!(read(pid, address, 4097, true).is_err());
        assert!(read_stack(pid, address, 32769).is_err());
        assert!(read_stack(pid, u64::MAX, 8).is_err());
    }
    #[test]
    fn own_memory_and_invalid_addresses() {
        let value = 0x123456789abcdef0u64;
        assert_eq!(
            read(std::process::id(), &value as *const _ as u64, 8, false).unwrap(),
            value.to_ne_bytes()
        );
        assert!(read(std::process::id(), 0, 8, false).is_err());
        assert!(read(std::process::id(), u64::MAX, 8, true).is_err());
        assert!(read(std::process::id(), 0, 4097, true).is_err());
    }
}
