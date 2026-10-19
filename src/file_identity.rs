//! File identities in the device-number domain used by /proc/PID/maps.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

const MAX_MOUNTINFO: u64 = 8 * 1024 * 1024;

pub(crate) struct Resolver {
    pid: u32,
    mounts: Option<BTreeMap<u64, u64>>,
}

impl Resolver {
    pub(crate) fn new(pid: u32) -> Self {
        Self { pid, mounts: None }
    }

    pub(crate) fn identify(&mut self, file: &File) -> io::Result<(u64, u64)> {
        let metadata = file.metadata()?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // The live file descriptor identifies the filesystem of the opened image.
        if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let filesystem = unsafe { filesystem.assume_init() };
        if filesystem.f_type as u64 != libc::BTRFS_SUPER_MAGIC as u64 {
            return Ok((metadata.dev(), metadata.ino()));
        }

        // Btrfs stat reports a subvolume device, whereas proc maps reports the
        // superblock device. Resolve the latter through the opened file's mount
        // ID, never by accepting an inode match on an arbitrary device.
        let mut status = std::mem::MaybeUninit::<libc::statx>::zeroed();
        if unsafe {
            libc::syscall(
                libc::SYS_statx,
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_MNT_ID,
                status.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe { status.assume_init() };
        if status.stx_mask & libc::STATX_MNT_ID == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Btrfs mapping identity requires statx mount IDs (Linux 5.8+)",
            ));
        }
        if self.mounts.is_none() {
            self.mounts = Some(read_mounts(self.pid)?);
        }
        let mounts = self.mounts.as_mut().unwrap();
        // Relative image paths can refer to the tracer's own mount namespace.
        if !mounts.contains_key(&status.stx_mnt_id) && self.pid != std::process::id() {
            mounts.extend(read_mounts(std::process::id())?);
        }
        let device = mounts.get(&status.stx_mnt_id).copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Btrfs image mount {} is absent from mountinfo",
                    status.stx_mnt_id
                ),
            )
        })?;
        Ok((device, metadata.ino()))
    }
}

fn read_mounts(pid: u32) -> io::Result<BTreeMap<u64, u64>> {
    let mut text = String::new();
    File::open(format!("/proc/{pid}/mountinfo"))?
        .take(MAX_MOUNTINFO + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_MOUNTINFO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mountinfo exceeds 8 MiB",
        ));
    }
    parse_mounts(&text)
}

fn parse_mounts(text: &str) -> io::Result<BTreeMap<u64, u64>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid mountinfo identity");
    let mut mounts = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let id = fields
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        fields.next().ok_or_else(invalid)?;
        let (major, minor) = fields
            .next()
            .ok_or_else(invalid)?
            .split_once(':')
            .ok_or_else(invalid)?;
        // Unlike /proc/PID/maps, mountinfo device numbers are decimal.
        let device = libc::makedev(
            major.parse().map_err(|_| invalid())?,
            minor.parse().map_err(|_| invalid())?,
        );
        if mounts.insert(id, device).is_some() || mounts.len() > 65536 {
            return Err(invalid());
        }
    }
    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_uses_decimal_devices_and_exact_mount_ids() {
        let mounts = parse_mounts(
            "41 1 0:35 /subvol /packages rw - btrfs /dev/sda rw\n\
             42 1 8:17 / /other\\040mount rw shared:2 - ext4 /dev/sdb rw\n",
        )
        .unwrap();
        assert_eq!(mounts[&41], libc::makedev(0, 0x23));
        assert_eq!(mounts[&42], libc::makedev(8, 17));
        assert!(!mounts.contains_key(&43));
        for invalid in ["41 1 bad", "41 1 0:35\n41 1 0:36", "41 1 0:4294967296"] {
            assert!(parse_mounts(invalid).is_err());
        }
    }

    #[test]
    fn opened_executable_identity_matches_proc_mapping() {
        let pid = std::process::id();
        let executable = File::open(format!("/proc/{pid}/exe")).unwrap();
        let (device, inode) = Resolver::new(pid).identify(&executable).unwrap();
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        assert!(
            maps.lines()
                .filter_map(crate::symbols::Mapping::parse)
                .any(|mapping| mapping.device == device && mapping.inode == inode)
        );
    }
}
