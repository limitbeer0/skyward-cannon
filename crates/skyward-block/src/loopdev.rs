//! Making a block device out of part of a file, which is how the bundles a
//! phone keeps its shared libraries in are opened.

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(target_os = "android")]
mod android {
    use anyhow::{Context, Result};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    const CONTROL: &str = "/dev/loop-control";

    const GET_FREE: u32 = 0x4C82;
    const SET_FD: u32 = 0x4C00;
    const SET_STATUS64: u32 = 0x4C04;

    /// The device only ever reads. It stays pointed at the file until the
    /// recovery ends, which is as long as anything mounted from it lasts.
    const READ_ONLY: u32 = 1;

    /// What `LOOP_SET_STATUS64` takes, as the kernel's `loop_info64` is laid
    /// out: every field a plain number or a run of bytes, filled by zeroing
    /// it and writing what matters.
    #[repr(C)]
    struct Info {
        device: u64,
        inode: u64,
        rdevice: u64,
        offset: u64,
        size_limit: u64,
        number: u32,
        encrypt_type: u32,
        encrypt_key_size: u32,
        flags: u32,
        file_name: [u8; 64],
        crypt_name: [u8; 64],
        encrypt_key: [u8; 32],
        init: [u64; 2],
    }

    /// Open `file` from `offset` for `length` bytes as a block device, and
    /// give its path. The device goes away once whatever is mounted from it
    /// is unmounted.
    ///
    /// The newer `LOOP_CONFIGURE` combines the two calls below into one and
    /// is atomic, but kernels before 5.8 do not have it: the older pair
    /// `LOOP_SET_FD` then `LOOP_SET_STATUS64` is what those answer, and is
    /// what every phone this recovery runs on before Android 11 keeps.
    pub fn attach(file: &Path, offset: u64, length: u64) -> Result<PathBuf> {
        let backing = File::open(file).with_context(|| format!("open {}", file.display()))?;
        let control = File::open(CONTROL).with_context(|| format!("open {CONTROL}"))?;
        let number = unsafe { libc::ioctl(control.as_raw_fd(), GET_FREE as libc::Ioctl) };
        if number < 0 {
            return Err(std::io::Error::last_os_error()).context("ask for a free loop device");
        }
        let path = free_device(number as u32)?;
        let device = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        // Point the device at the file: the older call takes the file's
        // descriptor as its argument.
        if unsafe { libc::ioctl(device.as_raw_fd(), SET_FD as libc::Ioctl, backing.as_raw_fd()) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("point {} at {}", path.display(), file.display()));
        }
        // Tell it where in the file the part it serves begins, and how long
        // that part is, and that it is read-only.
        let mut info: Info = unsafe { std::mem::zeroed() };
        info.offset = offset;
        info.size_limit = length;
        info.flags = READ_ONLY;
        if unsafe { libc::ioctl(device.as_raw_fd(), SET_STATUS64 as libc::Ioctl, &info) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("set {} to offset {offset} length {length}", path.display()));
        }
        Ok(path)
    }

    /// Where the kernel put the loop device it just handed out: Android
    /// keeps its block devices in their own directory.
    fn free_device(number: u32) -> Result<PathBuf> {
        for dir in ["/dev/block", "/dev"] {
            let path = Path::new(dir).join(format!("loop{number}"));
            if path.exists() {
                return Ok(path);
            }
        }
        anyhow::bail!("the kernel handed out loop device {number}, which is in neither /dev/block nor /dev")
    }
}
