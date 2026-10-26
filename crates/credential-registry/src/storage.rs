//! Unix descriptor-relative registry snapshots. Parent directory is caller-selected.
use crate::{Error, MAX_SNAPSHOT_BYTES};
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode, OFlags},
};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

fn io<T>(result: Result<T, impl std::fmt::Debug>) -> Result<T, Error> {
    result.map_err(|_| Error::Io)
}
fn open_parent(path: &Path) -> Result<(OwnedFd, String, u32), Error> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(Error::Invalid)?;
    if name.is_empty() || name == "." || name == ".." || name.len() > 128 {
        return Err(Error::Invalid);
    }
    // Canonicalization resolves caller-selected system aliases (e.g. macOS /var).
    // Each canonical component is then opened NOFOLLOW, avoiding untrusted traversal.
    let parent = io(path.parent().ok_or(Error::Invalid)?.canonicalize())?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = io(fs::open("/", flags, Mode::empty()))?;
    for part in parent.components() {
        if let Component::Normal(part) = part {
            dir = io(fs::openat(&dir, part, flags, Mode::empty()))?;
        }
    }
    let stat = io(fs::fstat(&dir))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_mode & 0o777 != 0o700
    {
        return Err(Error::Invalid);
    }
    Ok((dir, name.to_string(), stat.st_uid))
}
fn regular(file: &File, owner: u32) -> Result<u64, Error> {
    let meta = io(file.metadata())?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > MAX_SNAPSHOT_BYTES as u64
    {
        return Err(Error::Invalid);
    }
    Ok(meta.len())
}
struct Lock {
    file: File,
}
impl Lock {
    fn acquire(dir: &OwnedFd, owner: u32) -> Result<Self, Error> {
        let fd = io(fs::openat(
            dir,
            ".registry-lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ))?;
        let file = File::from(fd);
        regular(&file, owner)?;
        io(fs::flock(
            &file,
            fs::FlockOperation::NonBlockingLockExclusive,
        ))?;
        Ok(Self { file })
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::flock(&self.file, fs::FlockOperation::Unlock);
    }
}
pub(crate) fn save(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(Error::Bound);
    }
    let (dir, name, owner) = open_parent(path)?;
    let _lock = Lock::acquire(&dir, owner)?;
    let mut count = 0;
    let mut total = 0u64;
    let mut entries = io(fs::Dir::read_from(&dir))?;
    while let Some(entry) = entries.read() {
        let entry = io(entry)?;
        let n = entry.file_name();
        if n.to_bytes() == b"." || n.to_bytes() == b".." {
            continue;
        }
        count += 1;
        if count > 512 {
            return Err(Error::Bound);
        }
        let stat = io(fs::statat(&dir, n, fs::AtFlags::SYMLINK_NOFOLLOW))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_uid != owner
            || stat.st_mode & 0o777 != 0o600
            || stat.st_size < 0
        {
            return Err(Error::Invalid);
        }
        total = total.checked_add(stat.st_size as u64).ok_or(Error::Bound)?;
        if total > 64 * 1024 * 1024 {
            return Err(Error::Bound);
        }
    }
    if total.checked_add(bytes.len() as u64).ok_or(Error::Bound)? > 64 * 1024 * 1024 {
        return Err(Error::Bound);
    }
    let mut random = [0; 16];
    io(openssl::rand::rand_bytes(&mut random))?;
    let temp = format!("registry-pending-{:032x}", u128::from_be_bytes(random));
    let fd = io(fs::openat(
        &dir,
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ))?;
    let mut file = File::from(fd);
    regular(&file, owner)?;
    #[cfg(test)]
    test_faults::check(test_faults::Point::BeforeWrite)?;
    io(file.write_all(bytes))?;
    #[cfg(test)]
    test_faults::check(test_faults::Point::BeforeFileSync)?;
    io(file.sync_all())?;
    // Safe close has no observable close-error result. No power-loss claim follows.
    drop(file);
    #[cfg(test)]
    test_faults::check(test_faults::Point::BeforeRename)?;
    io(fs::renameat(&dir, temp.as_str(), &dir, name.as_str()))?;
    #[cfg(test)]
    test_faults::check(test_faults::Point::BeforeDirectorySync)?;
    io(fs::fsync(&dir))?;
    #[cfg(test)]
    test_faults::check(test_faults::Point::AfterDirectorySync)?;
    Ok(())
}
pub(crate) fn load(path: &Path) -> Result<Vec<u8>, Error> {
    let (dir, name, owner) = open_parent(path)?;
    let _lock = Lock::acquire(&dir, owner)?;
    let fd = io(fs::openat(
        &dir,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ))?;
    let mut file = File::from(fd);
    let len = regular(&file, owner)?;
    let mut bytes = vec![0; usize::try_from(len).map_err(|_| Error::Bound)?];
    io(file.read_exact(&mut bytes))?;
    let mut extra = [0; 1];
    if io(file.read(&mut extra))? != 0 || regular(&file, owner)? != len {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

// Compiled only into the unit-test binary. No environment or production control.
#[cfg(test)]
mod test_faults {
    use super::Error;
    use std::cell::Cell;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Point {
        BeforeWrite,
        BeforeFileSync,
        BeforeRename,
        BeforeDirectorySync,
        AfterDirectorySync,
    }
    thread_local! { static ARMED: Cell<Option<Point>> = const { Cell::new(None) }; }
    pub(super) fn arm(point: Point) { ARMED.with(|armed| armed.set(Some(point))); }
    pub(super) fn check(point: Point) -> Result<(), Error> {
        ARMED.with(|armed| {
            if armed.get() == Some(point) {
                armed.set(None);
                Err(Error::Io)
            } else {
                Ok(())
            }
        })
    }
}
