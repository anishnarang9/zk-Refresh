use super::*;
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags},
};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};
#[derive(Clone, Copy, Debug)]
pub struct StoreLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
}
impl StoreLimits {
    pub fn small() -> Self {
        Self {
            max_bytes: 128 * 1024 * 1024,
            max_entries: 512,
        }
    }
}
/// Held caller-trusted component descriptor; all untrusted names are single
/// basenames and each traversed component is separately NOFOLLOW checked.
pub struct ProtectedStore {
    dir: OwnedFd,
    lock: OwnedFd,
    owner: u32,
    limits: StoreLimits,
}
fn component(s: &str) -> Result<()> {
    if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\0') {
        return Err(PersistenceError::Trust("directory component"));
    }
    Ok(())
}
fn directory(fd: &OwnedFd, owner: u32, private: bool) -> Result<()> {
    let s = fs::fstat(fd)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || s.st_uid != owner
        || if private {
            s.st_mode & 0o777 != 0o700
        } else {
            s.st_mode & 0o022 != 0
        }
    {
        return Err(PersistenceError::Trust("directory owner/mode"));
    }
    Ok(())
}
fn name(id: [u8; 32], temp: bool) -> String {
    let mut n = String::with_capacity(80);
    n.push_str(if temp { "tmp-" } else { "commit-" });
    for x in id {
        use std::fmt::Write as _;
        write!(&mut n, "{x:02x}").unwrap();
    }
    n.push_str(if temp { ".tmp" } else { ".dync" });
    n
}
impl ProtectedStore {
    /// The root descriptor must already have been obtained through a trusted
    /// caller path. This API never resolves a multi-component untrusted path.
    pub fn open_private_leaf(
        root: OwnedFd,
        components: &[&str],
        owner: u32,
        limits: StoreLimits,
    ) -> Result<Self> {
        if components.is_empty() || limits.max_entries == 0 {
            return Err(PersistenceError::Bound("store configuration"));
        }
        directory(&root, owner, false)?;
        let mut dir = root;
        for (j, c) in components.iter().enumerate() {
            component(c)?;
            if j + 1 == components.len() {
                match fs::mkdirat(&dir, *c, Mode::from_raw_mode(0o700)) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            let next = fs::openat(
                &dir,
                *c,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            directory(&next, owner, j + 1 == components.len())?;
            dir = next;
        }
        let lock = fs::openat(
            &dir,
            ".dynark-lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let st = fs::fstat(&lock)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_uid != owner
            || st.st_mode & 0o777 != 0o600
            || st.st_nlink != 1
        {
            return Err(PersistenceError::Trust("store lock type/mode"));
        }
        Ok(Self {
            dir,
            lock,
            owner,
            limits,
        })
    }
    fn budget(&self, new: u64) -> Result<()> {
        let mut count = 0usize;
        let mut total = 0u64;
        let mut d = fs::Dir::read_from(&self.dir)?;
        while let Some(entry) = d.read() {
            let entry = entry?;
            let n = entry.file_name();
            if n.to_bytes() == b"." || n.to_bytes() == b".." {
                continue;
            }
            count = add(count, 1)?;
            if count >= self.limits.max_entries {
                return Err(PersistenceError::Bound("store entries"));
            }
            let s = fs::statat(&self.dir, n, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
                || s.st_uid != self.owner
                || s.st_mode & 0o777 != 0o600
                || s.st_nlink != 1
                || s.st_size < 0
            {
                return Err(PersistenceError::Trust("store entry type/mode"));
            }
            total = total
                .checked_add(s.st_size as u64)
                .ok_or(PersistenceError::Bound("store bytes"))?;
            if total > self.limits.max_bytes {
                return Err(PersistenceError::Bound("store bytes"));
            }
        }
        if total
            .checked_add(new)
            .ok_or(PersistenceError::Bound("store bytes"))?
            > self.limits.max_bytes
        {
            return Err(PersistenceError::Bound("store bytes"));
        }
        Ok(())
    }
    fn open_file(&self, n: &str) -> Result<File> {
        let fd = fs::openat(
            &self.dir,
            n,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                PersistenceError::RebuildRequired("missing committed file")
            } else {
                e.into()
            }
        })?;
        let f = File::from(fd);
        self.metadata(&f)?;
        Ok(f)
    }
    fn metadata(&self, f: &File) -> Result<std::fs::Metadata> {
        let m = f.metadata()?;
        if !m.is_file() || m.uid() != self.owner || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
            return Err(PersistenceError::Trust("file owner/type/mode"));
        }
        Ok(m)
    }
    pub(crate) fn publish(
        &self,
        id: [u8; 32],
        h: &[u8; 1024],
        p: &[u8],
        tag: &[u8; 16],
        digest: [u8; 32],
        cap: usize,
    ) -> Result<()> {
        let _guard = StoreLock::acquire(&self.lock)?;
        let len = add(p.len(), 1040)?;
        if len > cap {
            return Err(PersistenceError::Bound("publication bytes"));
        }
        self.budget(len as u64)?;
        let tmp = name(id, true);
        let final_name = name(id, false);
        let fd = fs::openat(
            &self.dir,
            tmp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        fault(FaultPoint::Create)?;
        let mut file = File::from(fd);
        let before = self.metadata(&file)?;
        file.write_all(h)?;
        fault(FaultPoint::Header)?;
        file.write_all(p)?;
        fault(FaultPoint::Payload)?;
        file.write_all(tag)?;
        fault(FaultPoint::Tag)?;
        fs::fsync(&file)?;
        fault(FaultPoint::FileSync)?;
        // Safe Drop closes before publication. Kernel close errors are not
        // observable; no unsafe raw descriptor close or fallback is used.
        drop(file);
        fault(FaultPoint::Close)?;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        ))]
        fs::renameat_with(
            &self.dir,
            tmp.as_str(),
            &self.dir,
            final_name.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        )))]
        return Err(PersistenceError::Unsupported("no-replace publication"));
        fault(FaultPoint::Publish)?;
        let mut published = self.open_file(&final_name)?;
        let meta = self.metadata(&published)?;
        fault(FaultPoint::Reopen)?;
        if meta.dev() != before.dev() || meta.ino() != before.ino() || meta.len() != len as u64 {
            return Err(PersistenceError::Trust("published inode/size"));
        }
        let mut hash = Sha256::new();
        let mut scratch = [0; 8192];
        let mut remain = len;
        while remain != 0 {
            let n = remain.min(scratch.len());
            published.read_exact(&mut scratch[..n])?;
            hash.update(&scratch[..n]);
            remain -= n;
        }
        let mut extra = [0; 1];
        if published.read(&mut extra)? != 0
            || published.metadata()?.len() != len as u64
            || <[u8; 32]>::from(hash.finalize()) != digest
        {
            return Err(PersistenceError::Trust("published digest/EOF"));
        }
        drop(published);
        fs::fsync(&self.dir)?;
        fault(FaultPoint::DirectorySync)?;
        Ok(())
    }
    pub(crate) fn receive(
        &self,
        id: [u8; 32],
        c: &ExpectedContext,
        s: &ProviderSnapshot,
        p: &LoadPolicy,
        m: &mut AdmissionMetrics,
    ) -> Result<([u8; 1024], Zeroizing<Vec<u8>>, [u8; 16])> {
        let mut f = self.open_file(&name(id, false))?;
        let before = self.metadata(&f)?;
        let mut h = [0; 1024];
        f.read_exact(&mut h)?;
        let len = wire::preflight(&h, before.len(), c, s, p)?;
        let mut payload = Zeroizing::new(reserve::<u8>(len)?);
        m.buffer_capacity = payload.capacity();
        let peak = add(add(payload.capacity(), p.old_live_bytes)?, 12 * 1024)?;
        p.peak(peak, c.trusted_tables.0.public_bytes)?;
        payload.resize(len, 0);
        let mut tag = [0; 16];
        f.read_exact(&mut payload)?;
        f.read_exact(&mut tag)?;
        let mut extra = [0; 1];
        if f.read(&mut extra)? != 0 || f.metadata()?.len() != before.len() {
            return Err(PersistenceError::Malformed("file growth/shrink"));
        }
        m.received_bytes = add(len, 1040)?;
        Ok((h, payload, tag))
    }
}

struct StoreLock<'a>(&'a OwnedFd);
impl<'a> StoreLock<'a> {
    fn acquire(fd: &'a OwnedFd) -> Result<Self> {
        fs::flock(fd, fs::FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                PersistenceError::Fenced
            } else {
                e.into()
            }
        })?;
        Ok(Self(fd))
    }
}
impl Drop for StoreLock<'_> {
    fn drop(&mut self) {
        let _ = fs::flock(self.0, fs::FlockOperation::Unlock);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    Create,
    Header,
    Payload,
    Tag,
    FileSync,
    Close,
    Publish,
    Reopen,
    DirectorySync,
    BeforeCas,
}
#[cfg(test)]
thread_local! {static INJECT:std::cell::Cell<Option<FaultPoint>>=const{std::cell::Cell::new(None)};}
#[cfg(test)]
pub(crate) fn inject(point: Option<FaultPoint>) {
    INJECT.with(|x| x.set(point));
}
pub(crate) fn fault(point: FaultPoint) -> Result<()> {
    #[cfg(test)]
    if INJECT.with(|x| x.get() == Some(point)) {
        INJECT.with(|x| x.set(None));
        return Err(PersistenceError::Io(std::io::Error::other(
            "synthetic storage boundary interruption",
        )));
    }
    let _ = point;
    Ok(())
}
