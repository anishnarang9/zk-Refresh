use crate::{
    ClientError, Digest, OperationControl, WitnessGenerator, WitnessMode, V1_WITNESS_BYTES,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct PinnedFile {
    path: PathBuf,
    digest: Digest,
    max_bytes: u64,
}
impl PinnedFile {
    pub fn new(
        path: impl AsRef<Path>,
        digest: Digest,
        max_bytes: u64,
    ) -> Result<Self, ClientError> {
        let path = path.as_ref();
        if !path.is_absolute() || fs::canonicalize(path).map_err(|_| ClientError::Identity)? != path
        {
            return Err(ClientError::Identity);
        }
        let result = Self {
            path: path.to_owned(),
            digest,
            max_bytes,
        };
        result.verify()?;
        Ok(result)
    }
    fn verify(&self) -> Result<(), ClientError> {
        let meta = fs::symlink_metadata(&self.path).map_err(|_| ClientError::Identity)?;
        if !meta.is_file() || meta.len() > self.max_bytes {
            return Err(ClientError::Identity);
        }
        let mut f = File::open(&self.path).map_err(|_| ClientError::Identity)?;
        let mut hash = Sha256::new();
        let mut remaining = self.max_bytes;
        let mut buf = [0; 8192];
        loop {
            let n = f.read(&mut buf).map_err(|_| ClientError::Io)?;
            if n == 0 {
                break;
            }
            remaining = remaining.checked_sub(n as u64).ok_or(ClientError::Bound)?;
            hash.update(&buf[..n]);
        }
        let digest: Digest = hash.finalize().into();
        if digest != self.digest {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
}

/// Executes a single worker without a shell. Runtime and script identities are
/// checked immediately before spawning. stdout/stderr cannot retain secrets.
pub struct WorkerRunner {
    runtime: PinnedFile,
    script: PinnedFile,
}
impl WorkerRunner {
    pub fn pinned(runtime: PinnedFile, script: PinnedFile) -> Self {
        Self { runtime, script }
    }
    fn run(
        &self,
        args: &[&std::ffi::OsStr],
        control: &OperationControl,
    ) -> Result<i32, ClientError> {
        control.check()?;
        self.runtime.verify()?;
        self.script.verify()?;
        control.check()?;
        let mut child = Command::new(&self.runtime.path)
            .arg(&self.script.path)
            .args(args)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONHASHSEED", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ClientError::Worker)?;
        loop {
            if let Err(error) = control.check() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    control.check()?;
                    return status.code().ok_or(ClientError::Worker);
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ClientError::Worker);
                }
            }
        }
    }
}

struct PrivateDirectory(PathBuf);
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ClientError::Io)?;
    f.write_all(bytes).map_err(|_| ClientError::Io)
}

pub struct NativeWitnessGenerator {
    python: WorkerRunner,
    node: WorkerRunner,
    wasm: PinnedFile,
    calculator: PinnedFile,
    private_root: PathBuf,
}
impl NativeWitnessGenerator {
    pub fn new(
        python: WorkerRunner,
        node: WorkerRunner,
        wasm: PinnedFile,
        calculator: PinnedFile,
        private_root: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        let root = private_root.as_ref();
        use std::os::unix::fs::PermissionsExt;
        if !root.is_absolute()
            || fs::canonicalize(root).map_err(|_| ClientError::Identity)? != root
            || !root.is_dir()
            || fs::metadata(root)
                .map_err(|_| ClientError::Io)?
                .permissions()
                .mode()
                & 0o077
                != 0
        {
            return Err(ClientError::Identity);
        }
        // Fixed v1 source identities, including the original calculator, are
        // required independently of caller-provided source labels.
        if wasm.digest
            != crate::decode_digest(
                "fd5bfce8aa51fe89fb8f2783153666a65fb7a2c2a17753f75910d8a3aa891960",
            )?
        {
            return Err(ClientError::Identity);
        }
        if calculator.digest
            != crate::decode_digest(
                "cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942",
            )?
            || python.script.digest
                != <[u8; 32]>::from(Sha256::digest(include_bytes!(
                    "../workers/suffix_worker.py"
                )))
            || node.script.digest
                != <[u8; 32]>::from(Sha256::digest(include_bytes!("../workers/full_worker.cjs")))
        {
            return Err(ClientError::Identity);
        }
        Ok(Self {
            python,
            node,
            wasm,
            calculator,
            private_root: root.to_owned(),
        })
    }
}
impl WitnessGenerator for NativeWitnessGenerator {
    fn generate(
        &mut self,
        before_input: &[u8],
        before_witness: &[u8],
        target_input: &[u8],
        allow_incremental: bool,
        control: &OperationControl,
    ) -> Result<(Vec<u8>, WitnessMode), ClientError> {
        control.check()?;
        if target_input.is_empty()
            || target_input.len() > 65536
            || before_input.len() > 65536
            || before_witness.len() > V1_WITNESS_BYTES
        {
            return Err(ClientError::Bound);
        }
        self.wasm.verify()?;
        self.calculator.verify()?;
        let name = format!(
            "m2-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        );
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        let path = self.private_root.join(name);
        builder.create(&path).map_err(|_| ClientError::Io)?;
        let directory = PrivateDirectory(path);
        write_private(&directory.0.join("target.json"), target_input)?;
        let mut mode = WitnessMode::Full;
        if allow_incremental {
            write_private(&directory.0.join("before.json"), before_input)?;
            write_private(&directory.0.join("before.wtns"), before_witness)?;
            let status = self.python.run(
                &[std::ffi::OsStr::new("incremental"), directory.0.as_os_str()],
                control,
            )?;
            match status {
                0 => mode = WitnessMode::IncrementalV1,
                2 => (),
                _ => return Err(ClientError::Worker),
            }
        }
        if mode == WitnessMode::Full {
            if self.python.run(
                &[std::ffi::OsStr::new("normalize"), directory.0.as_os_str()],
                control,
            )? != 0
            {
                return Err(ClientError::Encoding);
            }
            self.wasm.verify()?;
            self.calculator.verify()?;
            if self.node.run(
                &[
                    directory.0.as_os_str(),
                    self.wasm.path.as_os_str(),
                    self.calculator.path.as_os_str(),
                ],
                control,
            )? != 0
            {
                return Err(ClientError::Worker);
            }
        }
        control.check()?;
        let output = directory.0.join("output.wtns");
        let meta = fs::symlink_metadata(&output).map_err(|_| ClientError::Worker)?;
        if !meta.is_file() || meta.len() != V1_WITNESS_BYTES as u64 {
            return Err(ClientError::Bound);
        }
        let mut result = Vec::with_capacity(V1_WITNESS_BYTES);
        File::open(output)
            .map_err(|_| ClientError::Io)?
            .take(V1_WITNESS_BYTES as u64 + 1)
            .read_to_end(&mut result)
            .map_err(|_| ClientError::Io)?;
        if result.len() != V1_WITNESS_BYTES {
            return Err(ClientError::Bound);
        }
        control.check()?;
        Ok((result, mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn shell(script: &[u8]) -> (WorkerRunner, PrivateDirectory) {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = base.join(format!(
            "m2-native-test-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).unwrap();
        let directory = PrivateDirectory(path);
        let script_path = directory.0.join("worker.sh");
        write_private(&script_path, script).unwrap();
        let runtime = fs::canonicalize("/bin/sh").unwrap();
        let hash: Digest = Sha256::digest(fs::read(&runtime).unwrap()).into();
        let pinned_runtime = PinnedFile::new(runtime, hash, 16 * 1024 * 1024).unwrap();
        let pinned_script =
            PinnedFile::new(script_path, Sha256::digest(script).into(), 65536).unwrap();
        (
            WorkerRunner::pinned(pinned_runtime, pinned_script),
            directory,
        )
    }

    #[test]
    fn child_failure_is_observed_without_forwarding_worker_output() {
        let (runner, _directory) = shell(b"echo private-output; echo private-error >&2; exit 7\n");
        let control = OperationControl::new(Instant::now() + Duration::from_secs(2));
        assert_eq!(runner.run(&[], &control), Ok(7));
    }

    #[test]
    fn cancelled_child_is_killed_and_joined() {
        let (runner, _directory) = shell(b"while :; do :; done\n");
        let control = OperationControl::new(Instant::now() + Duration::from_secs(2));
        let cancellation = control.clone();
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            cancellation.cancel();
        });
        assert_eq!(runner.run(&[], &control), Err(ClientError::Cancelled));
        thread.join().unwrap();
    }

    #[test]
    fn expired_deadline_reaps_the_child() {
        let (runner, _directory) = shell(b"while :; do :; done\n");
        let control = OperationControl::new(Instant::now() + Duration::from_millis(80));
        assert_eq!(runner.run(&[], &control), Err(ClientError::Deadline));
    }

    #[test]
    fn changed_pinned_script_is_rejected_before_spawn() {
        let (runner, directory) = shell(b"exit 0\n");
        fs::write(directory.0.join("worker.sh"), b"exit 7\n").unwrap();
        let control = OperationControl::new(Instant::now() + Duration::from_secs(2));
        assert_eq!(runner.run(&[], &control), Err(ClientError::Identity));
    }
}

/// Exact v2 development Full calculator; no Python/v1 mapping or incremental
/// worker is admitted. Each invocation owns a fresh 0700 directory and deletes
/// all inputs, calculator snapshots and output on every return path.
pub struct NativeV2FullWitnessGenerator {
    node: WorkerRunner,
    wasm: PinnedFile,
    calculator: PinnedFile,
    private_root: PathBuf,
}
impl NativeV2FullWitnessGenerator {
    pub fn new(
        node: WorkerRunner,
        wasm: PinnedFile,
        calculator: PinnedFile,
        private_root: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        use std::os::unix::fs::PermissionsExt;
        let root = private_root.as_ref();
        if !root.is_absolute()
            || fs::canonicalize(root).map_err(|_| ClientError::Identity)? != root
            || !fs::symlink_metadata(root)
                .map_err(|_| ClientError::Identity)?
                .is_dir()
            || fs::metadata(root)
                .map_err(|_| ClientError::Io)?
                .permissions()
                .mode()
                & 0o077
                != 0
        {
            return Err(ClientError::Identity);
        }
        if wasm.digest != crate::decode_digest(crate::V2_WASM_HEX)?
            || calculator.digest != crate::decode_digest(crate::V2_CALCULATOR_HEX)?
            || node.script.digest
                != <[u8; 32]>::from(Sha256::digest(include_bytes!(
                    "../workers/v2_full_worker.cjs"
                )))
        {
            return Err(ClientError::Identity);
        }
        // Fixed bounds apply even if a caller gives PinnedFile a looser bound.
        if wasm.max_bytes > 16 * 1024 * 1024 || calculator.max_bytes > 1024 * 1024 {
            return Err(ClientError::Bound);
        }
        Ok(Self {
            node,
            wasm,
            calculator,
            private_root: root.to_owned(),
        })
    }
}
impl WitnessGenerator for NativeV2FullWitnessGenerator {
    fn generate(
        &mut self,
        before_input: &[u8],
        before_witness: &[u8],
        target_input: &[u8],
        allow_incremental: bool,
        control: &OperationControl,
    ) -> Result<(Vec<u8>, WitnessMode), ClientError> {
        control.check()?;
        if allow_incremental {
            return Err(ClientError::Unsupported);
        }
        if target_input.is_empty()
            || target_input.len() > 65_536
            || before_input.len() > 65_536
            || before_witness.len() > crate::V2_WITNESS_BYTES
        {
            return Err(ClientError::Bound);
        }
        // Recheck root before creating a fresh private invocation. The caller
        // owns/trusts this root and the runtime/script parent directories.
        use std::os::unix::fs::PermissionsExt;
        if fs::canonicalize(&self.private_root).map_err(|_| ClientError::Identity)?
            != self.private_root
            || !fs::symlink_metadata(&self.private_root)
                .map_err(|_| ClientError::Identity)?
                .is_dir()
            || fs::metadata(&self.private_root)
                .map_err(|_| ClientError::Io)?
                .permissions()
                .mode()
                & 0o077
                != 0
        {
            return Err(ClientError::Identity);
        }
        let name = format!(
            "v2-full-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        );
        let path = self.private_root.join(name);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).map_err(|_| ClientError::Io)?;
        let directory = PrivateDirectory(path);
        write_private(&directory.0.join("target.json"), target_input)?;
        // Snapshot the exact bytes just verified, closing the mutable WASM /
        // calculator filename gap between native admission and worker loading.
        for (source, name) in [
            (&self.wasm, "circuit.wasm"),
            (&self.calculator, "calculator.source"),
        ] {
            control.check()?;
            let mut bytes = Vec::new();
            File::open(&source.path)
                .map_err(|_| ClientError::Io)?
                .take(source.max_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ClientError::Io)?;
            if bytes.len() as u64 > source.max_bytes
                || <[u8; 32]>::from(Sha256::digest(&bytes)) != source.digest
            {
                return Err(ClientError::Identity);
            }
            write_private(&directory.0.join(name), &bytes)?;
        }
        let status = self.node.run(
            &[
                directory.0.as_os_str(),
                directory.0.join("circuit.wasm").as_os_str(),
                directory.0.join("calculator.source").as_os_str(),
            ],
            control,
        )?;
        if status == 2 {
            return Err(ClientError::Encoding);
        }
        if status != 0 {
            return Err(ClientError::Worker);
        }
        control.check()?;
        let output = directory.0.join("output.wtns");
        let meta = fs::symlink_metadata(&output).map_err(|_| ClientError::Worker)?;
        use std::os::unix::fs::MetadataExt;
        if !meta.is_file()
            || meta.len() != crate::V2_WITNESS_BYTES as u64
            || meta.permissions().mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(ClientError::Bound);
        }
        let mut bytes = Vec::with_capacity(crate::V2_WITNESS_BYTES);
        File::open(output)
            .map_err(|_| ClientError::Io)?
            .take(crate::V2_WITNESS_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ClientError::Io)?;
        if bytes.len() != crate::V2_WITNESS_BYTES {
            return Err(ClientError::Bound);
        }
        control.check()?;
        Ok((bytes, WitnessMode::Full))
    }
}
