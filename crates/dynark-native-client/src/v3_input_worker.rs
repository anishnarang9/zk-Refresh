//! Non-authorizing native transport and independent v3 candidate comparison.
//!
//! Request bytes and expected summary are untrusted data from the future action
//! builder. Neither constructing a request nor accepting a candidate authenticates
//! a credential, issuer, source, clock, allocation, enrollment or finalized action.
//! The future builder must derive the request from admitted DER and exact reviewed
//! action/state capabilities; no candidate JSON supplies expected field values.
//! Rust compares every input scalar, exact summary and request bytes itself. RSA
//! and Poseidon correctness additionally rely on the reviewed pinned Python worker
//! and subsequent complete relation validation; this module supplies no native RSA
//! or Poseidon implementation. Full admission still requires independently derived
//! JSON equality, all 751 complete-WTNS coordinate equalities, canonical complete
//! witness import, R1CS validation under the admitted shared package, concrete chain
//! authentication and a fresh state recheck. open_full remains closed elsewhere.
use crate::{
    decode_digest, ClientError, FieldBytes, OperationControl, PinnedFile, V3CredentialSummary,
};
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

pub const V3_INPUT_REQUEST_BYTES: usize = 1918;
pub const V3_INPUT_RESPONSE_BYTES: usize = 24495;
pub const V3_INPUT_SCALARS: usize = 751;

// Independent implementation policy, never learned from a caller's asserted hash.
// The Python installation/stdlib remains trusted; this is not a hermetic runtime.
const PYTHON_PATH: &str = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14";
const PYTHON_SHA256: &str = "4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d";
const SCRIPT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/workers/v3_input_worker.py");
const SCRIPT_SHA256: &str = "b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e";

// Reviewed OS ABI flags; no unsafe code or new libc dependency. Other Unix
// targets reject transport instead of silently dropping nofollow/nonblock.
#[cfg(target_os = "macos")]
const PRIVATE_FLAGS: i32 = 0x0100 | 0x0004;
#[cfg(target_os = "linux")]
const PRIVATE_FLAGS: i32 = 0x20000 | 0x0800;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const PRIVATE_FLAGS: i32 = 0;
static RUN_SERIAL: AtomicU64 = AtomicU64::new(0);

// Fixed in-memory launch code closes the hash-then-spawn pathname gap. The
// trusted Python binary verifies one same-handle bounded script snapshot, then
// executes exactly those bytes with the original script filename and CLI argv.
// No helper file, caller-selected script, repository import or pycache is used.
const BOOTSTRAP: &str = r#"import hashlib, os, stat, sys
try:
    path, expected, directory = sys.argv[1:]
    before = os.lstat(path)
    def identity(meta):
        return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_size,
                meta.st_mtime_ns, meta.st_ctime_ns)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 131072:
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        if identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError()
        script = source.read(131073)
        if (len(script) != before.st_size or len(script) > 131072
                or identity(os.fstat(source.fileno())) != identity(before)
                or hashlib.sha256(script).hexdigest() != expected):
            raise ValueError()
    sys.argv = [path, 'build', directory]
    exec(compile(script, path, 'exec'), {'__name__': '__main__', '__file__': path})
except Exception:
    raise SystemExit(2) from None
"#;

/// Fixed V3Q1 wire data plus the independent expected imported-summary values.
/// No public fields, Debug, serialization or claimed authentication capability.
/// Public summary records themselves are caller-constructible and grant no trust.
pub struct V3InputWorkerRequest {
    wire: [u8; V3_INPUT_REQUEST_BYTES],
    expected_summary: V3CredentialSummary,
}
impl V3InputWorkerRequest {
    /// Require exact type/length/header, canonical action and state fields, bounded
    /// slot, and structurally extracted DER/TBS/signature matching the summary.
    /// Structural request validation alone performs no crypto/profile admission.
    pub fn from_wire(wire: &[u8], summary: &V3CredentialSummary) -> Result<Self, ClientError> {
        let request = Self {
            wire: wire.try_into().map_err(|_| ClientError::Encoding)?,
            expected_summary: summary.clone(),
        };
        expected_inputs(&request)?;
        Ok(request)
    }
}

/// Candidate only. Private construction prevents caller output from bypassing the
/// request/response comparison. This is not a validated complete assignment.
pub struct V3InputCandidate {
    summary: V3CredentialSummary,
    scalars: [FieldBytes; V3_INPUT_SCALARS],
}

/// One fixed Python/script identity, with one fresh private invocation per call.
/// No API accepts executable/script paths, digest assertions or output filenames.
pub struct V3InputWorker {
    private_root: PathBuf,
}
impl V3InputWorker {
    /// Check absolute canonical 0700 root, current ownership, and independent
    /// fixed source/runtime identities. No caller substitute identity is admitted.
    pub fn new(private_root: impl AsRef<Path>) -> Result<Self, ClientError> {
        supported_transport()?;
        // The exclusively created child is owned by this process. Comparing it
        // with the root enforces ownership without an unsafe getuid binding.
        drop(private_run(private_root.as_ref())?);
        fixed_sources()?;
        Ok(Self {
            private_root: private_root.as_ref().to_owned(),
        })
    }

    /// Check cancellation/deadline before I/O; create fresh 0700 child/0600
    /// request.bin, invoke fixed Python/script with ["build", absolute child]
    /// through a bounded hash-and-execute child, and read only exact owner-only
    /// single-link output.bin using nofollow, same-handle before/after metadata
    /// and a RESPONSE_BYTES+1 cap. Never reopen a mutable source for parsing.
    /// Every return path must clean private invocation files and reap the worker.
    /// Compare all reply bytes/fields before returning any private candidate.
    pub fn build(
        &self,
        request: &V3InputWorkerRequest,
        control: &OperationControl,
    ) -> Result<V3InputCandidate, ClientError> {
        control.check()?;
        supported_transport()?;
        expected_inputs(request)?;
        control.check()?;
        let (runtime, _) = fixed_sources()?;
        control.check()?;
        let run = private_run(&self.private_root)?;
        let owner = fs::symlink_metadata(&run.0)
            .map_err(|_| ClientError::Io)?
            .uid();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(PRIVATE_FLAGS)
            .open(run.0.join("request.bin"))
            .map_err(|_| ClientError::Io)?;
        control.check()?;
        file.write_all(&request.wire).map_err(|_| ClientError::Io)?;
        let written = file.metadata().map_err(|_| ClientError::Io)?;
        if !written.is_file()
            || written.uid() != owner
            || written.nlink() != 1
            || written.permissions().mode() & 0o7777 != 0o600
            || written.len() != V3_INPUT_REQUEST_BYTES as u64
        {
            return Err(ClientError::Identity);
        }
        drop(file);
        control.check()?;
        let process = Command::new(&runtime.path)
            .args(["-I", "-B", "-c", BOOTSTRAP, SCRIPT_PATH, SCRIPT_SHA256])
            .arg(&run.0)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ClientError::Worker)?;
        let mut child = OwnedChild(process);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            control.check()?;
            if Instant::now() >= deadline {
                return Err(ClientError::Deadline);
            }
            match child.0.try_wait().map_err(|_| ClientError::Worker)? {
                Some(status) => {
                    if !status.success() {
                        return Err(if status.code() == Some(2) {
                            ClientError::Encoding
                        } else {
                            ClientError::Worker
                        });
                    }
                    break;
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        }
        control.check()?;
        let bytes = read_response(&run.0.join("output.bin"), owner, control)?;
        let candidate = compare_response(&bytes, request)?;
        control.check()?;
        Ok(candidate)
    }
}

fn supported_transport() -> Result<(), ClientError> {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        Ok(())
    } else {
        Err(ClientError::Unsupported)
    }
}

fn fixed_sources() -> Result<(PinnedFile, PinnedFile), ClientError> {
    Ok((
        PinnedFile::new(PYTHON_PATH, decode_digest(PYTHON_SHA256)?, 1024 * 1024)?,
        PinnedFile::new(SCRIPT_PATH, decode_digest(SCRIPT_SHA256)?, 128 * 1024)?,
    ))
}

struct PrivateRun(PathBuf);
impl Drop for PrivateRun {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_run(root: &Path) -> Result<PrivateRun, ClientError> {
    let before = fs::symlink_metadata(root).map_err(|_| ClientError::Io)?;
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| ClientError::Identity)? != root
        || !before.is_dir()
        || before.permissions().mode() & 0o7777 != 0o700
    {
        return Err(ClientError::Identity);
    }
    let path = root.join(format!(
        "v3-input-{}-{}",
        std::process::id(),
        RUN_SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| ClientError::Io)?;
    let run = PrivateRun(path);
    let child = fs::symlink_metadata(&run.0).map_err(|_| ClientError::Io)?;
    let after = fs::symlink_metadata(root).map_err(|_| ClientError::Io)?;
    if !child.is_dir()
        || child.permissions().mode() & 0o7777 != 0o700
        || child.uid() != before.uid()
        || (after.dev(), after.ino(), after.uid(), after.mode())
            != (before.dev(), before.ino(), before.uid(), before.mode())
        || fs::canonicalize(&run.0).map_err(|_| ClientError::Identity)? != run.0
    {
        return Err(ClientError::Identity);
    }
    Ok(run)
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn metadata_identity(meta: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.uid(),
        meta.mode(),
        meta.nlink(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

fn read_response(
    path: &Path,
    owner: u32,
    control: &OperationControl,
) -> Result<Vec<u8>, ClientError> {
    control.check()?;
    let before = fs::symlink_metadata(path).map_err(|_| ClientError::Io)?;
    if !before.is_file()
        || before.uid() != owner
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != 0o600
        || before.len() != V3_INPUT_RESPONSE_BYTES as u64
    {
        return Err(ClientError::Identity);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(PRIVATE_FLAGS)
        .open(path)
        .map_err(|_| ClientError::Io)?;
    if metadata_identity(&file.metadata().map_err(|_| ClientError::Io)?)
        != metadata_identity(&before)
    {
        return Err(ClientError::Identity);
    }
    let mut bytes = Vec::with_capacity(V3_INPUT_RESPONSE_BYTES + 1);
    {
        let mut limited = (&mut file).take(V3_INPUT_RESPONSE_BYTES as u64 + 1);
        let mut buffer = [0; 4096];
        loop {
            control.check()?;
            let count = limited.read(&mut buffer).map_err(|_| ClientError::Io)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    if bytes.len() != V3_INPUT_RESPONSE_BYTES
        || metadata_identity(&file.metadata().map_err(|_| ClientError::Io)?)
            != metadata_identity(&before)
    {
        return Err(ClientError::Identity);
    }
    control.check()?;
    Ok(bytes)
}

/// Private structural equality only: exact V3I1/459-byte V3A1 summary, canonical
/// 751 Fr encodings and exact scalars independently reconstructed from request
/// DER/TBS/signatures, expected summary, action, root, issuer/policy, slot/path.
/// In particular, matching six public fields alone cannot accept a candidate.
fn compare_response(
    bytes: &[u8],
    request: &V3InputWorkerRequest,
) -> Result<V3InputCandidate, ClientError> {
    if bytes.len() != V3_INPUT_RESPONSE_BYTES || &bytes[..4] != b"V3I1" {
        return Err(ClientError::Encoding);
    }
    let expected = expected_inputs(request)?;
    if bytes[4..463] != summary_bytes(&request.expected_summary) {
        return Err(ClientError::Identity);
    }
    for (chunk, expected) in bytes[463..].chunks_exact(32).zip(expected.iter()) {
        let actual: FieldBytes = chunk.try_into().map_err(|_| ClientError::Encoding)?;
        canonical(actual)?;
        if actual != *expected {
            return Err(ClientError::Identity);
        }
    }
    Ok(V3InputCandidate {
        summary: request.expected_summary.clone(),
        scalars: expected,
    })
}

fn canonical(word: FieldBytes) -> Result<FieldBytes, ClientError> {
    Fr::deserialize_compressed(&word[..]).map_err(|_| ClientError::Encoding)?;
    Ok(word)
}

fn small_field(value: u64) -> FieldBytes {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn summary_bytes(summary: &V3CredentialSummary) -> Vec<u8> {
    let mut bytes = b"V3A1".to_vec();
    bytes.push(summary.layout);
    bytes.extend(summary.tbs_digest);
    bytes.extend(summary.holder_modulus_be);
    bytes.extend(summary.issuer_hash);
    bytes.extend(summary.policy_hash);
    bytes.extend(summary.not_before.to_be_bytes());
    bytes.extend(summary.not_after.to_be_bytes());
    bytes.extend(summary.signed_aki);
    bytes.extend(summary.signed_organization);
    bytes.extend(summary.signed_group);
    for offset in summary.structural_offsets {
        bytes.extend(offset.to_be_bytes());
    }
    bytes
}

/// Bounded canonical DER envelopes only. Profile/eligibility semantics remain
/// with the pinned worker and admitted credential; synthetic parser fixtures
/// deliberately do not satisfy those semantics.
fn der_item<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    tag: u8,
) -> Result<(&'a [u8], &'a [u8]), ClientError> {
    let start = *position;
    if bytes.get(start) != Some(&tag) {
        return Err(ClientError::Encoding);
    }
    let first = *bytes.get(start + 1).ok_or(ClientError::Encoding)?;
    let (header, length) = match first {
        0..=127 => (2, usize::from(first)),
        0x81 => {
            let length = usize::from(*bytes.get(start + 2).ok_or(ClientError::Encoding)?);
            if length < 128 {
                return Err(ClientError::Encoding);
            }
            (3, length)
        }
        0x82 => {
            let high = usize::from(*bytes.get(start + 2).ok_or(ClientError::Encoding)?);
            let low = usize::from(*bytes.get(start + 3).ok_or(ClientError::Encoding)?);
            if high == 0 {
                return Err(ClientError::Encoding);
            }
            (4, high * 256 + low)
        }
        _ => return Err(ClientError::Encoding),
    };
    let content = start.checked_add(header).ok_or(ClientError::Bound)?;
    let end = content.checked_add(length).ok_or(ClientError::Bound)?;
    let full = bytes.get(start..end).ok_or(ClientError::Encoding)?;
    let value = bytes.get(content..end).ok_or(ClientError::Encoding)?;
    *position = end;
    Ok((full, value))
}

fn rsa_limbs(bytes: &[u8; 256]) -> [FieldBytes; 17] {
    std::array::from_fn(|limb| {
        let mut scalar = [0; 32];
        for bit in 0..121 {
            let source = 121 * limb + bit;
            if source < 2048 {
                let digit = (bytes[255 - source / 8] >> (source % 8)) & 1;
                scalar[bit / 8] |= digit << (bit % 8);
            }
        }
        scalar
    })
}

fn expected_inputs(
    request: &V3InputWorkerRequest,
) -> Result<[FieldBytes; V3_INPUT_SCALARS], ClientError> {
    let wire = &request.wire;
    let summary = &request.expected_summary;
    if &wire[..4] != b"V3Q1" || summary.layout >= 8 || summary.not_before > summary.not_after {
        return Err(ClientError::Encoding);
    }
    let certificate = &wire[4..956];
    let mut outer_position = 0;
    let (_, body) = der_item(certificate, &mut outer_position, 0x30)?;
    if outer_position != certificate.len() {
        return Err(ClientError::Encoding);
    }
    let mut position = 0;
    let (tbs, _) = der_item(body, &mut position, 0x30)?;
    let (algorithm, _) = der_item(body, &mut position, 0x30)?;
    let (_, signature_bits) = der_item(body, &mut position, 0x03)?;
    if position != body.len()
        || tbs.len() != 672
        || algorithm
            != [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
                0x00,
            ]
        || signature_bits.len() != 257
        || signature_bits[0] != 0
        || <[u8; 32]>::from(Sha256::digest(tbs)) != summary.tbs_digest
    {
        return Err(ClientError::Encoding);
    }
    let issuer: [u8; 256] = wire[956..1212]
        .try_into()
        .map_err(|_| ClientError::Encoding)?;
    let issuer_signature: [u8; 256] = signature_bits[1..]
        .try_into()
        .map_err(|_| ClientError::Encoding)?;
    let holder_signature: [u8; 256] = wire[1244..1500]
        .try_into()
        .map_err(|_| ClientError::Encoding)?;
    for modulus in [&issuer, &summary.holder_modulus_be] {
        if modulus[0] & 0x80 == 0 || modulus[255] & 1 == 0 {
            return Err(ClientError::Encoding);
        }
    }
    if issuer_signature >= issuer || holder_signature >= summary.holder_modulus_be {
        return Err(ClientError::Encoding);
    }
    let issuer_length = if summary.layout & 4 == 0 { 40 } else { 24 };
    for (offset, length) in summary.structural_offsets.iter().zip([
        16,
        13,
        13,
        issuer_length,
        64 - issuer_length,
        256,
        20,
        16,
        32,
    ]) {
        if usize::from(*offset) + length > tbs.len() {
            return Err(ClientError::Bound);
        }
    }
    for (index, expected) in [
        (5, summary.holder_modulus_be.as_slice()),
        (6, summary.signed_aki.as_slice()),
        (7, summary.signed_organization.as_slice()),
        (8, summary.signed_group.as_slice()),
    ] {
        let offset = usize::from(summary.structural_offsets[index]);
        if tbs.get(offset..offset + expected.len()) != Some(expected) {
            return Err(ClientError::Identity);
        }
    }
    let word = |start: usize| -> Result<FieldBytes, ClientError> {
        canonical(
            wire[start..start + 32]
                .try_into()
                .map_err(|_| ClientError::Encoding)?,
        )
    };
    let root = word(1822)?;
    let issuer_hash = word(1854)?;
    let policy_hash = word(1886)?;
    if issuer_hash != canonical(summary.issuer_hash)?
        || policy_hash != canonical(summary.policy_hash)?
    {
        return Err(ClientError::Identity);
    }
    let mut action: FieldBytes = wire[1212..1244]
        .try_into()
        .map_err(|_| ClientError::Encoding)?;
    action.reverse();
    canonical(action)?;
    let slot = u16::from_be_bytes(
        wire[1500..1502]
            .try_into()
            .map_err(|_| ClientError::Encoding)?,
    );
    if slot >= 1024 {
        return Err(ClientError::Bound);
    }
    let mut fields = vec![
        root,
        issuer_hash,
        small_field(summary.not_before),
        small_field(summary.not_after),
        action,
        policy_hash,
        small_field(u64::from(summary.layout)),
        small_field(u64::from(slot)),
    ];
    fields.extend(tbs.iter().map(|byte| small_field(u64::from(*byte))));
    fields.extend(rsa_limbs(&issuer));
    fields.extend(rsa_limbs(&issuer_signature));
    fields.extend(rsa_limbs(&holder_signature));
    for start in (1502..1822).step_by(32) {
        fields.push(word(start)?);
    }
    fields.extend((0..10).map(|level| small_field(u64::from((slot >> level) & 1))));
    fields.try_into().map_err(|_| ClientError::Bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use sha2::{Digest as _, Sha256};
    use std::time::{Duration, Instant};

    fn field(value: u128) -> FieldBytes {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    // Test oracle over unsigned BE bytes, independent of any native limb helper.
    fn limbs(bytes: &[u8; 256]) -> Vec<FieldBytes> {
        let bits: Vec<_> = bytes
            .iter()
            .rev()
            .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1))
            .collect();
        (0..17)
            .map(|limb| {
                let start = limb * 121;
                let value = bits[start..bits.len().min(start + 121)]
                    .iter()
                    .enumerate()
                    .fold(0u128, |value, (bit, digit)| {
                        value | (u128::from(*digit) << bit)
                    });
                field(value)
            })
            .collect()
    }

    fn fixture() -> (
        V3InputWorkerRequest,
        Vec<u8>,
        [FieldBytes; V3_INPUT_SCALARS],
    ) {
        // Deliberately synthetic non-eligible DER envelopes, never a credential
        // admission fixture. No signature, Poseidon, worker or key is evaluated.
        let mut tbs = [0x5a; 672];
        tbs[..4].copy_from_slice(&[0x30, 0x82, 0x02, 0x9c]);
        let mut holder = [0x33; 256];
        holder[0] |= 0x80;
        holder[255] |= 1;
        tbs[160..416].copy_from_slice(&holder);
        let issuer_signature = [0x11; 256];
        let holder_signature = [0x22; 256];
        let mut issuer = [0; 256];
        issuer[0] = 0x80;
        issuer[255] = 1;
        let summary = V3CredentialSummary {
            layout: 3,
            tbs_digest: Sha256::digest(tbs).into(),
            holder_modulus_be: holder,
            issuer_hash: field(8),
            policy_hash: field(11),
            not_before: 100,
            not_after: 200,
            signed_aki: [0x5a; 20],
            signed_organization: [0x5a; 16],
            signed_group: [0x5a; 32],
            structural_offsets: [16, 40, 60, 80, 120, 160, 420, 450, 480],
        };
        let mut certificate = vec![0x30, 0x82, 0x03, 0xb4];
        certificate.extend(tbs);
        certificate.extend([
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
            0x00,
        ]);
        certificate.extend([0x03, 0x82, 0x01, 0x01, 0x00]);
        certificate.extend(issuer_signature);
        assert_eq!(certificate.len(), 952);
        let slot = 513u16;
        let siblings: [FieldBytes; 10] = std::array::from_fn(|i| field(30 + i as u128));
        let mut action = field(9);
        action.reverse();
        let mut wire = b"V3Q1".to_vec();
        wire.extend(certificate);
        wire.extend(issuer);
        wire.extend(action);
        wire.extend(holder_signature);
        wire.extend(slot.to_be_bytes());
        for sibling in siblings {
            wire.extend(sibling);
        }
        wire.extend(field(7));
        wire.extend(summary.issuer_hash);
        wire.extend(summary.policy_hash);
        let request = V3InputWorkerRequest {
            wire: wire.try_into().expect("fixed synthetic request"),
            expected_summary: summary,
        };
        let mut scalars = vec![
            field(7),
            field(8),
            field(100),
            field(200),
            field(9),
            field(11),
            field(3),
            field(u128::from(slot)),
        ];
        scalars.extend(tbs.iter().map(|byte| field(u128::from(*byte))));
        scalars.extend(limbs(&issuer));
        scalars.extend(limbs(&issuer_signature));
        scalars.extend(limbs(&holder_signature));
        scalars.extend(siblings);
        scalars.extend((0..10).map(|level| field(u128::from((slot >> level) & 1))));
        let scalars: [FieldBytes; V3_INPUT_SCALARS] = scalars.try_into().expect("751 fields");
        let s = &request.expected_summary;
        let mut response = b"V3I1V3A1".to_vec();
        response.push(s.layout);
        response.extend(s.tbs_digest);
        response.extend(s.holder_modulus_be);
        response.extend(s.issuer_hash);
        response.extend(s.policy_hash);
        response.extend(s.not_before.to_be_bytes());
        response.extend(s.not_after.to_be_bytes());
        response.extend(s.signed_aki);
        response.extend(s.signed_organization);
        response.extend(s.signed_group);
        for offset in s.structural_offsets {
            response.extend(offset.to_be_bytes());
        }
        for scalar in scalars {
            response.extend(scalar);
        }
        assert_eq!(response.len(), V3_INPUT_RESPONSE_BYTES);
        (request, response, scalars)
    }

    #[test]
    fn synthetic_reply_compares_all_751_inputs_without_authorizing_a_credential() {
        let (request, response, expected) = fixture();
        let candidate = compare_response(&response, &request)
            .expect("independent v3 input response comparison is implemented");
        assert!(candidate.scalars == expected);
        assert!(candidate.summary == request.expected_summary);
    }

    #[test]
    fn every_scalar_and_summary_byte_must_match_independent_request_values() {
        let (request, response, _) = fixture();
        for index in 0..V3_INPUT_SCALARS {
            let mut changed = response.clone();
            changed[4 + 459 + index * 32] ^= 1;
            assert!(
                compare_response(&changed, &request).is_err(),
                "field {index}"
            );
        }
        for index in 4..4 + 459 {
            let mut changed = response.clone();
            changed[index] ^= 1;
            assert!(
                compare_response(&changed, &request).is_err(),
                "summary {index}"
            );
        }
        for offset in [4, 956, 1212, 1244, 1500, 1502, 1822, 1854, 1886] {
            let mut changed = V3InputWorkerRequest {
                wire: request.wire,
                expected_summary: request.expected_summary.clone(),
            };
            changed.wire[offset] ^= 1;
            assert!(
                compare_response(&response, &changed).is_err(),
                "request {offset}"
            );
        }
    }

    #[test]
    fn reply_header_length_and_each_fr_encoding_are_exact() {
        let (request, response, _) = fixture();
        assert!(compare_response(&response[..response.len() - 1], &request).is_err());
        let mut trailing = response.clone();
        trailing.push(0);
        assert!(compare_response(&trailing, &request).is_err());
        let mut header = response.clone();
        header[..4].copy_from_slice(b"V2I1");
        assert!(compare_response(&header, &request).is_err());
        let modulus = Fr::MODULUS.to_bytes_le();
        assert_eq!(modulus.len(), 32);
        for index in 0..V3_INPUT_SCALARS {
            let mut alias = response.clone();
            let start = 4 + 459 + 32 * index;
            alias[start..start + 32].copy_from_slice(&modulus);
            assert!(compare_response(&alias, &request).is_err(), "alias {index}");
        }
    }

    #[test]
    fn request_constructor_preserves_fixed_wire_and_rejects_aliases() {
        let (request, _, _) = fixture();
        let parsed = V3InputWorkerRequest::from_wire(&request.wire, &request.expected_summary)
            .expect("fixed v3 input request construction is implemented");
        assert!(parsed.wire == request.wire);
        assert!(parsed.expected_summary == request.expected_summary);
        assert!(
            V3InputWorkerRequest::from_wire(&request.wire[..1917], &request.expected_summary)
                .is_err()
        );
        let mut changed = request.wire.to_vec();
        changed.push(0);
        assert!(V3InputWorkerRequest::from_wire(&changed, &request.expected_summary).is_err());
        let mut wrong_header = request.wire;
        wrong_header[..4].copy_from_slice(b"V2Q1");
        assert!(V3InputWorkerRequest::from_wire(&wrong_header, &request.expected_summary).is_err());
        let mut wrong_slot = request.wire;
        wrong_slot[1500..1502].copy_from_slice(&1024u16.to_be_bytes());
        assert!(V3InputWorkerRequest::from_wire(&wrong_slot, &request.expected_summary).is_err());
        let modulus = Fr::MODULUS.to_bytes_le();
        for start in [1502, 1822, 1854, 1886] {
            let mut alias = request.wire;
            alias[start..start + 32].copy_from_slice(&modulus);
            assert!(V3InputWorkerRequest::from_wire(&alias, &request.expected_summary).is_err());
        }
        let mut action_alias = request.wire;
        let mut modulus_be = modulus;
        modulus_be.reverse();
        action_alias[1212..1244].copy_from_slice(&modulus_be);
        assert!(V3InputWorkerRequest::from_wire(&action_alias, &request.expected_summary).is_err());
    }

    #[test]
    fn cancelled_and_expired_transport_stop_before_io_or_spawn() {
        let (request, _, _) = fixture();
        let worker = V3InputWorker {
            private_root: PathBuf::from("/nonexistent-v3-input-red"),
        };
        let control = OperationControl::new(Instant::now() + Duration::from_secs(1));
        control.cancel();
        assert!(matches!(
            worker.build(&request, &control),
            Err(ClientError::Cancelled)
        ));
        let expired = OperationControl::new(Instant::now());
        assert!(matches!(
            worker.build(&request, &expired),
            Err(ClientError::Deadline)
        ));
    }
}
