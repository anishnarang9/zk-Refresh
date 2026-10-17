//! Strict bounded-v3 DER import only. Cryptographic/profile admission does not
//! enroll an issuer, enable a policy or authorize an application. No v3 proving
//! package is admitted here; R1CS/profile/schema commitments are separate pins.
use crate::{
    decode_digest, ClientError, Digest, FieldBytes, OperationControl, PinnedFile, WorkerRunner,
};
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub const V3_CERTIFICATE_BYTES: usize = 952;
pub const V3_TBS_BYTES: usize = 672;
pub const V3_OFFSET_NAMES: [&str; 9] = [
    "serial",
    "not_before",
    "not_after",
    "issuer_cn",
    "subject_cn",
    "modulus",
    "aki",
    "organization",
    "group",
];
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3AdmissionError {
    MalformedOrUnsupportedCredential,
    InvalidIssuerSignature,
    Operation(ClientError),
}
impl From<ClientError> for V3AdmissionError {
    fn from(value: ClientError) -> Self {
        Self::Operation(value)
    }
}
impl std::fmt::Display for V3AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for V3AdmissionError {}
type Result<T> = std::result::Result<T, V3AdmissionError>;

/// Source commitments only, not an engine circuit/package/VK identity. A
/// qualified setup must later authenticate its association with these pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3AdmissionIdentity {
    pub profile: Digest,
    pub r1cs: Digest,
    pub semantic_schema: Digest,
}
impl V3AdmissionIdentity {
    pub fn frozen_development() -> Result<Self> {
        Ok(Self {
            profile: decode_digest(
                "2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918",
            )?,
            r1cs: decode_digest(
                "976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888",
            )?,
            semantic_schema: decode_digest(
                "eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4",
            )?,
        })
    }
    pub fn check(&self) -> Result<()> {
        if *self != Self::frozen_development()? {
            return Err(ClientError::Identity.into());
        }
        Ok(())
    }
}
/// Private credential metadata; deliberately no Debug or serialization. Both
/// hashes are canonical LE32 Fr. AKI/org/group are extracted signed bytes;
/// offsets are derived by structural parsing, in V3_OFFSET_NAMES order.
#[derive(Clone, PartialEq, Eq)]
pub struct V3CredentialSummary {
    pub layout: u8,
    pub tbs_digest: Digest,
    pub holder_modulus_be: [u8; 256],
    pub issuer_hash: FieldBytes,
    pub policy_hash: FieldBytes,
    pub not_before: u64,
    pub not_after: u64,
    pub signed_aki: [u8; 20],
    pub signed_organization: [u8; 16],
    pub signed_group: [u8; 32],
    pub structural_offsets: [u16; 9],
}
/// One holder-private imported credential. A valid signature under the supplied
/// issuer key does not prove that key/AKI is enrolled or its policy is enabled.
/// Keep this object separate from the shareable proving package and enrollment.
pub struct ImportedV3Credential {
    certificate: Vec<u8>,
    issuer_modulus_be: [u8; 256],
    summary: V3CredentialSummary,
    identity: V3AdmissionIdentity,
}
impl Drop for ImportedV3Credential {
    fn drop(&mut self) {
        self.certificate.fill(0);
    }
}
impl ImportedV3Credential {
    /// Internal immutable DER bytes; never a public credential export.
    pub(crate) fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }
    pub fn summary(&self) -> &V3CredentialSummary {
        &self.summary
    }
    pub fn admission_identity(&self) -> V3AdmissionIdentity {
        self.identity
    }
    pub fn issuer_public_modulus(&self) -> &[u8; 256] {
        &self.issuer_modulus_be
    }
}
fn malformed<T>() -> Result<T> {
    Err(V3AdmissionError::MalformedOrUnsupportedCredential)
}
fn decode_summary(bytes: &[u8]) -> Result<V3CredentialSummary> {
    if bytes.len() != 459 || &bytes[..4] != b"V3A1" || bytes[4] >= 8 {
        return malformed();
    }
    let word = |start: usize| -> FieldBytes {
        bytes[start..start + 32]
            .try_into()
            .expect("fixed response width")
    };
    let issuer_hash = word(293);
    let policy_hash = word(325);
    for field in [issuer_hash, policy_hash] {
        Fr::deserialize_compressed(&field[..])
            .map_err(|_| V3AdmissionError::MalformedOrUnsupportedCredential)?;
    }
    let before = u64::from_be_bytes(bytes[357..365].try_into().expect("fixed epoch"));
    let after = u64::from_be_bytes(bytes[365..373].try_into().expect("fixed epoch"));
    if before > after || bytes[37] & 0x80 == 0 || bytes[292] & 1 == 0 {
        return malformed();
    }
    let offsets = std::array::from_fn(|i| {
        u16::from_be_bytes(
            bytes[441 + 2 * i..443 + 2 * i]
                .try_into()
                .expect("fixed offset"),
        )
    });
    let issuer_len = if bytes[4] & 4 != 0 { 24 } else { 40 };
    let subject_len = 64 - issuer_len;
    for (offset, length) in
        offsets
            .iter()
            .zip([16, 13, 13, issuer_len, subject_len, 256, 20, 16, 32])
    {
        if *offset as usize + length > V3_TBS_BYTES {
            return malformed();
        }
    }
    Ok(V3CredentialSummary {
        layout: bytes[4],
        tbs_digest: word(5),
        holder_modulus_be: bytes[37..293].try_into().expect("fixed modulus"),
        issuer_hash,
        policy_hash,
        not_before: before,
        not_after: after,
        signed_aki: bytes[373..393].try_into().expect("fixed AKI"),
        signed_organization: bytes[393..409].try_into().expect("fixed organization"),
        signed_group: bytes[409..441].try_into().expect("fixed group"),
        structural_offsets: offsets,
    })
}
fn private_root(root: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(root).map_err(|_| ClientError::Io)?;
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| ClientError::Io)? != root
        || !meta.is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(ClientError::Identity.into());
    }
    Ok(())
}
struct PrivateRun(PathBuf);
impl Drop for PrivateRun {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
/// Pinned worker delegates parsing to exact reviewed bounded-v3 source, loaded
/// directly rather than through Python bytecode caches. No credential offsets,
/// key bytes or source are changed to admit another eligible certificate.
pub struct V3CredentialImporter {
    runner: WorkerRunner,
    private_root: PathBuf,
    identity: V3AdmissionIdentity,
}
impl V3CredentialImporter {
    pub fn new(
        python: PinnedFile,
        worker: PinnedFile,
        private: impl AsRef<Path>,
        identity: V3AdmissionIdentity,
    ) -> Result<Self> {
        identity.check()?;
        let expected: Digest =
            Sha256::digest(include_bytes!("../workers/v3_admission_worker.py")).into();
        if worker.digest != expected {
            return Err(ClientError::Identity.into());
        }
        let private = private.as_ref();
        private_root(private)?;
        Ok(Self {
            runner: WorkerRunner::pinned(python, worker),
            private_root: private.to_owned(),
            identity,
        })
    }
    pub fn import(
        &mut self,
        certificate: &[u8],
        issuer_modulus_be: &[u8; 256],
        control: &OperationControl,
    ) -> Result<ImportedV3Credential> {
        control.check()?;
        self.identity.check()?;
        private_root(&self.private_root)?;
        if certificate.len() != V3_CERTIFICATE_BYTES {
            return malformed();
        }
        if issuer_modulus_be[0] & 0x80 == 0 || issuer_modulus_be[255] & 1 == 0 {
            return Err(V3AdmissionError::InvalidIssuerSignature);
        }
        let path = self.private_root.join(format!(
            "v3-admission-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| ClientError::Io)?;
        let run = PrivateRun(path);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(run.0.join("request.bin"))
            .map_err(|_| ClientError::Io)?;
        file.write_all(certificate).map_err(|_| ClientError::Io)?;
        file.write_all(issuer_modulus_be)
            .map_err(|_| ClientError::Io)?;
        drop(file);
        let status = self
            .runner
            .run(&[std::ffi::OsStr::new("admit"), run.0.as_os_str()], control)?;
        match status {
            0 => (),
            10 => return malformed(),
            11 => return Err(V3AdmissionError::InvalidIssuerSignature),
            20 => return Err(ClientError::Identity.into()),
            _ => return Err(ClientError::Worker.into()),
        }
        control.check()?;
        let output = run.0.join("output.bin");
        let meta = fs::symlink_metadata(&output).map_err(|_| ClientError::Io)?;
        let owner = fs::metadata(&self.private_root)
            .map_err(|_| ClientError::Io)?
            .uid();
        if !meta.is_file()
            || meta.len() != 459
            || meta.permissions().mode() & 0o777 != 0o600
            || meta.uid() != owner
            || meta.nlink() != 1
        {
            return Err(ClientError::Identity.into());
        }
        let file = File::open(output).map_err(|_| ClientError::Io)?;
        let opened = file.metadata().map_err(|_| ClientError::Io)?;
        if (opened.dev(), opened.ino(), opened.len()) != (meta.dev(), meta.ino(), meta.len()) {
            return Err(ClientError::Identity.into());
        }
        let mut bytes = Vec::new();
        file.take(460)
            .read_to_end(&mut bytes)
            .map_err(|_| ClientError::Io)?;
        let summary = decode_summary(&bytes);
        bytes.fill(0);
        let summary = summary?;
        control.check()?;
        Ok(ImportedV3Credential {
            certificate: certificate.to_vec(),
            issuer_modulus_be: *issuer_modulus_be,
            summary,
            identity: self.identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encoded() -> Vec<u8> {
        let mut bytes = vec![0; 459];
        bytes[..4].copy_from_slice(b"V3A1");
        bytes[37] = 0x80;
        bytes[292] = 1;
        bytes[364] = 1;
        bytes[372] = 2;
        bytes
    }
    #[test]
    fn metadata_layout_and_bounds_are_checked_without_private_debug_output() {
        let mut bytes = encoded();
        assert!(decode_summary(&bytes).is_ok());
        bytes[4] = 8;
        assert!(matches!(
            decode_summary(&bytes),
            Err(V3AdmissionError::MalformedOrUnsupportedCredential)
        ));
        bytes[4] = 0;
        bytes[441..443].copy_from_slice(&672u16.to_be_bytes());
        assert!(matches!(
            decode_summary(&bytes),
            Err(V3AdmissionError::MalformedOrUnsupportedCredential)
        ));
        assert!(decode_summary(&[]).is_err());
    }
    #[test]
    fn modulus_epoch_and_field_aliases_fail_metadata_admission() {
        let mut bytes = encoded();
        bytes[292] = 0;
        assert!(decode_summary(&bytes).is_err());
        let mut bytes = encoded();
        bytes[364] = 3;
        assert!(decode_summary(&bytes).is_err());
        use ark_ff::{BigInteger, PrimeField};
        let mut bytes = encoded();
        bytes[293..325].copy_from_slice(&Fr::MODULUS.to_bytes_le());
        assert!(decode_summary(&bytes).is_err());
    }
    #[test]
    fn v3_source_identity_never_accepts_a_v2_or_unknown_profile() {
        let mut identity = V3AdmissionIdentity::frozen_development().unwrap();
        assert!(identity.check().is_ok());
        identity.profile = [0; 32];
        assert_eq!(
            identity.check(),
            Err(V3AdmissionError::Operation(ClientError::Identity))
        );
    }
}

#[cfg(test)]
#[path = "../tests/support/v3_imported_local_input.rs"]
mod imported_local_input_tests;
