//! Supported local synthetic signer and authenticated fixed-template v2 input.
//! Authentication adapters remain responsible for current source/root binding.
use crate::{
    AuthenticatedTarget, ClientError, Digest, FieldBytes, OperationControl, PinnedFile,
    V2FullManifest, WitnessBinding, WorkerRunner,
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

static SERIAL: AtomicU64 = AtomicU64::new(0);

/// Signs SHA256(canonical BE32 actionHash) using RSA-2048/e65537/PKCS1-v1_5.
/// Implementations must honor cancellation/deadlines and never log key/message.
pub trait HolderSigner {
    fn sign_action(
        &mut self,
        action_be: Digest,
        control: &OperationControl,
    ) -> Result<[u8; 256], ClientError>;
}
/// Trusted capability from registry/status and onchain-state authentication.
/// `authorize` must require a fresh enabled issuer/policy, current root bound
/// to the exact source sequence/digest, certificate/action validity and current
/// generation. New source heads advance generation even if root is unchanged.
/// Field words here are canonical LE32; binding.action alone is canonical BE32.
pub trait AuthenticatedV2State {
    fn binding(&self) -> &WitnessBinding;
    fn issuer_hash(&self) -> FieldBytes;
    fn slot(&self) -> u16;
    fn siblings(&self) -> &[FieldBytes; 10];
    fn authorize(&self, now_unix: u64) -> Result<(), ClientError>;
}
fn canonical_word(word: FieldBytes) -> Result<(), ClientError> {
    Fr::deserialize_compressed(&word[..])
        .map(|_| ())
        .map_err(|_| ClientError::Encoding)
}
fn canonical_action(mut action: Digest) -> Result<FieldBytes, ClientError> {
    action.reverse();
    canonical_word(action)?;
    Ok(action)
}
fn checked_root(root: &Path) -> Result<(), ClientError> {
    let meta = fs::symlink_metadata(root).map_err(|_| ClientError::Io)?;
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| ClientError::Io)? != root
        || !meta.is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(ClientError::Identity);
    }
    Ok(())
}
struct PrivateRun(PathBuf);
impl Drop for PrivateRun {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ClientError::Io)?;
    file.write_all(bytes).map_err(|_| ClientError::Io)
}
fn read_private(path: &Path, max: u64, owner: u32) -> Result<Vec<u8>, ClientError> {
    let meta = fs::symlink_metadata(path).map_err(|_| ClientError::Io)?;
    if !meta.is_file()
        || meta.len() > max
        || meta.permissions().mode() & 0o777 != 0o600
        || meta.uid() != owner
        || meta.nlink() != 1
    {
        return Err(ClientError::Identity);
    }
    let file = File::open(path).map_err(|_| ClientError::Io)?;
    let opened = file.metadata().map_err(|_| ClientError::Io)?;
    if (opened.dev(), opened.ino(), opened.len()) != (meta.dev(), meta.ino(), meta.len()) {
        return Err(ClientError::Identity);
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ClientError::Io)?;
    if bytes.len() as u64 != meta.len() {
        return Err(ClientError::Bound);
    }
    Ok(bytes)
}
/// Shared pinned worker configuration; creates one isolated private invocation
/// per operation. Python runtime and installation directories are trusted.
pub struct V2InputWorker {
    runner: WorkerRunner,
    private_root: PathBuf,
}
impl V2InputWorker {
    pub fn new(
        python: PinnedFile,
        worker: PinnedFile,
        private_root: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        let expected: Digest =
            Sha256::digest(include_bytes!("../workers/v2_input_worker.py")).into();
        if worker.digest != expected {
            return Err(ClientError::Identity);
        }
        let root = private_root.as_ref();
        checked_root(root)?;
        Ok(Self {
            runner: WorkerRunner::pinned(python, worker),
            private_root: root.to_owned(),
        })
    }
    fn call(
        &self,
        mode: &str,
        files: &[(&str, &[u8])],
        max_output: u64,
        control: &OperationControl,
    ) -> Result<Vec<u8>, ClientError> {
        control.check()?;
        checked_root(&self.private_root)?;
        let path = self.private_root.join(format!(
            "v2-input-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| ClientError::Io)?;
        let run = PrivateRun(path);
        for (name, bytes) in files {
            write_private(&run.0.join(name), bytes)?;
        }
        let status = self
            .runner
            .run(&[std::ffi::OsStr::new(mode), run.0.as_os_str()], control)?;
        if status == 2 {
            return Err(ClientError::Encoding);
        }
        if status != 0 {
            return Err(ClientError::Worker);
        }
        control.check()?;
        let owner = fs::metadata(&self.private_root)
            .map_err(|_| ClientError::Io)?
            .uid();
        let result = read_private(&run.0.join("output.bin"), max_output, owner)?;
        control.check()?;
        Ok(result)
    }
}
/// Controlled development signer only. Key bytes are retained solely in the
/// caller's pinned 0600 private file and a temporary isolated invocation.
pub struct LocalSyntheticV2HolderSigner {
    worker: V2InputWorker,
    key: PinnedFile,
}
impl LocalSyntheticV2HolderSigner {
    pub fn new(worker: V2InputWorker, key: PinnedFile) -> Result<Self, ClientError> {
        if key.max_bytes > 8192 {
            return Err(ClientError::Bound);
        }
        let owner = fs::metadata(&worker.private_root)
            .map_err(|_| ClientError::Io)?
            .uid();
        let mut bytes = read_private(&key.path, 8192, owner)?;
        let actual: Digest = Sha256::digest(&bytes).into();
        bytes.fill(0);
        if actual != key.digest {
            return Err(ClientError::Identity);
        }
        Ok(Self { worker, key })
    }
}
impl HolderSigner for LocalSyntheticV2HolderSigner {
    fn sign_action(
        &mut self,
        action: Digest,
        control: &OperationControl,
    ) -> Result<[u8; 256], ClientError> {
        control.check()?;
        canonical_action(action)?;
        let owner = fs::metadata(&self.worker.private_root)
            .map_err(|_| ClientError::Io)?
            .uid();
        let mut key = read_private(&self.key.path, 8192, owner)?;
        if <[u8; 32]>::from(Sha256::digest(&key)) != self.key.digest {
            key.fill(0);
            return Err(ClientError::Identity);
        }
        let result = self.worker.call(
            "sign",
            &[("key.pem", &key), ("action.be", &action)],
            256,
            control,
        );
        key.fill(0);
        result?.try_into().map_err(|_| ClientError::Encoding)
    }
}
fn epoch(value: FieldBytes) -> Result<u64, ClientError> {
    if value[8..] != [0; 24] {
        return Err(ClientError::Encoding);
    }
    Ok(u64::from_le_bytes(
        value[..8].try_into().map_err(|_| ClientError::Encoding)?,
    ))
}
fn decode_response(
    bytes: &[u8],
    binding: &WitnessBinding,
    issuer: FieldBytes,
    now: u64,
) -> Result<(Vec<u8>, [FieldBytes; 5]), ClientError> {
    if bytes.len() < 200 || &bytes[..4] != b"V2I1" {
        return Err(ClientError::Encoding);
    }
    let mut publics = [[0; 32]; 5];
    for (word, chunk) in publics.iter_mut().zip(bytes[4..164].chunks_exact(32)) {
        word.copy_from_slice(chunk);
        canonical_word(*word)?;
    }
    if publics[0] != binding.target.root
        || publics[1] != issuer
        || publics[4] != canonical_action(binding.action)?
        || bytes[164..196] != binding.credential
    {
        return Err(ClientError::Identity);
    }
    let before = epoch(publics[2])?;
    let after = epoch(publics[3])?;
    if before > after || now < before || now > after {
        return Err(ClientError::Expired);
    }
    let length = u32::from_be_bytes(
        bytes[196..200]
            .try_into()
            .map_err(|_| ClientError::Encoding)?,
    ) as usize;
    if length == 0 || length > 65536 || bytes.len() != 200 + length {
        return Err(ClientError::Bound);
    }
    Ok((bytes[200..].to_vec(), publics))
}
#[derive(Clone, PartialEq, Eq)]
struct StateSnapshot {
    binding: WitnessBinding,
    issuer: FieldBytes,
    slot: u16,
    siblings: [FieldBytes; 10],
}
impl StateSnapshot {
    fn capture(state: &impl AuthenticatedV2State) -> Result<Self, ClientError> {
        V2FullManifest::accepted_development()?.check_binding(state.binding())?;
        if state.slot() >= 1024 {
            return Err(ClientError::Bound);
        }
        canonical_action(state.binding().action)?;
        canonical_word(state.binding().target.root)?;
        canonical_word(state.issuer_hash())?;
        for word in state.siblings() {
            canonical_word(*word)?;
        }
        Ok(Self {
            binding: state.binding().clone(),
            issuer: state.issuer_hash(),
            slot: state.slot(),
            siblings: *state.siblings(),
        })
    }
}
/// Private canonical input tied to its live authenticated state capability.
/// Complete WTNS/relation validation is still mandatory via open_v2/prepare.
pub struct V2InputTarget<'a, S: AuthenticatedV2State> {
    state: &'a S,
    snapshot: StateSnapshot,
    input: Vec<u8>,
    publics: [FieldBytes; 5],
}
impl<S: AuthenticatedV2State> Drop for V2InputTarget<'_, S> {
    fn drop(&mut self) {
        self.input.fill(0);
    }
}
impl<S: AuthenticatedV2State> AuthenticatedTarget for V2InputTarget<'_, S> {
    fn binding(&self) -> &WitnessBinding {
        &self.snapshot.binding
    }
    fn input(&self) -> &[u8] {
        &self.input
    }
    fn public_values(&self) -> &[FieldBytes] {
        &self.publics
    }
    fn authorize(&self, now: u64) -> Result<(), ClientError> {
        self.state.authorize(now)?;
        if StateSnapshot::capture(self.state)? != self.snapshot {
            return Err(ClientError::Superseded);
        }
        if now < epoch(self.publics[2])? || now > epoch(self.publics[3])? {
            return Err(ClientError::Expired);
        }
        Ok(())
    }
}
pub struct V2AuthenticatedInputBuilder {
    worker: V2InputWorker,
}
impl V2AuthenticatedInputBuilder {
    pub fn new(worker: V2InputWorker) -> Self {
        Self { worker }
    }
    pub fn build<'a, S: AuthenticatedV2State>(
        &mut self,
        certificate: &[u8],
        issuer_modulus_be: &[u8; 256],
        state: &'a S,
        signer: &mut impl HolderSigner,
        now: u64,
        control: &OperationControl,
    ) -> Result<V2InputTarget<'a, S>, ClientError> {
        control.check()?;
        state.authorize(now)?;
        let snapshot = StateSnapshot::capture(state)?;
        if certificate.len() != 936 {
            return Err(ClientError::Encoding);
        }
        let mut signature = signer.sign_action(snapshot.binding.action, control)?;
        control.check()?;
        state.authorize(now)?;
        if StateSnapshot::capture(state)? != snapshot {
            return Err(ClientError::Superseded);
        }
        let mut request = Vec::with_capacity(1866);
        request.extend(certificate);
        request.extend(issuer_modulus_be);
        request.extend(snapshot.binding.action);
        request.extend(signature);
        signature.fill(0);
        request.extend(snapshot.slot.to_be_bytes());
        for word in snapshot.siblings {
            request.extend(word);
        }
        request.extend(snapshot.binding.target.root);
        request.extend(snapshot.issuer);
        let result = self
            .worker
            .call("build", &[("request.bin", &request)], 65736, control);
        request.fill(0);
        let mut response = result?;
        let decoded = decode_response(&response, &snapshot.binding, snapshot.issuer, now);
        response.fill(0);
        let (input, publics) = decoded?;
        let target = V2InputTarget {
            state,
            snapshot,
            input,
            publics,
        };
        control.check()?;
        target.authorize(now)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct State {
        binding: WitnessBinding,
        issuer: std::cell::Cell<FieldBytes>,
        siblings: [FieldBytes; 10],
        status: std::cell::Cell<Result<(), ClientError>>,
    }
    impl AuthenticatedV2State for State {
        fn binding(&self) -> &WitnessBinding {
            &self.binding
        }
        fn issuer_hash(&self) -> FieldBytes {
            self.issuer.get()
        }
        fn slot(&self) -> u16 {
            7
        }
        fn siblings(&self) -> &[FieldBytes; 10] {
            &self.siblings
        }
        fn authorize(&self, _: u64) -> Result<(), ClientError> {
            self.status.get()
        }
    }
    #[test]
    fn changed_authenticated_state_or_revocation_fences_prepared_input() {
        let manifest = V2FullManifest::accepted_development().unwrap();
        let state = State {
            binding: WitnessBinding {
                package: manifest.native.package,
                profile: manifest.profile,
                credential: [7; 32],
                credential_version: 1,
                action: [0; 32],
                issuer: [8; 32],
                target: crate::RootTarget {
                    root: [0; 32],
                    version: 1,
                    issuer_version: 1,
                    policy_version: 1,
                },
                mapping: [0; 32],
                generation: 1,
            },
            issuer: std::cell::Cell::new([0; 32]),
            siblings: [[0; 32]; 10],
            status: std::cell::Cell::new(Ok(())),
        };
        let mut publics = [[0; 32]; 5];
        publics[3][0] = 200;
        let target = V2InputTarget {
            state: &state,
            snapshot: StateSnapshot::capture(&state).unwrap(),
            input: b"{}".to_vec(),
            publics,
        };
        assert_eq!(target.authorize(150), Ok(()));
        let mut changed = [0; 32];
        changed[0] = 1;
        state.issuer.set(changed);
        assert_eq!(target.authorize(150), Err(ClientError::Superseded));
        state.status.set(Err(ClientError::Revoked));
        assert_eq!(target.authorize(150), Err(ClientError::Revoked));
    }
    #[test]
    fn action_conversion_is_exact_and_rejects_modulus_alias() {
        let mut action = [0; 32];
        action[31] = 1;
        let le = canonical_action(action).unwrap();
        assert_eq!(le[0], 1);
        assert!(le[1..].iter().all(|b| *b == 0));
        use ark_ff::{BigInteger, PrimeField};
        let modulus: [u8; 32] = Fr::MODULUS.to_bytes_be().try_into().unwrap();
        assert_eq!(canonical_action(modulus), Err(ClientError::Encoding));
    }
    #[test]
    fn private_response_cannot_substitute_credential_or_publics() {
        let mut fields = [[0; 32]; 5];
        fields[0][0] = 10;
        fields[1][0] = 20;
        fields[2][0] = 100;
        fields[3][0] = 200;
        fields[4][0] = 30;
        let mut response = b"V2I1".to_vec();
        for word in fields {
            response.extend(word);
        }
        response.extend([7; 32]);
        response.extend(2u32.to_be_bytes());
        response.extend(b"{}");
        let mut action = [0; 32];
        action[31] = 30;
        let manifest = crate::V2FullManifest::accepted_development().unwrap();
        let binding = WitnessBinding {
            package: manifest.native.package,
            profile: manifest.profile,
            credential: [7; 32],
            credential_version: 1,
            action,
            issuer: [8; 32],
            target: crate::RootTarget {
                root: fields[0],
                version: 1,
                issuer_version: 1,
                policy_version: 1,
            },
            mapping: [0; 32],
            generation: 1,
        };
        assert!(decode_response(&response, &binding, fields[1], 150).is_ok());
        response[164] ^= 1;
        assert!(matches!(
            decode_response(&response, &binding, fields[1], 150),
            Err(ClientError::Identity)
        ));
        response[164] ^= 1;
        response[132] ^= 1;
        assert!(matches!(
            decode_response(&response, &binding, fields[1], 150),
            Err(ClientError::Identity)
        ));
        response[132] ^= 1;
        assert!(matches!(
            decode_response(&response, &binding, fields[1], 201),
            Err(ClientError::Expired)
        ));
    }
}
