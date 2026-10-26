use crate::ClientError;
use dynark_bn254::PackageIdentity;

pub type Digest = [u8; 32];
/// Canonical little-endian Fr encoding, matching WTNS and the engine API.
pub type FieldBytes = [u8; 32];
pub const V1_PACKAGE_HEX: &str = "57cea7ff53a711f8fbb2e8f256a21a852d087564c49df70b6065c6994765c0d5";
pub const V1_MAPPING_HEX: &str = "b842dd6bbcce1765629dad6af9e2b7e1d318df73a356887922316a40ed92ad67";

/// Selected from the trusted package manifest. M5 owns ordinary-VK digest
/// serialization/domain separation; this is never inferred from the engine VK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePackageManifest {
    pub package: PackageIdentity,
    pub ordinary_vk_digest: Digest,
}
impl NativePackageManifest {
    pub fn check(&self, package: &dynark_bn254::PublicPackage) -> Result<(), ClientError> {
        if self.package != package.identity() || self.ordinary_vk_digest == [0;32] {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootTarget {
    pub root: FieldBytes,
    pub version: u64,
    pub issuer_version: u64,
    pub policy_version: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WitnessBinding {
    pub package: PackageIdentity,
    pub profile: Digest,
    pub credential: Digest,
    pub credential_version: u64,
    /// Canonical big-endian actionHash encoding from the application contract.
    pub action: Digest,
    pub issuer: Digest,
    pub target: RootTarget,
    pub mapping: Digest,
    pub generation: u64,
}
impl WitnessBinding {
    pub fn same_reusable_context(&self, other: &Self) -> bool {
        self.package == other.package && self.profile == other.profile
            && self.credential == other.credential && self.credential_version == other.credential_version
            && self.action == other.action && self.issuer == other.issuer && self.mapping == other.mapping
            && self.target.issuer_version == other.target.issuer_version
            && self.target.policy_version == other.target.policy_version
    }
    pub fn check_v1(&self) -> Result<(), ClientError> {
        if self.package.package_digest != decode_digest(V1_PACKAGE_HEX)?
            || self.mapping != decode_digest(V1_MAPPING_HEX)?
            || self.profile != decode_digest("66c76a69bc8da77248778f2c651705022e572320af29dbf38d3541e21ed4b9f4")? {
            return Err(ClientError::Unsupported);
        }
        Ok(())
    }
}

pub fn decode_digest(value: &str) -> Result<Digest, ClientError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ClientError::Encoding);
    }
    let mut result = [0;32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2*i..2*i+2], 16).map_err(|_| ClientError::Encoding)?;
    }
    Ok(result)
}

/// Implementations are trusted authentication adapters, not untrusted data holders.
/// The adapter checks source signature, predecessor/current snapshot, membership,
/// issuer freshness and policy before returning a target capability.
pub trait AuthenticatedTarget {
    fn binding(&self) -> &WitnessBinding;
    fn input(&self) -> &[u8];
    fn public_values(&self) -> &[FieldBytes];
    fn authorize(&self, now_unix: u64) -> Result<(), ClientError>;
}

pub trait CredentialProfile {
    fn profile_digest(&self) -> Digest;
    fn admit(&self, credential: &[u8]) -> Result<Digest, ClientError>;
}

pub trait SubmissionAdapter {
    type Submission;
    fn prepare(&mut self, proof: &crate::ProofResult) -> Result<Self::Submission, ClientError>;
    fn receipt(&mut self, action: Digest) -> Result<crate::EffectOutcome, ClientError>;
}
