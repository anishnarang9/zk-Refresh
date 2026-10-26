//! Exact fixed-template development v2 Full package boundary. These pins do not
//! admit the generalizable successor profile or enable incremental witnesses.
use crate::{decode_digest, ClientError, Digest, NativePackageManifest, WitnessBinding};
use dynark_bn254::{PackageIdentity, PublicPackage, Shape};

pub const V2_COORDINATES: usize = 769_108;
pub const V2_WITNESS_BYTES: usize = 76 + 32 * V2_COORDINATES;
pub const V2_WASM_HEX: &str = "050084646eef2aa3bf827e4486f7aebe11483b4b4f1fd7785f146e6c8b36d760";
pub const V2_CALCULATOR_HEX: &str =
    "cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942";

/// Separately named commitments: tagged ordinary VK is not its raw file hash
/// and neither is the engine's extended VK commitment in `native.package`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2FullManifest {
    pub native: NativePackageManifest,
    pub profile: Digest,
    pub semantic_schema: Digest,
    pub ordinary_vk_file_sha256: Digest,
}
impl V2FullManifest {
    /// Accepted synthetic development setup, never a production ceremony claim.
    pub fn accepted_development() -> Result<Self, ClientError> {
        Ok(Self {
            native: NativePackageManifest {
                package: PackageIdentity {
                    circuit_digest: decode_digest(
                        "da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146",
                    )?,
                    matrix_digest: decode_digest(
                        "b53cdc6c346056fd7fb12274ca5a60338f47e20413bfd163a96123a650ff0e4b",
                    )?,
                    proving_key_digest: decode_digest(
                        "9cff95490d8198690888d84262821077227093c2a4aefe84076f2aa3b7da9a21",
                    )?,
                    verifying_key_digest: decode_digest(
                        "b2678dbd6c04cfb536826cf26156ac5a046c1cdfe3734ea936f79e5d5f2a3a06",
                    )?,
                    package_digest: decode_digest(
                        "04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb",
                    )?,
                },
                ordinary_vk_digest: decode_digest(
                    "e677671299cae78e1a7a3015aaac5200d03c8b54d562c8362cb326721610b22a",
                )?,
            },
            profile: decode_digest(
                "eb77028b2bd1e324c6ee74c40b43739ec2ce519014f6d04aebe2ca7f82aa1f68",
            )?,
            semantic_schema: decode_digest(
                "de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611",
            )?,
            ordinary_vk_file_sha256: decode_digest(
                "52b614e3a8560ae8b5dc246bc197944a95072b8784b5a2c9c84c740f119925e3",
            )?,
        })
    }
    pub fn check(&self) -> Result<(), ClientError> {
        if *self != Self::accepted_development()? {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    pub fn check_identity(
        &self,
        identity: PackageIdentity,
        shape: Shape,
    ) -> Result<(), ClientError> {
        self.check()?;
        if identity != self.native.package
            || shape.assignment_len != V2_COORDINATES
            || shape.instance_len != 6
            || shape.constraint_rows != 775_166
            || shape.reduction_rows != 775_166
            || shape.domain_size != 1_048_576
        {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    pub fn check_package(&self, package: &PublicPackage) -> Result<(), ClientError> {
        self.check_identity(package.identity(), package.shape())
    }
    pub fn check_binding(&self, binding: &WitnessBinding) -> Result<(), ClientError> {
        self.check()?;
        if binding.package != self.native.package || binding.profile != self.profile {
            return Err(ClientError::Identity);
        }
        // No compiler-derived v2 mapping is qualified. Zero explicitly denotes
        // Full-only; a v1 or invented mapping cannot enable incremental reuse.
        if binding.mapping != [0; 32] {
            return Err(ClientError::Unsupported);
        }
        Ok(())
    }
}
