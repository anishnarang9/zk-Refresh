use dynark_bn254::{PackageIdentity, Shape};
use dynark_native_client::*;

fn manifest() -> V2FullManifest {
    V2FullManifest::accepted_development().unwrap()
}

#[test]
fn exact_v2_manifest_rejects_schema_profile_and_package_substitution() {
    let accepted = manifest();
    assert_eq!(
        accepted.check_identity(
            accepted.native.package,
            Shape {
                constraint_rows: 775166,
                reduction_rows: 775166,
                assignment_len: V2_COORDINATES,
                instance_len: 6,
                domain_size: 1048576,
            }
        ),
        Ok(())
    );
    let mut wrong = accepted;
    wrong.semantic_schema = [0; 32];
    assert_eq!(wrong.check(), Err(ClientError::Identity));
    wrong = accepted;
    wrong.profile = [0; 32];
    assert_eq!(wrong.check(), Err(ClientError::Identity));
    wrong = accepted;
    wrong.native.package = PackageIdentity {
        package_digest: [0; 32],
        ..accepted.native.package
    };
    assert_eq!(wrong.check(), Err(ClientError::Identity));
    wrong = accepted;
    wrong.ordinary_vk_file_sha256 = wrong.native.ordinary_vk_digest;
    assert_eq!(wrong.check(), Err(ClientError::Identity));
}

#[test]
fn v2_binding_rejects_v1_mapping_and_cross_profile_or_package() {
    let accepted = manifest();
    let mut binding = WitnessBinding {
        package: accepted.native.package,
        profile: accepted.profile,
        credential: [3; 32],
        credential_version: 1,
        action: [4; 32],
        issuer: [5; 32],
        target: RootTarget {
            root: [0; 32],
            version: 1,
            issuer_version: 1,
            policy_version: 1,
        },
        mapping: [0; 32],
        generation: 1,
    };
    assert_eq!(accepted.check_binding(&binding), Ok(()));
    binding.mapping = decode_digest(V1_MAPPING_HEX).unwrap();
    assert_eq!(
        accepted.check_binding(&binding),
        Err(ClientError::Unsupported)
    );
    binding.mapping = [0; 32];
    binding.profile = [1; 32];
    assert_eq!(accepted.check_binding(&binding), Err(ClientError::Identity));
}

#[test]
fn v2_shape_is_exact_and_rejects_v1_or_wrong_instance_dimension() {
    let accepted = manifest();
    let shape = Shape {
        constraint_rows: 775166,
        reduction_rows: 775166,
        assignment_len: V2_COORDINATES,
        instance_len: 6,
        domain_size: 1048576,
    };
    assert_eq!(
        accepted.check_identity(
            accepted.native.package,
            Shape {
                assignment_len: V1_COORDINATES,
                ..shape
            }
        ),
        Err(ClientError::Identity)
    );
    assert_eq!(
        accepted.check_identity(
            accepted.native.package,
            Shape {
                instance_len: 5,
                ..shape
            }
        ),
        Err(ClientError::Identity)
    );
}

#[test]
fn v2_parser_rejects_truncation_before_allocating() {
    assert_eq!(parse_canonical_v2_wtns(&[]), Err(ClientError::Encoding));
    assert_eq!(
        parse_canonical_v2_wtns(&[0; 76]),
        Err(ClientError::Encoding)
    );
}

#[test]
fn complete_v2_wtns_is_canonical_and_rejects_constant_modulus_and_v1_shape() {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    let mut bytes = Vec::with_capacity(V2_WITNESS_BYTES);
    bytes.extend_from_slice(b"wtns");
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&40u64.to_le_bytes());
    bytes.extend_from_slice(&32u32.to_le_bytes());
    bytes.extend_from_slice(&Fr::MODULUS.to_bytes_le());
    bytes.extend_from_slice(&(V2_COORDINATES as u32).to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&(32u64 * V2_COORDINATES as u64).to_le_bytes());
    bytes.resize(V2_WITNESS_BYTES, 0);
    bytes[76] = 1;
    assert!(parse_canonical_v2_wtns(&bytes).is_ok());
    assert!(matches!(
        parse_canonical_wtns(&bytes),
        Err(ClientError::Encoding)
    ));
    bytes[76] = 0;
    assert!(matches!(
        parse_canonical_v2_wtns(&bytes),
        Err(ClientError::Encoding)
    ));
    bytes[76] = 1;
    bytes[108..140].copy_from_slice(&Fr::MODULUS.to_bytes_le());
    assert!(matches!(
        parse_canonical_v2_wtns(&bytes),
        Err(ClientError::Encoding)
    ));
}
