//! Structural input construction only. Synthetic DER/signatures below are not
//! credential admission, holder RSA, membership or chain-authentication evidence.
use super::*;
use crate::{
    v3_input_worker::build_imported_local_request, OperationControl, V3ActionConfig,
    V3ActionRequest, V3CheckedLocalAccounts, V3FullManifest, V3InputWorkerRequest,
    V3LocalAccount, V3LocalAccountSet, V3UntrustedLocalPath,
};
use std::result::Result;
// Reuse the existing byte-accurate synthetic account fixture and its tests.
include!("v3_local_accounts.rs");

fn imported_fixture() -> (Fixture, ImportedV3Credential, [u8; 256]) {
    let mut f = Fixture::new();
    let mut tbs = [0x5a; 672];
    tbs[..4].copy_from_slice(&[0x30, 0x82, 0x02, 0x9c]);
    tbs[160..416].copy_from_slice(&f.summary.holder_modulus_be);
    tbs[420..440].copy_from_slice(&f.summary.signed_aki);
    tbs[450..466].copy_from_slice(&f.summary.signed_organization);
    tbs[480..512].copy_from_slice(&f.summary.signed_group);
    f.summary.layout = 3;
    f.summary.structural_offsets = [16, 40, 60, 80, 120, 160, 420, 450, 480];
    f.summary.tbs_digest = Sha256::digest(tbs).into();
    let mut der = vec![0x30, 0x82, 0x03, 0xb4];
    der.extend(tbs);
    der.extend([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00]);
    der.extend([0x03, 0x82, 0x01, 0x01, 0x00]);
    der.extend([0x11; 256]);
    let mut issuer = [0; 256];
    issuer[0] = 0x80;
    issuer[255] = 1;
    let imported = ImportedV3Credential {
        certificate: der,
        issuer_modulus_be: issuer,
        summary: f.summary.clone(),
        identity: V3AdmissionIdentity::frozen_development().unwrap(),
    };
    (f, imported, [0x22; 256])
}

fn build(
    f: &Fixture,
    credential: &ImportedV3Credential,
    signature: &[u8; 256],
    expected_action: Digest,
    slot: u16,
    siblings: &[FieldBytes; 10],
) -> Result<V3InputWorkerRequest, ClientError> {
    build_imported_local_request(
        credential, &f.manifest, &f.accounts(), expected_action, signature,
        &V3UntrustedLocalPath { slot, siblings }, 1100,
        &OperationControl::new(Instant::now() + Duration::from_secs(5)),
    )
}

#[test]
fn imported_local_request_accepts_only_structurally_bound_credential_and_action() {
    let (mut f, mut credential, signature) = imported_fixture();
    let path = [le(30); 10];
    assert!(build(&f, &credential, &signature, f.action(), 513, &path).is_ok());
    let expected = f.action();
    f.request[72] ^= 1;
    assert!(build(&f, &credential, &signature, expected, 513, &path).is_err());
    f.request[72] ^= 1;
    f.request[1225] ^= 1;
    assert!(build(&f, &credential, &signature, expected, 513, &path).is_err());
    f.request[1225] ^= 1;
    credential.certificate[50] ^= 1;
    assert!(build(&f, &credential, &signature, expected, 513, &path).is_err());
}

#[test]
fn imported_local_request_rejects_issuer_profile_signature_and_path_aliases() {
    let (mut f, mut credential, signature) = imported_fixture();
    let path = [le(30); 10];
    let action = f.action();
    f.issuer[40] ^= 1;
    assert!(build(&f, &credential, &signature, action, 513, &path).is_err());
    f.issuer[40] ^= 1;
    credential.identity.profile[0] ^= 1;
    assert!(build(&f, &credential, &signature, action, 513, &path).is_err());
    credential.identity.profile[0] ^= 1;
    assert!(build(&f, &credential, &[0xff; 256], action, 513, &path).is_err());
    assert!(build(&f, &credential, &signature, action, 1024, &path).is_err());
    let mut alias = path;
    alias[0] = decode_digest("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001").unwrap();
    alias[0].reverse();
    assert!(build(&f, &credential, &signature, action, 513, &alias).is_err());
}
