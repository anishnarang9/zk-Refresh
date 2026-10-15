//! Publisher RED: independent fixture crypto first, then the rejecting gate.
//! Fixture generation is a separately granted prerequisite; no JSON is authority.
use credential_registry::v3::protocol::{
    CurrentHead, EnrolledSource, IssuerScope, PublisherBinding, Scope, SignedSource, SourceHead,
    VerifiedSource,
};
use credential_registry::{Error, Field};
use openssl::{
    pkey::{Id, PKey},
    sign::Verifier,
};
use serde::Serialize;
use serde_json::Value;
use std::{fs, path::Path};

const PUBLISHER_TAG: &[u8] = b"DYNARK-V3-PUBLISHER-BINDING-v1\0";

fn vectors() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v3-publisher-auth-v1.json");
    let raw =
        fs::read(path).expect("ROOT must materialize/pin the new independent fixture before RED");
    assert!(raw.len() <= 2 * 1024 * 1024);
    serde_json::from_slice(&raw).unwrap()
}
fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert_eq!(text.len() % 2, 0);
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
#[derive(Serialize)]
struct IndependentBody<'a> {
    scope: &'a Scope,
    issuer: &'a IssuerScope,
    source_head: &'a SourceHead,
    root: Field,
    root_version: u64,
    publisher_key: [u8; 32],
    publication_sequence: u64,
    previous_publication_digest: [u8; 32],
}
fn genuine_binding(row: &Value) -> PublisherBinding {
    let b: PublisherBinding = serde_json::from_value(row["binding"].clone()).unwrap();
    let body = IndependentBody {
        scope: &b.scope,
        issuer: &b.issuer,
        source_head: &b.source_head,
        root: b.root,
        root_version: b.root_version,
        publisher_key: b.publisher_key,
        publication_sequence: b.publication_sequence,
        previous_publication_digest: b.previous_publication_digest,
    };
    let mut message = PUBLISHER_TAG.to_vec();
    message.extend(serde_json::to_vec(&body).unwrap());
    assert_eq!(message, hex(&row["signing_bytes_hex"]));
    let key = PKey::public_key_from_raw_bytes(&b.publisher_key, Id::ED25519).unwrap();
    assert!(Verifier::new_without_digest(&key)
        .unwrap()
        .verify_oneshot(&b.signature, &message)
        .unwrap());
    b
}
fn verified_source(row: &Value) -> VerifiedSource {
    let s: SignedSource = serde_json::from_value(row["signed_source"].clone()).unwrap();
    let e: EnrolledSource = serde_json::from_value(row["enrolled_source"].clone()).unwrap();
    let previous: SourceHead = serde_json::from_value(row["previous_source_head"].clone()).unwrap();
    s.verify(&e, &previous, row["source_verified_at"].as_i64().unwrap())
        .expect("real source prerequisite")
}
/// Permanent public fail-closed boundary. Neither these JSON records nor the
/// authenticated source signature establish finalized chain/checkpoint provenance.
/// Private envelope crypto is tested separately inside the protocol module.
fn gate_under_test(
    binding: &PublisherBinding,
    source: &VerifiedSource,
    current: &CurrentHead,
    previous_publication: &Value,
    now: i64,
) -> Result<(), Error> {
    let _ = (source, previous_publication);
    let result = binding.require_current(current, now);
    assert_eq!(result, Err(Error::Authentication));
    result
}

#[test]
fn independent_v3_publisher_signature_does_not_authorize_caller_json() {
    let v = vectors();
    let row = &v["cases"][0];
    let binding = genuine_binding(row);
    let source = verified_source(row);
    assert_ne!(
        binding.publisher_key,
        source.observation().issuer.source_key
    );
    assert_eq!(
        binding.root_version, 0,
        "initialized current root version is allowed"
    );
    assert_eq!(binding.source_head.sequence, source.head().sequence);
    assert_eq!(binding.source_head.digest, source.head().digest);
    let current: CurrentHead = serde_json::from_value(row["current_head"].clone()).unwrap();
    assert_eq!(
        gate_under_test(
            &binding,
            &source,
            &current,
            &row["previous_publication_head"],
            150
        ),
        Err(Error::Authentication),
        "genuine signatures cannot authenticate caller-provided current-state JSON"
    );
}

#[test]
fn zero_and_later_root_claims_do_not_authenticate_themselves() {
    let v = vectors();
    for row in v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["expect"] == "accept")
    {
        let b = genuine_binding(row);
        let s = verified_source(row);
        let h: CurrentHead = serde_json::from_value(row["current_head"].clone()).unwrap();
        assert_eq!(
            gate_under_test(
                &b,
                &s,
                &h,
                &row["previous_publication_head"],
                row["now"].as_i64().unwrap()
            ),
            Err(Error::Authentication)
        );
    }
}

#[test]
fn genuinely_signed_wrong_roots_epochs_keys_heads_replay_and_staleness_reject() {
    let v = vectors();
    for row in v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["expect"] == "reject")
    {
        let b = genuine_binding(row);
        let s = verified_source(row);
        let h: CurrentHead = serde_json::from_value(row["current_head"].clone()).unwrap();
        assert!(
            gate_under_test(
                &b,
                &s,
                &h,
                &row["previous_publication_head"],
                row["now"].as_i64().unwrap()
            )
            .is_err(),
            "genuine negative admitted: {}",
            row["name"]
        );
    }
}

#[test]
fn authenticated_inactive_source_is_not_current_authorization() {
    let v = vectors();
    let row = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "inactive_source")
        .unwrap();
    let b = genuine_binding(row);
    let s = verified_source(row);
    assert!(!s.observation().issuer_status_active);
    let h: CurrentHead = serde_json::from_value(row["current_head"].clone()).unwrap();
    assert!(gate_under_test(&b, &s, &h, &row["previous_publication_head"], 150).is_err());
}

#[test]
fn altered_publisher_signature_is_rejected() {
    let v = vectors();
    let row = &v["cases"][0];
    let mut b = genuine_binding(row);
    let s = verified_source(row);
    let h: CurrentHead = serde_json::from_value(row["current_head"].clone()).unwrap();
    b.signature[0] ^= 1;
    assert!(gate_under_test(&b, &s, &h, &row["previous_publication_head"], 150).is_err());
}

#[test]
fn caller_constructed_current_head_never_authenticates_itself() {
    let v = vectors();
    let row = &v["cases"][0];
    let b = genuine_binding(row);
    let h: CurrentHead = serde_json::from_value(row["current_head"].clone()).unwrap();
    assert_eq!(
        b.require_current(&h, 150),
        Err(Error::Authentication),
        "legacy JSON-only route must stay permanently rejecting after safe API is added"
    );
}
