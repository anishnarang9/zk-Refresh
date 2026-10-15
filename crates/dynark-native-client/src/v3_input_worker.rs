//! Non-authorizing native transport and independent v3 candidate comparison.
//!
//! RED only: constructors, transport and response comparison remain Unsupported.
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
use crate::{ClientError, FieldBytes, OperationControl, V3CredentialSummary};
use std::path::{Path, PathBuf};

pub const V3_INPUT_REQUEST_BYTES: usize = 1918;
pub const V3_INPUT_RESPONSE_BYTES: usize = 24495;
pub const V3_INPUT_SCALARS: usize = 751;

// Independent implementation policy, never learned from a caller's asserted hash.
// The Python installation/stdlib remains trusted; this is not a hermetic runtime.
const PYTHON_PATH: &str = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14";
const PYTHON_SHA256: &str = "4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d";
const SCRIPT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/workers/v3_input_worker.py");
const SCRIPT_SHA256: &str = "b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e";

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
    pub fn from_wire(_: &[u8], _: &V3CredentialSummary) -> Result<Self, ClientError> {
        Err(ClientError::Unsupported)
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
    pub fn new(_: impl AsRef<Path>) -> Result<Self, ClientError> {
        Err(ClientError::Unsupported)
    }

    /// Check cancellation/deadline before I/O; create fresh 0700 child/0600
    /// request.bin, invoke fixed Python/script with ["build", absolute child]
    /// through bounded WorkerRunner, and read only exact regular owner-only
    /// single-link output.bin using nofollow, same-handle before/after metadata
    /// and a RESPONSE_BYTES+1 cap. Never reopen a mutable source for parsing.
    /// Every return path must clean private invocation files and reap the worker.
    /// Compare all reply bytes/fields before returning any private candidate.
    pub fn build(
        &self,
        _: &V3InputWorkerRequest,
        _: &OperationControl,
    ) -> Result<V3InputCandidate, ClientError> {
        Err(ClientError::Unsupported)
    }
}

/// Private structural equality only: exact V3I1/459-byte V3A1 summary, canonical
/// 751 Fr encodings and exact scalars independently reconstructed from request
/// DER/TBS/signatures, expected summary, action, root, issuer/policy, slot/path.
/// In particular, matching six public fields alone cannot accept a candidate.
fn compare_response(_: &[u8], _: &V3InputWorkerRequest) -> Result<V3InputCandidate, ClientError> {
    Err(ClientError::Unsupported)
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
