//! Private context guards. Eligibility remains enforced by the complete relation.
use crate::artifacts::*;
use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootOnlyContext {
    pub package: [u8; 32],
    pub credential: [u8; 32],
    pub action: [u8; 32],
    pub root: [u8; 32],
    pub root_version: u64,
    pub policy_version: u32,
    pub allocation_epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base() -> RootOnlyContext {
        RootOnlyContext {
            package: [1; 32],
            credential: [2; 32],
            action: [3; 32],
            root: [4; 32],
            root_version: 1,
            policy_version: 1,
            allocation_epoch: 1,
        }
    }
    #[test]
    fn cross_credential_action_policy_epoch_and_rollback_are_rejected() {
        let b = base();
        let near = RootOnlyContext {
            root: [5; 32],
            root_version: 2,
            ..b
        };
        admit_root_only(&b, &near).unwrap();
        let mut variants = vec![];
        let mut v = near;
        v.credential[0] ^= 1;
        variants.push(v);
        let mut v = near;
        v.action[0] ^= 1;
        variants.push(v);
        let mut v = near;
        v.package[0] ^= 1;
        variants.push(v);
        let mut v = near;
        v.policy_version += 1;
        variants.push(v);
        let mut v = near;
        v.allocation_epoch += 1;
        variants.push(v);
        let mut v = near;
        v.root_version = 1;
        variants.push(v);
        let mut v = near;
        v.root = b.root;
        variants.push(v);
        for v in variants {
            assert!(admit_root_only(&b, &v).is_err());
        }
    }
    #[test]
    fn unknown_fields_lossy_scalars_and_wrong_shapes_rejected() {
        assert!(flatten_inputs(&serde_json::json!({"root":1})).is_err());
        let mut raw = serde_json::Map::new();
        for name in PUBLIC_FIELDS {
            raw.insert(name.into(), Value::String("1".into()));
        }
        raw.insert("layout".into(), Value::String("0".into()));
        raw.insert("slot".into(), Value::String("1".into()));
        for (name, n) in ARRAYS {
            raw.insert(
                name.into(),
                Value::Array(vec![Value::String("0".into()); n]),
            );
        }
        assert_eq!(
            flatten_inputs(&Value::Object(raw.clone())).unwrap().len(),
            751
        );
        raw.insert("extra".into(), Value::String("0".into()));
        assert!(flatten_inputs(&Value::Object(raw)).is_err());
        assert!(scalar(&Value::String("01".into())).is_err());
    }
    #[test]
    fn field_be_encoding_has_canonical_length_and_order() {
        let b = fr_be(&Fr::from(258u64)).unwrap();
        assert_eq!(&b[30..], &[1, 2]);
        assert!(b[..30].iter().all(|x| *x == 0));
    }

    #[test]
    fn cumulative_request_context_accepts_only_registered_zero_to_target_steps() {
        let base = RootOnlyContext {
            root_version: 0,
            ..base()
        };
        for count in [1, 2, 5, 10] {
            let target = RootOnlyContext {
                root: [count as u8 + 4; 32],
                root_version: count,
                ..base
            };
            admit_cumulative_request(&base, &target, count).unwrap();
            let mut wrong = target;
            wrong.action[0] ^= 1;
            assert!(admit_cumulative_request(&base, &wrong, count).is_err());
            wrong = target;
            wrong.root_version -= 1;
            assert!(admit_cumulative_request(&base, &wrong, count).is_err());
            wrong = target;
            wrong.root = base.root;
            assert!(admit_cumulative_request(&base, &wrong, count).is_err());
        }
        admit_cumulative_request(&base, &base, 0).unwrap();
        let mut wrong = base;
        wrong.root[0] ^= 1;
        assert!(admit_cumulative_request(&base, &wrong, 0).is_err());
        for count in [3, 4, 11] {
            assert!(admit_cumulative_request(&base, &base, count).is_err());
        }
    }

    #[test]
    fn zero_update_control_requires_identical_complete_inputs() {
        let mut base = BTreeMap::new();
        for name in PUBLIC_FIELDS.into_iter().chain(["layout", "slot"]) {
            base.insert(format!("main.{name}"), Fr::from(1u64));
        }
        for (name, count) in ARRAYS {
            for index in 0..count {
                base.insert(format!("main.{name}[{index}]"), Fr::from(1u64));
            }
        }
        assert_eq!(base.len(), 751);
        root_only_inputs_cumulative(&base, &base, 0).unwrap();
        let mut changed = base.clone();
        *changed.get_mut("main.actionHash").unwrap() = Fr::from(2u64);
        assert!(root_only_inputs_cumulative(&base, &changed, 0).is_err());
        let mut changed = base.clone();
        *changed.get_mut("main.siblings[4]").unwrap() = Fr::from(2u64);
        assert!(root_only_inputs_cumulative(&base, &changed, 0).is_err());
        assert!(root_only_inputs_cumulative(&base, &base, 1).is_err());
    }
}

fn admit_same_context(base: &RootOnlyContext, target: &RootOnlyContext) -> Result<()> {
    required(
        base.package == target.package
            && base.credential == target.credential
            && base.action == target.action
            && base.policy_version == target.policy_version
            && base.allocation_epoch == target.allocation_epoch,
        "cross-context Anchor reuse",
    )
}
pub(crate) fn admit_root_only(base: &RootOnlyContext, target: &RootOnlyContext) -> Result<()> {
    admit_same_context(base, target)?;
    required(
        base.root != target.root
            && base.root_version > 0
            && target.root_version > base.root_version,
        "root refresh monotonicity",
    )
}
const ARRAYS: [(&str, usize); 6] = [
    ("tbs", 672),
    ("issuerModulus", 17),
    ("issuerSignature", 17),
    ("holderSignature", 17),
    ("siblings", 10),
    ("pathIndices", 10),
];
pub(crate) fn scalar(value: &Value) -> Result<Fr> {
    let s = value.as_str().ok_or("canonical scalar string")?;
    required(
        !s.is_empty()
            && s.len() <= 77
            && s.bytes().all(|x| x.is_ascii_digit())
            && (s == "0" || !s.starts_with('0')),
        "canonical scalar decimal",
    )?;
    let field = Fr::from_str(s).map_err(|_| "scalar field bound")?;
    required(field.to_string() == s, "scalar field alias")?;
    Ok(field)
}
pub(crate) fn flatten_inputs(value: &Value) -> Result<BTreeMap<String, Fr>> {
    let obj = value.as_object().ok_or("input object")?;
    required(obj.len() == 14, "exact input field set")?;
    let mut out = BTreeMap::new();
    for name in PUBLIC_FIELDS.into_iter().chain(["layout", "slot"]) {
        out.insert(
            format!("main.{name}"),
            scalar(obj.get(name).ok_or("required scalar")?)?,
        );
    }
    for (name, length) in ARRAYS {
        let values = obj
            .get(name)
            .and_then(Value::as_array)
            .ok_or("required array")?;
        required(values.len() == length, "exact input array shape")?;
        for (i, v) in values.iter().enumerate() {
            out.insert(format!("main.{name}[{i}]"), scalar(v)?);
        }
    }
    required(out.len() == 751, "declared input count")?;
    Ok(out)
}
pub(crate) fn mapping(value: &Value) -> Result<BTreeMap<String, usize>> {
    required(
        text(value, "schema")? == "credential-v3-bounded-input-wire-map-v1"
            && text(value, "symbols_sha256")? == SYMBOLS_SHA
            && value["assignment_fields"].as_u64() == Some(ASSIGNMENT_FIELDS as u64),
        "compiled input map context",
    )?;
    let coords = value["coordinates"]
        .as_object()
        .ok_or("input map coordinates")?;
    required(coords.len() == 751, "complete input coordinate map")?;
    let mut out = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for (name, index) in coords {
        let index = index.as_u64().ok_or("input coordinate integer")? as usize;
        required(
            index > 0 && index < ASSIGNMENT_FIELDS && seen.insert(index),
            "input coordinate bounds/alias",
        )?;
        out.insert(name.clone(), index);
    }
    for (i, name) in PUBLIC_FIELDS.iter().enumerate() {
        required(
            out.get(&format!("main.{name}")) == Some(&(i + 1)),
            "six public coordinate order",
        )?;
    }
    Ok(out)
}
pub(crate) fn match_inputs(
    values: &[Fr],
    inputs: &Value,
    map: &BTreeMap<String, usize>,
) -> Result<BTreeMap<String, Fr>> {
    let flat = flatten_inputs(inputs)?;
    required(flat.len() == map.len(), "input map completeness")?;
    for (name, value) in &flat {
        let index = *map.get(name).ok_or("required input symbol")?;
        required(
            values.get(index) == Some(value),
            "input-to-complete-witness binding",
        )?;
    }
    Ok(flat)
}
pub(crate) fn root_only_inputs(
    base: &BTreeMap<String, Fr>,
    near: &BTreeMap<String, Fr>,
) -> Result<()> {
    required(
        base.len() == 751 && near.len() == 751,
        "root-only complete input maps",
    )?;
    let mut siblings = 0;
    for (key, value) in base {
        let target = near.get(key).ok_or("target input key")?;
        if key == "main.root" {
            required(value != target, "new root value")?;
        } else if key.starts_with("main.siblings[") {
            siblings += usize::from(value != target);
        } else {
            required(
                value == target,
                "root-only retry changed credential/action/slot/input",
            )?;
        }
    }
    required(siblings == 1, "qualified single-sibling retry")
}
pub(crate) fn root_only_inputs_cumulative(
    base: &BTreeMap<String, Fr>,
    target: &BTreeMap<String, Fr>,
    count: u64,
) -> Result<()> {
    if count == 0 {
        required(
            base.len() == 751 && base == target,
            "zero-update control requires identical complete inputs",
        )
    } else {
        root_only_inputs(base, target)
    }
}
pub(crate) fn fr_be(value: &Fr) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    value.serialize_compressed(&mut out[..])?;
    out.reverse();
    Ok(out)
}
fn version(value: &Value, key: &str) -> Result<u64> {
    let n = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or("context version")?;
    required(n > 0, "positive context version")?;
    Ok(n)
}
pub(crate) fn derive_context(flat: &BTreeMap<String, Fr>, spec: &Value) -> Result<RootOnlyContext> {
    derive_context_mode(flat, spec, false)
}
pub(crate) fn derive_context_mode(
    flat: &BTreeMap<String, Fr>,
    spec: &Value,
    request_bound: bool,
) -> Result<RootOnlyContext> {
    let get = |name: &str| flat.get(&format!("main.{name}")).ok_or("context input");
    let issuer = fr_be(get("issuerHash")?)?;
    let policy = fr_be(get("policyHash")?)?;
    let action = fr_be(get("actionHash")?)?;
    let issuer_version = u32::try_from(version(spec, "issuer_version")?)?;
    let policy_version = u32::try_from(version(spec, "policy_version")?)?;
    let mut tbs = Vec::with_capacity(672);
    for i in 0..672 {
        tbs.push(
            get(&format!("tbs[{i}]"))?
                .to_string()
                .parse::<u8>()
                .map_err(|_| "signed TBS byte")?,
        );
    }
    let mut e = Sha256::new();
    e.update(b"dynark-v3-proof/synthetic-enrollment/v1");
    e.update(issuer);
    let enrollment: [u8; 32] = e.finalize().into();
    let package = unhex(PACKAGE_SHA)?;
    let mut c = Sha256::new();
    c.update(b"dynark-v3-proof/credential/v1");
    c.update(package);
    c.update(unhex(PROFILE_SHA)?);
    c.update(unhex(SEMANTIC_SCHEMA)?);
    c.update(enrollment);
    c.update(issuer_version.to_be_bytes());
    c.update(Sha256::digest(tbs));
    c.update(issuer);
    c.update(policy);
    let credential = c.finalize().into();
    let mut a = Sha256::new();
    a.update(b"dynark-v3-proof/action/v1");
    a.update(package);
    a.update(policy);
    a.update(policy_version.to_be_bytes());
    a.update(action);
    Ok(RootOnlyContext {
        package,
        credential,
        action: a.finalize().into(),
        root: fr_be(get("root")?)?,
        root_version: if request_bound {
            spec["root_version"]
                .as_u64()
                .filter(|n| *n <= 10)
                .ok_or("bounded request generation 0 to 10")?
        } else {
            version(spec, "root_version")?
        },
        policy_version,
        allocation_epoch: version(spec, "allocation_epoch")?,
    })
}
/// Caller pins bind mathematical inputs to a retained application observation.
/// This runner does not authenticate a chain, a finalized request, or its state.
pub(crate) fn admit_pair(
    base: &RootOnlyContext,
    near: &RootOnlyContext,
    request_bound: bool,
) -> Result<()> {
    if request_bound {
        required(
            base.root_version == 0 && near.root_version == 1,
            "request generation 0 to 1",
        )?;
        admit_same_context(base, near)?;
        required(base.root != near.root, "request root change")
    } else {
        admit_root_only(base, near)
    }
}

/// The registered campaign compares one immutable R0 action with one current
/// target after a fixed number of distinct, unrelated signed revocations.
/// k=0 is the no-refresh Full control. This mathematical guard is not source,
/// allocation, finality, request or current-chain authentication.
pub(crate) fn admit_cumulative_request(
    base: &RootOnlyContext,
    target: &RootOnlyContext,
    count: u64,
) -> Result<()> {
    required(
        matches!(count, 0 | 1 | 2 | 5 | 10),
        "registered update count",
    )?;
    admit_same_context(base, target)?;
    required(
        base.root_version == 0
            && target.root_version == count
            && (base.root != target.root) == (count > 0),
        "registered R0 to current target",
    )
}
fn exact_fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("exact schema object")?;
    required(
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)),
        "exact request packet fields",
    )
}
fn base58_32(value: &str) -> Result<()> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    required((32..=44).contains(&value.len()), "32-byte base58 length")?;
    let mut bytes = Vec::<u8>::new();
    for character in value.bytes() {
        let mut carry = ALPHABET
            .iter()
            .position(|c| *c == character)
            .ok_or("base58 character")? as u32;
        for byte in &mut bytes {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry != 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    required(
        bytes.len() + value.bytes().take_while(|c| *c == b'1').count() == 32,
        "canonical 32-byte base58",
    )
}
fn request_bound_cases(packet: &Value, campaign: bool) -> Result<&Vec<Value>> {
    let mut fields = vec![
        "schema",
        "synthetic_only",
        "application_verified",
        "package_digest",
        "cohort",
        "proof_source_identity",
        "setup_manifest_path",
        "setup_manifest_sha256",
        "package_check_path",
        "package_check_sha256",
        "r1cs_path",
        "wasm_path",
        "profile_path",
        "input_map_path",
        "input_map_sha256",
        "application_stage",
        "pairs",
    ];
    if campaign {
        fields.extend([
            "update_count",
            "freeze_receipt_sha256",
            "history_receipt_sha256",
            "root_schedule_sha256",
        ]);
    }
    exact_fields(packet, &fields)?;
    let count = if campaign {
        let count = packet["update_count"]
            .as_u64()
            .ok_or("campaign update count")?;
        required(
            matches!(count, 0 | 1 | 2 | 5 | 10),
            "registered update count",
        )?;
        for name in [
            "freeze_receipt_sha256",
            "history_receipt_sha256",
            "root_schedule_sha256",
        ] {
            unhex(text(packet, name)?)?;
        }
        count
    } else {
        1
    };
    required(
        packet["synthetic_only"] == false
            && packet["application_verified"] == false
            && text(packet, "cohort")?
                == if campaign {
                    "cumulative-training-v1"
                } else {
                    "request-bound-training-v1"
                }
            && text(packet, "package_digest")? == PACKAGE_SHA
            && text(packet, "setup_manifest_sha256")? == SETUP_MANIFEST_SHA
            && text(packet, "package_check_sha256")? == PACKAGE_CHECK_SHA
            && text(packet, "proof_source_identity")? == crate::proof_source_identity(),
        "request-only training identities",
    )?;
    unhex(text(packet, "input_map_sha256")?)?;
    for key in [
        "setup_manifest_path",
        "package_check_path",
        "r1cs_path",
        "wasm_path",
        "profile_path",
        "input_map_path",
    ] {
        required(!text(packet, key)?.is_empty(), "request artifact path")?;
    }
    let stage = &packet["application_stage"];
    exact_fields(
        stage,
        &[
            "program_id",
            "genesis_hash",
            "loaded_elf_sha256",
            "base_stage_report_sha256",
            "base_config_sha256",
            "finalized_request_sha256",
            "request_address",
            "base_finalized_slot",
            "near_state_report_sha256",
            "near_config_sha256",
            "near_finalized_slot",
            "base_root",
            "near_root",
            "action_hash",
        ],
    )?;
    for key in ["program_id", "genesis_hash", "request_address"] {
        base58_32(text(stage, key)?)?;
    }
    for key in [
        "loaded_elf_sha256",
        "base_stage_report_sha256",
        "base_config_sha256",
        "finalized_request_sha256",
        "near_state_report_sha256",
        "near_config_sha256",
    ] {
        unhex(text(stage, key)?)?;
    }
    let base_slot = stage["base_finalized_slot"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("base finalized slot")?;
    required(
        stage["near_finalized_slot"].as_u64().is_some_and(|n| {
            if count == 0 {
                n == base_slot
            } else {
                n > base_slot
            }
        }),
        "target finalized slot sequence",
    )?;
    if count > 0 {
        required(
            scalar(&stage["base_root"])? != scalar(&stage["near_root"])?,
            "distinct stage roots",
        )?;
    } else {
        required(
            stage["base_root"] == stage["near_root"]
                && stage["base_config_sha256"] == stage["near_config_sha256"],
            "zero-update unchanged root and config",
        )?;
    }
    scalar(&stage["action_hash"])?;
    let pairs = packet["pairs"].as_array().ok_or("request pair array")?;
    required(
        pairs.len()
            == if campaign {
                usize::try_from(count.max(1))?
            } else {
                1
            },
        "exact registered request checkpoint count",
    )?;
    for (index, pair) in pairs.iter().enumerate() {
        exact_fields(pair, &["name", "base", "near"])?;
        let generation = if campaign && count > 0 {
            index as u64 + 1
        } else {
            count
        };
        let expected_name = if campaign {
            format!("request_bound_training_r{generation}")
        } else {
            "request_bound_training".to_owned()
        };
        required(
            text(pair, "name")? == expected_name,
            "registered request checkpoint name",
        )?;
        if index > 0 {
            required(pair["base"] == pairs[0]["base"], "immutable R0 case")?;
        }
        for (role, generation) in [("base", 0), ("near", generation)] {
            let spec = &pair[role];
            exact_fields(
                spec,
                &[
                    "wtns_path",
                    "wtns_sha256",
                    "public_path",
                    "public_sha256",
                    "input_path",
                    "input_sha256",
                    "issuer_version",
                    "policy_version",
                    "allocation_epoch",
                    "root_version",
                ],
            )?;
            required(
                spec["root_version"].as_u64() == Some(generation),
                "registered request generation",
            )?;
            for key in ["wtns_sha256", "public_sha256", "input_sha256"] {
                unhex(text(spec, key)?)?;
            }
            for key in ["wtns_path", "public_path", "input_path"] {
                required(!text(spec, key)?.is_empty(), "request case path")?;
            }
            u32::try_from(version(spec, "issuer_version")?)?;
            u32::try_from(version(spec, "policy_version")?)?;
            version(spec, "allocation_epoch")?;
        }
    }
    Ok(pairs)
}
pub(crate) fn match_request_stage(
    packet: &Value,
    base: &BTreeMap<String, Fr>,
    near: &BTreeMap<String, Fr>,
) -> Result<()> {
    let stage = &packet["application_stage"];
    required(
        base.get("main.root") == Some(&scalar(&stage["base_root"])?)
            && near.get("main.root") == Some(&scalar(&stage["near_root"])?)
            && base.get("main.actionHash") == Some(&scalar(&stage["action_hash"])?)
            && near.get("main.actionHash") == base.get("main.actionHash"),
        "caller stage roots/action match complete witnesses",
    )
}
pub(crate) fn packet_cases(packet: &Value) -> Result<&Vec<Value>> {
    if packet["schema"] == "credential-v3-request-bound-anchor-v1" {
        return request_bound_cases(packet, false);
    }
    if packet["schema"] == "credential-v3-cumulative-request-v1" {
        return request_bound_cases(packet, true);
    }
    required(
        text(packet, "schema")? == "credential-v3-bounded-proof-contexts-v1"
            && packet["synthetic_only"] == true
            && text(packet, "package_digest")? == PACKAGE_SHA,
        "proof packet context",
    )?;
    let cases = packet["pairs"].as_array().ok_or("proof pairs")?;
    required(
        !cases.is_empty() && cases.len() <= 16,
        "bounded proof cohort",
    )?;
    let mut names = BTreeSet::new();
    for case in cases {
        let name = text(case, "name")?;
        required(
            !name.is_empty()
                && name.len() <= 40
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && names.insert(name.to_owned()),
            "unique safe pair name",
        )?;
    }
    match text(packet, "cohort")? {
        "training-v1" => required(
            names == (0..9).map(|i| format!("credential_{i}")).collect(),
            "exact nine training pairs",
        )?,
        "heldout-v1" => {
            required(
                packet["freeze_receipt_path"].is_string()
                    && packet["freeze_receipt_sha256"].is_string(),
                "heldout freeze authority",
            )?;
            required(
                names == (0..cases.len()).map(|i| format!("holdout_{i}")).collect(),
                "heldout pair names",
            )?;
        }
        _ => return Err("unknown cohort".into()),
    }
    Ok(cases)
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use serde_json::json;
    fn inputs() -> Value {
        let mut raw = serde_json::Map::new();
        for key in PUBLIC_FIELDS {
            raw.insert(key.into(), json!("1"));
        }
        raw.insert("layout".into(), json!("0"));
        raw.insert("slot".into(), json!("1"));
        for (key, n) in ARRAYS {
            raw.insert(key.into(), Value::Array(vec![json!("0"); n]));
        }
        Value::Object(raw)
    }
    fn meta() -> Value {
        json!({"issuer_version":1,"policy_version":1,"allocation_epoch":1,"root_version":1})
    }
    #[test]
    fn identities_are_derived_from_actual_tbs_issuer_policy_and_action() {
        let raw = inputs();
        let base = derive_context(&flatten_inputs(&raw).unwrap(), &meta()).unwrap();
        let mut changed = raw.clone();
        changed["tbs"][20] = json!("1");
        assert_ne!(
            derive_context(&flatten_inputs(&changed).unwrap(), &meta())
                .unwrap()
                .credential,
            base.credential
        );
        let mut changed = raw.clone();
        changed["issuerHash"] = json!("2");
        assert_ne!(
            derive_context(&flatten_inputs(&changed).unwrap(), &meta())
                .unwrap()
                .credential,
            base.credential
        );
        let mut changed = raw.clone();
        changed["policyHash"] = json!("2");
        let policy = derive_context(&flatten_inputs(&changed).unwrap(), &meta()).unwrap();
        assert_ne!(policy.credential, base.credential);
        assert_ne!(policy.action, base.action);
        let mut changed = raw;
        changed["actionHash"] = json!("2");
        let action = derive_context(&flatten_inputs(&changed).unwrap(), &meta()).unwrap();
        assert_eq!(action.credential, base.credential);
        assert_ne!(action.action, base.action);
    }
    #[test]
    fn all_input_coordinates_match_and_relabeling_cannot_replace_them() {
        let raw = inputs();
        let flat = flatten_inputs(&raw).unwrap();
        let map = flat
            .keys()
            .enumerate()
            .map(|(i, k)| (k.clone(), i + 1))
            .collect::<BTreeMap<_, _>>();
        let mut values = vec![Fr::from(0u64); 752];
        for (k, i) in &map {
            values[*i] = flat[k];
        }
        assert!(match_inputs(&values, &raw, &map).is_ok());
        let mut changed = raw.clone();
        changed["holderSignature"][0] = json!("7");
        assert!(match_inputs(&values, &changed, &map).is_err());
        let mut changed = raw;
        changed["tbs"][100] = json!("9");
        assert!(match_inputs(&values, &changed, &map).is_err());
    }
    #[test]
    fn root_only_rejects_holder_signature_slot_and_multiple_sibling_changes() {
        let raw = inputs();
        let base = flatten_inputs(&raw).unwrap();
        let mut near = raw.clone();
        near["root"] = json!("2");
        near["siblings"][0] = json!("1");
        root_only_inputs(&base, &flatten_inputs(&near).unwrap()).unwrap();
        for field in ["slot", "actionHash"] {
            let mut wrong = near.clone();
            wrong[field] = json!("8");
            assert!(root_only_inputs(&base, &flatten_inputs(&wrong).unwrap()).is_err());
        }
        let mut wrong = near.clone();
        wrong["holderSignature"][0] = json!("8");
        assert!(root_only_inputs(&base, &flatten_inputs(&wrong).unwrap()).is_err());
        near["siblings"][1] = json!("1");
        assert!(root_only_inputs(&base, &flatten_inputs(&near).unwrap()).is_err());
    }
    fn request_packet() -> Value {
        let mut packet = json!({
            "schema":"credential-v3-request-bound-anchor-v1", "synthetic_only":false,
            "application_verified":false, "package_digest":PACKAGE_SHA,
            "cohort":"request-bound-training-v1", "proof_source_identity":crate::proof_source_identity(),
            "setup_manifest_sha256":SETUP_MANIFEST_SHA,
            "input_map_sha256":"11".repeat(32),
            "application_stage":{
                "program_id":"11111111111111111111111111111111",
                "genesis_hash":"11111111111111111111111111111111",
                "request_address":"11111111111111111111111111111111",
                "loaded_elf_sha256":"11".repeat(32),
                "base_stage_report_sha256":"22".repeat(32),
                "base_config_sha256":"33".repeat(32),
                "finalized_request_sha256":"44".repeat(32),
                "near_state_report_sha256":"55".repeat(32),
                "near_config_sha256":"66".repeat(32),
                "base_finalized_slot":10,"near_finalized_slot":11,
                "base_root":"1","near_root":"2","action_hash":"1"
            },
            "pairs":[{"name":"request_bound_training",
                "base":{"issuer_version":1,"policy_version":1,"allocation_epoch":1,"root_version":0},
                "near":{"issuer_version":1,"policy_version":1,"allocation_epoch":1,"root_version":1}}]
        });
        packet["package_check_sha256"] = json!(PACKAGE_CHECK_SHA);
        for key in [
            "setup_manifest_path",
            "package_check_path",
            "r1cs_path",
            "wasm_path",
            "profile_path",
            "input_map_path",
        ] {
            packet[key] = json!("private-or-pinned");
        }
        for role in ["base", "near"] {
            for key in ["input_path", "wtns_path", "public_path"] {
                packet["pairs"][0][role][key] = json!("private");
            }
            for key in ["input_sha256", "wtns_sha256", "public_sha256"] {
                packet["pairs"][0][role][key] = json!("77".repeat(32));
            }
        }
        packet
    }
    #[test]
    fn registered_cumulative_packet_requires_exact_count_roots_and_history_pins() {
        let mut packet = request_packet();
        packet["schema"] = json!("credential-v3-cumulative-request-v1");
        packet["cohort"] = json!("cumulative-training-v1");
        packet["update_count"] = json!(2);
        packet["freeze_receipt_sha256"] = json!("77".repeat(32));
        packet["history_receipt_sha256"] = json!("88".repeat(32));
        packet["root_schedule_sha256"] = json!("99".repeat(32));
        packet["pairs"][0]["name"] = json!("request_bound_training_r1");
        let mut second = packet["pairs"][0].clone();
        second["name"] = json!("request_bound_training_r2");
        second["near"]["root_version"] = json!(2);
        packet["pairs"].as_array_mut().unwrap().push(second);
        packet_cases(&packet).unwrap();
        packet["pairs"][1]["near"]["root_version"] = json!(1);
        assert!(packet_cases(&packet).is_err());
        packet["pairs"][1]["near"]["root_version"] = json!(2);
        packet["pairs"][1]["base"]["root_version"] = json!(1);
        assert!(packet_cases(&packet).is_err());
        packet["pairs"][1]["base"]["root_version"] = json!(0);
        packet["history_receipt_sha256"] = json!("bad");
        assert!(packet_cases(&packet).is_err());
        packet["history_receipt_sha256"] = json!("88".repeat(32));
        packet["update_count"] = json!(3);
        assert!(packet_cases(&packet).is_err());

        packet["update_count"] = json!(0);
        packet["pairs"].as_array_mut().unwrap().truncate(1);
        packet["pairs"][0]["name"] = json!("request_bound_training_r0");
        packet["pairs"][0]["near"]["root_version"] = json!(0);
        packet["application_stage"]["near_root"] = packet["application_stage"]["base_root"].clone();
        packet["application_stage"]["near_finalized_slot"] =
            packet["application_stage"]["base_finalized_slot"].clone();
        packet["application_stage"]["near_config_sha256"] =
            packet["application_stage"]["base_config_sha256"].clone();
        packet_cases(&packet).unwrap();
        packet["application_stage"]["near_config_sha256"] = json!("66".repeat(32));
        assert!(packet_cases(&packet).is_err());
    }
    #[test]
    fn separate_request_packet_admits_exactly_one_zero_to_one_training_pair() {
        let packet = request_packet();
        assert_eq!(packet_cases(&packet).unwrap().len(), 1);
        for mutation in [
            "extra_pair",
            "generation",
            "schema",
            "cohort",
            "source",
            "stage",
            "slot",
            "root",
            "digest",
            "address",
        ] {
            let mut wrong = packet.clone();
            match mutation {
                "extra_pair" => wrong["pairs"]
                    .as_array_mut()
                    .unwrap()
                    .push(packet["pairs"][0].clone()),
                "generation" => wrong["pairs"][0]["base"]["root_version"] = json!(1),
                "schema" => wrong["schema"] = json!("credential-v3-bounded-proof-contexts-v1"),
                "cohort" => wrong["cohort"] = json!("heldout-v1"),
                "source" => wrong["proof_source_identity"] = json!("00".repeat(32)),
                "stage" => {
                    wrong["application_stage"]
                        .as_object_mut()
                        .unwrap()
                        .remove("finalized_request_sha256");
                }
                "slot" => wrong["application_stage"]["near_finalized_slot"] = json!(10),
                "root" => wrong["application_stage"]["near_root"] = json!("1"),
                "digest" => wrong["application_stage"]["loaded_elf_sha256"] = json!("ABC"),
                _ => wrong["application_stage"]["request_address"] = json!("0".repeat(32)),
            }
            assert!(packet_cases(&wrong).is_err(), "{mutation}");
        }
    }
    #[test]
    fn request_zero_generation_is_separate_and_stage_action_and_roots_match() {
        let packet = request_packet();
        let base_flat = flatten_inputs(&inputs()).unwrap();
        let mut raw = inputs();
        raw["root"] = json!("2");
        raw["siblings"][0] = json!("1");
        let near_flat = flatten_inputs(&raw).unwrap();
        let base_spec = &packet["pairs"][0]["base"];
        let near_spec = &packet["pairs"][0]["near"];
        assert!(derive_context(&base_flat, base_spec).is_err());
        let base = derive_context_mode(&base_flat, base_spec, true).unwrap();
        let near = derive_context_mode(&near_flat, near_spec, true).unwrap();
        assert!(admit_root_only(&base, &near).is_err());
        admit_pair(&base, &near, true).unwrap();
        root_only_inputs(&base_flat, &near_flat).unwrap();
        match_request_stage(&packet, &base_flat, &near_flat).unwrap();
        for key in ["base_root", "near_root", "action_hash"] {
            let mut wrong = packet.clone();
            wrong["application_stage"][key] = json!("9");
            assert!(match_request_stage(&wrong, &base_flat, &near_flat).is_err());
        }
        for field in ["actionHash", "slot", "issuerHash", "policyHash"] {
            let mut wrong = raw.clone();
            wrong[field] = json!("9");
            assert!(root_only_inputs(&base_flat, &flatten_inputs(&wrong).unwrap()).is_err());
        }
        let mut wrong = near;
        wrong.root_version = 2;
        assert!(admit_pair(&base, &wrong, true).is_err());
        wrong = near;
        wrong.action[0] ^= 1;
        assert!(admit_pair(&base, &wrong, true).is_err());
    }
    #[test]
    fn request_schema_rejects_unknown_keys_and_noncanonical_pins() {
        for scope in ["packet", "stage", "pair", "case"] {
            let mut packet = request_packet();
            let target = match scope {
                "packet" => &mut packet,
                "stage" => &mut packet["application_stage"],
                "pair" => &mut packet["pairs"][0],
                _ => &mut packet["pairs"][0]["base"],
            };
            target["extra"] = json!(true);
            assert!(packet_cases(&packet).is_err(), "{scope}");
        }
        for key in ["base_root", "near_root", "action_hash"] {
            let mut packet = request_packet();
            packet["application_stage"][key] = json!("01");
            assert!(packet_cases(&packet).is_err());
        }
        for bad in ["1".repeat(31), "1".repeat(33), "z".repeat(44)] {
            assert!(base58_32(&bad).is_err());
        }
        base58_32("3nqhgGtpPD8UyYMYtYFb4nBLntsW36gDUnzPXh5j9JNi").unwrap();
    }
    #[test]
    fn cohort_count_is_exact_for_training_and_bounded_for_holdout() {
        let pairs = (0..9)
            .map(|i| json!({"name":format!("credential_{i}")}))
            .collect::<Vec<_>>();
        let training = json!({"schema":"credential-v3-bounded-proof-contexts-v1","synthetic_only":true,"package_digest":PACKAGE_SHA,"cohort":"training-v1","pairs":pairs});
        assert_eq!(packet_cases(&training).unwrap().len(), 9);
        let mut wrong = training.clone();
        wrong["pairs"].as_array_mut().unwrap().pop();
        assert!(packet_cases(&wrong).is_err());
        let heldout = json!({"schema":"credential-v3-bounded-proof-contexts-v1","synthetic_only":true,"package_digest":PACKAGE_SHA,"cohort":"heldout-v1","freeze_receipt_path":"protected","freeze_receipt_sha256":"trusted","pairs":[{"name":"holdout_0"}]});
        assert_eq!(packet_cases(&heldout).unwrap().len(), 1);
    }
}
