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
}

pub(crate) fn admit_root_only(base: &RootOnlyContext, target: &RootOnlyContext) -> Result<()> {
    required(
        base.package == target.package
            && base.credential == target.credential
            && base.action == target.action
            && base.policy_version == target.policy_version
            && base.allocation_epoch == target.allocation_epoch,
        "cross-context Anchor reuse",
    )?;
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
        root_version: version(spec, "root_version")?,
        policy_version,
        allocation_epoch: version(spec, "allocation_epoch")?,
    })
}
pub(crate) fn packet_cases(packet: &Value) -> Result<&Vec<Value>> {
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
