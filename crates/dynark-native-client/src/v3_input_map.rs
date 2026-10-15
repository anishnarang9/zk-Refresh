//! Exact compiler input map only. A map authenticates no credential, state,
//! complete witness relation, signer or application authorization.
use crate::{ClientError, Digest, OperationControl};
use std::{collections::BTreeMap, path::PathBuf};

pub const V3_INPUT_KEYS: [&str; 14] = [
    "root",
    "issuerHash",
    "notBefore",
    "notAfter",
    "actionHash",
    "policyHash",
    "layout",
    "slot",
    "tbs",
    "issuerModulus",
    "issuerSignature",
    "holderSignature",
    "siblings",
    "pathIndices",
];

/// Caller data only. The digest must match the independently frozen compiler pin.
#[derive(Clone)]
pub struct V3CompilerSymbols {
    pub path: PathBuf,
    pub asserted_sha256: Digest,
}

/// Private constructor: callers cannot select certificate offsets or relabel
/// arbitrary coordinates as the accepted compiler's input map.
pub struct V3CompilerInputMap {
    coordinates: BTreeMap<String, usize>,
}
impl V3CompilerInputMap {
    pub fn load(_: &V3CompilerSymbols, _: &OperationControl) -> Result<Self, ClientError> {
        Err(ClientError::Unsupported)
    }
}

/// Pure structural parser. Product map admission must independently authenticate
/// exact source bytes before invoking it; parser success supplies no authority.
fn parse_declared_symbols(_: &str) -> Result<V3CompilerInputMap, ClientError> {
    Err(ClientError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dynark_native_client::decode_digest;
    use std::{
        collections::BTreeSet,
        time::{Duration, Instant},
    };

    fn required() -> Vec<String> {
        let mut names = [
            "root",
            "issuerHash",
            "notBefore",
            "notAfter",
            "actionHash",
            "policyHash",
            "layout",
            "slot",
        ]
        .map(|name| format!("main.{name}"))
        .to_vec();
        for (name, count) in [
            ("tbs", 672),
            ("issuerModulus", 17),
            ("issuerSignature", 17),
            ("holderSignature", 17),
            ("siblings", 10),
            ("pathIndices", 10),
        ] {
            names.extend((0..count).map(|i| format!("main.{name}[{i}]")));
        }
        names
    }
    fn source() -> V3CompilerSymbols {
        V3CompilerSymbols {
            path: PathBuf::from("/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential.sym"),
            asserted_sha256: decode_digest("d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0").unwrap(),
        }
    }
    fn check_map(map: &V3CompilerInputMap) {
        let names = required();
        assert_eq!(V3_INPUT_KEYS.len(), 14);
        assert_eq!(names.len(), 751);
        assert_eq!(
            map.coordinates.keys().cloned().collect::<BTreeSet<_>>(),
            names.into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            map.coordinates
                .values()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            751
        );
        assert!(map.coordinates.values().all(|i| *i > 0 && *i < 784_796));
        for (index, name) in [
            "root",
            "issuerHash",
            "notBefore",
            "notAfter",
            "actionHash",
            "policyHash",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                map.coordinates.get(&format!("main.{name}")),
                Some(&(index + 1))
            );
        }
    }
    #[test]
    #[ignore = "ROOT-owned bounded exact compiler-symbol map admission grant required"]
    fn pinned_v3_compiler_map_covers_exactly_751_unique_inputs() {
        assert_eq!(
            std::env::var("M2_V3_INPUT_MAP_SCOPE").as_deref(),
            Ok("native-v3-compiler-map"),
            "exact ROOT execution scope"
        );
        let control = OperationControl::new(Instant::now() + Duration::from_secs(150));
        let map = V3CompilerInputMap::load(&source(), &control)
            .expect("pinned v3 compiler map admission is implemented");
        check_map(&map);
    }
    #[test]
    fn parser_requires_complete_unique_noneliminated_input_and_public_coordinates() {
        // Public synthetic symbol rows exercise parsing only. These rows cannot
        // pass the fixed hash gate or manufacture admitted credential/state.
        let rows: Vec<String> = required()
            .iter()
            .enumerate()
            .map(|(i, name)| format!("{},{},0,{name}", i + 1, i + 1))
            .collect();
        let valid = rows.join("\n") + "\n";
        check_map(&parse_declared_symbols(&valid).expect("complete symbol parsing is implemented"));
        for mutation in 0..7 {
            let mut changed = rows.clone();
            match mutation {
                0 => {
                    changed.pop();
                }
                1 => changed.push(rows[0].clone()),
                2 => changed[750] = format!("751,1,0,{}", required()[750]),
                3 => changed[750] = format!("751,-1,0,{}", required()[750]),
                4 => changed[750] = format!("751,784796,0,{}", required()[750]),
                5 => {
                    changed[0] = "1,2,0,main.root".into();
                    changed[1] = "2,1,0,main.issuerHash".into();
                }
                _ => changed[750] = "malformed-symbol-row".into(),
            }
            assert!(parse_declared_symbols(&(changed.join("\n") + "\n")).is_err());
        }
    }
    #[test]
    fn caller_symbol_hash_cannot_replace_fixed_compiler_pin() {
        let mut source = source();
        source.asserted_sha256 = [0; 32];
        let control = OperationControl::new(Instant::now() + Duration::from_secs(2));
        assert!(matches!(
            V3CompilerInputMap::load(&source, &control),
            Err(ClientError::Identity)
        ));
    }
}
