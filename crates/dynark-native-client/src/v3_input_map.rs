//! Exact compiler input map only. A map authenticates no credential, state,
//! complete witness relation, signer or application authorization.
use crate::{ClientError, Digest, OperationControl};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

const SYMBOL_BYTES_CAP: u64 = 256 * 1024 * 1024;
const ASSIGNMENT_FIELDS: usize = 784_796;

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
    /// Read-only lookup in the independently pinned map; no coordinate relabeling.
    pub(crate) fn coordinate(&self, name: &str) -> Option<usize> {
        self.coordinates.get(name).copied()
    }

    pub fn load(
        symbols: &V3CompilerSymbols,
        control: &OperationControl,
    ) -> Result<Self, ClientError> {
        control.check()?;
        const EXPECTED: Digest = [
            0xd2, 0xd6, 0x6e, 0x23, 0x8b, 0xdc, 0x0a, 0x73, 0x1c, 0x86, 0xc1, 0x89, 0x7c, 0x29,
            0x78, 0xd2, 0x39, 0x08, 0xdc, 0xc1, 0x94, 0x60, 0x58, 0x2c, 0xc8, 0x73, 0xdc, 0x2d,
            0x41, 0xe5, 0xdb, 0xf0,
        ];
        let expected = EXPECTED;
        let path = &symbols.path;
        if symbols.asserted_sha256 != expected
            || !path.is_absolute()
            || fs::canonicalize(path).map_err(|_| ClientError::Identity)? != *path
        {
            return Err(ClientError::Identity);
        }
        let before = fs::symlink_metadata(path).map_err(|_| ClientError::Io)?;
        if !before.is_file() || !matches!(before.permissions().mode() & 0o777, 0o600 | 0o644) {
            return Err(ClientError::Identity);
        }
        if before.len() == 0 || before.len() > SYMBOL_BYTES_CAP {
            return Err(ClientError::Bound);
        }
        let mut file = File::open(path).map_err(|_| ClientError::Io)?;
        let identity = |meta: &fs::Metadata| {
            (
                meta.dev(),
                meta.ino(),
                meta.len(),
                meta.uid(),
                meta.mode(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
            )
        };
        if identity(&file.metadata().map_err(|_| ClientError::Io)?) != identity(&before) {
            return Err(ClientError::Identity);
        }
        // Parse this authenticated snapshot only; never reopen the pathname.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(before.len() as usize)
            .map_err(|_| ClientError::Bound)?;
        let mut hash = Sha256::new();
        let mut buffer = [0; 65_536];
        loop {
            control.check()?;
            let count = file.read(&mut buffer).map_err(|_| ClientError::Io)?;
            if count == 0 {
                break;
            }
            if bytes.len() as u64 + count as u64 > before.len() {
                return Err(ClientError::Bound);
            }
            hash.update(&buffer[..count]);
            bytes.extend_from_slice(&buffer[..count]);
        }
        if bytes.len() as u64 != before.len()
            || identity(&file.metadata().map_err(|_| ClientError::Io)?) != identity(&before)
            || <Digest>::from(hash.finalize()) != expected
        {
            return Err(ClientError::Identity);
        }
        control.check()?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ClientError::Encoding)?;
        let map = parse_symbols(text, Some(control))?;
        control.check()?;
        Ok(map)
    }
}

/// Pure structural parser. Product map admission must independently authenticate
/// exact source bytes before invoking it; parser success supplies no authority.
fn parse_declared_symbols(text: &str) -> Result<V3CompilerInputMap, ClientError> {
    parse_symbols(text, None)
}

fn parse_symbols(
    text: &str,
    control: Option<&OperationControl>,
) -> Result<V3CompilerInputMap, ClientError> {
    if text.len() as u64 > SYMBOL_BYTES_CAP {
        return Err(ClientError::Bound);
    }
    let mut required = BTreeSet::new();
    for name in &V3_INPUT_KEYS[..8] {
        required.insert(format!("main.{name}"));
    }
    for (name, length) in [
        ("tbs", 672),
        ("issuerModulus", 17),
        ("issuerSignature", 17),
        ("holderSignature", 17),
        ("siblings", 10),
        ("pathIndices", 10),
    ] {
        required.extend((0..length).map(|i| format!("main.{name}[{i}]")));
    }
    let mut coordinates = BTreeMap::new();
    let mut indices = BTreeSet::new();
    for (row, line) in text.lines().enumerate() {
        if row % 1024 == 0 {
            if let Some(control) = control {
                control.check()?;
            }
        }
        let mut fields = line.split(',');
        let signal = fields.next().ok_or(ClientError::Encoding)?;
        let witness = fields.next().ok_or(ClientError::Encoding)?;
        let component = fields.next().ok_or(ClientError::Encoding)?;
        let name = fields.next().ok_or(ClientError::Encoding)?;
        let decimal = |value: &str| {
            !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && (value == "0" || !value.starts_with('0'))
        };
        if fields.next().is_some()
            || !decimal(signal)
            || signal.parse::<u64>().map_or(true, |index| index == 0)
            || !(witness == "-1" || decimal(witness))
            || witness.parse::<i64>().is_err()
            || !decimal(component)
            || component.parse::<u64>().is_err()
            || name.is_empty()
            || name
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(ClientError::Encoding);
        }
        if !required.contains(name) {
            continue;
        }
        let index = witness
            .parse::<usize>()
            .map_err(|_| ClientError::Encoding)?;
        if index == 0 || index >= ASSIGNMENT_FIELDS {
            return Err(ClientError::Bound);
        }
        if coordinates.insert(name.to_owned(), index).is_some() || !indices.insert(index) {
            return Err(ClientError::Identity);
        }
    }
    if coordinates.len() != required.len()
        || V3_INPUT_KEYS[..6]
            .iter()
            .enumerate()
            .any(|(i, name)| coordinates.get(&format!("main.{name}")) != Some(&(i + 1)))
    {
        return Err(ClientError::Identity);
    }
    Ok(V3CompilerInputMap { coordinates })
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
