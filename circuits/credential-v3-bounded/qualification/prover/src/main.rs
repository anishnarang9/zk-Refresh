//! Tests-first v3 qualification scaffold. No setup/proof implementation exists.
//! ROOT must observe the intended decoder test failure before positive code.
#![forbid(unsafe_code)]
use ark_bn254::Fr;

const ASSIGNMENT_FIELDS: usize = 784_796;
const PUBLIC_FIELDS: [&str; 6] = [
    "root",
    "issuerHash",
    "notBefore",
    "notAfter",
    "actionHash",
    "policyHash",
];

fn decode_witness(_bytes: &[u8], _expected_count: usize) -> Result<Vec<Fr>, &'static str> {
    Err("v3 decoder intentionally unimplemented until observed red gate")
}

fn main() {
    eprintln!("v3 setup/proof execution unavailable: tests-first scaffold only");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};

    fn fixture(values: &[[u8; 32]]) -> Vec<u8> {
        let mut bytes = b"wtns".to_vec();
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(40u64.to_le_bytes());
        bytes.extend(32u32.to_le_bytes());
        bytes.extend(Fr::MODULUS.to_bytes_le());
        bytes.extend((values.len() as u32).to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(((values.len() * 32) as u64).to_le_bytes());
        for value in values {
            bytes.extend(value);
        }
        bytes
    }

    #[test]
    fn canonical_v3_wtns_round_trip_and_six_public_coordinates() {
        assert_eq!(PUBLIC_FIELDS.len(), 6);
        assert_eq!(ASSIGNMENT_FIELDS, 784_796);
        let mut values = [[0u8; 32]; 8];
        for (i, item) in values.iter_mut().enumerate() {
            item[0] = (i + 1) as u8;
        }
        let decoded = decode_witness(&fixture(&values), 8)
            .expect("canonical v3 WTNS must decode all six public coordinates");
        assert_eq!(decoded, (1u64..=8).map(Fr::from).collect::<Vec<_>>());
        assert_eq!(
            &decoded[1..7],
            &(2u64..=7).map(Fr::from).collect::<Vec<_>>()
        );
    }
}
