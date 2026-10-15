//! Reviewed ordinary VK for the shared six-public development setup.
//! The component verifier does not enable runtime Execute or application effects.
//! Raw file SHA, engine extended digest and tagged ordinary digest are distinct.
use groth16_solana::groth16::Groth16Verifyingkey;
const fn hex(s: &[u8; 64]) -> [u8; 32] {
    let mut b = [0; 32];
    let mut i = 0;
    while i < 32 {
        let a = s[2 * i];
        let c = s[2 * i + 1];
        b[i] = ((if a <= b'9' { a - b'0' } else { a - b'a' + 10 }) << 4)
            | (if c <= b'9' { c - b'0' } else { c - b'a' + 10 });
        i += 1;
    }
    b
}
pub const PUBLIC_INPUTS: usize = 6;
pub const IC_COUNT: usize = 7;
pub const ORDINARY_VK_FILE_BYTES: usize = 456;
pub const ORDINARY_VK_TAG: &[u8] = b"dynark-solana-adapter/ordinary-vk/v2";
pub const CIRCUIT_ID: [u8; 32] =
    hex(b"eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe");
pub const PACKAGE_ID: [u8; 32] =
    hex(b"61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8");
pub const PROFILE_ID: [u8; 32] =
    hex(b"2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918");
pub const SEMANTIC_SCHEMA_ID: [u8; 32] =
    hex(b"eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4");
pub const ORDINARY_VK_DIGEST: [u8; 32] =
    hex(b"2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e");
pub const ORDINARY_VK_FILE_SHA256: [u8; 32] =
    hex(b"87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875");
pub const ENGINE_EXTENDED_VK_DIGEST: [u8; 32] =
    hex(b"2611d58c8c8d0b0c1f2c3f0facc4516e5c08e1fb3a7f14b16e32b948bc8f3c70");
pub const SETUP_MANIFEST_SHA256: [u8; 32] =
    hex(b"d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918");

const fn point<const N: usize>(s: &[u8]) -> [u8; N] {
    assert!(s.len() == N * 2);
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        let a = s[2 * i];
        let b = s[2 * i + 1];
        assert!((a >= b'0' && a <= b'9') || (a >= b'a' && a <= b'f'));
        assert!((b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f'));
        out[i] = ((if a <= b'9' { a - b'0' } else { a - b'a' + 10 }) << 4)
            | (if b <= b'9' { b - b'0' } else { b - b'a' + 10 });
        i += 1;
    }
    out
}

// Exact reviewed export_v3_vk projection, alpha64 || beta128 || gamma128 ||
// delta128 || IC7*64, SHA256 b3321c0bbc47f8775de86539f04b38e7768c8cefd58d7e62619f99d8b1103c94.
// Alpha is NOT negated; G2 components are x.c1,x.c0,y.c1,y.c0, canonical BE Fq.
pub const VERIFYING_KEY: Groth16Verifyingkey<'static> = Groth16Verifyingkey {
    nr_pubinputs: PUBLIC_INPUTS,
    vk_alpha_g1: point(b"11bd6833cb5f8055c6631069be81a0c3ea731cbe4b970a91711645c1e15059492060b514ea6eb5931aeac2d864e203c2bd4e381c02b8b38769b092301ec05d4f"),
    vk_beta_g2: point(b"12b8da5d62b2e82f43ea25498168399190fa0d17096b1d97c65318d150da700526adf6defa63e383b284530082ac68c8e60b3d1e8f5eddb4239b1dc64af0827a22cbf232107014b1e24d73ba7f1133653f589bbf142aeb25edc8392d0789942b20378df15c0356511ea1077c09b060555ebd6b453278260a7628aa0049f97d7b"),
    vk_gamme_g2: point(b"0ae2d490abf47e0d49b412e7af3023a9f33847380a22775974c53dc0f2171f8808dba4bbf1eb668e3405585ca3cde18f4a3fb73ed743ab07cf8fbc6eefb8c7902afd4d43941a907b786fb1e99a8e8d90d66da5b3b7f2a368e233dbb2615716031698ca1953583ca9d980aba2548e574b602b6a5381be7efba0f6d9b81ed212ed"),
    vk_delta_g2: point(b"11b88ce9d4031f7c476bfe2991405d9a3d87a35f906f53958dcd0a81f438345a0df0031407cd337bec2b715eecd7d850d901e2f9e6b6184ab1561308d325cbdc0479205baf55ee2f9ebb90ebb3ee14ad2aa8846721dc01290599d5c986921edd0d1694906c46a9e99384ad5ef8c531945e1d83f8144e3f60d3f96984b1605365"),
    vk_ic: &[
        point(b"02dde4cbc9b53308e45b5801e3ae0921f39e9aab42ec838d6249c53185e889bc05bfba37e8e5c40e37d2663f55825a927cb1043747d3895a8e89e228f268c2be"),
        point(b"24c0519d44e1a054713b1b77b328f59120aa84ccbb80de936f0a0987cfc4a69c02baf671418b0fe735aea4bc3564aa1d821c2a06d9c19b683bb330d31ab35c9c"),
        point(b"1435049f85a40a7a2d14a0273cd3ce646889bc658abb469e0d2f92cab1fc4aeb05f1ca65e08e2936f0d4da57b5cd21652e19b940527e4151f7d3b0e133d8e544"),
        point(b"262f95bfde3d2534e363831049437217727509bf4f51045c9a86702414272b982be782e7dade05292cc0d63be225ed345d37d72c90450ba9a037a44ad5acfc32"),
        point(b"13223ae046b5a9e21e51cf79e9305605c625b21bdb16d959a8a0a85b94bdd7ee088199efa2ef7323d1ad460f0ef37dfcf7870b5c599e8cc00b69cf6d03c29966"),
        point(b"25157297a033a45eece452ba95b75c663f16b065da90c3eac442bb5813dad01a2ef8ab9c6c8e8cb67431832791d4248bec2d819416aabc5ea885fb3e7fe6c292"),
        point(b"0908c60c0c387898dd6165a3078399886c8586314ea48861d3ee5129ad89a345269d608cc0075472c3b02b15260f45cacd368b3a8d4292ad511f4c165943e748"),
    ],
};
