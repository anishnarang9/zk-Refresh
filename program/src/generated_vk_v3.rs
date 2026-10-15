//! Identity-only stage for the reviewed shared six-public development setup.
//! No verifying key or successful verification path exists in this slice.
//! Raw file SHA, engine extended digest and tagged ordinary digest are distinct.
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
