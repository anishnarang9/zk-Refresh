//! Separate tests-first v3 Full/Anchor runner scaffold; no runtime proof mode yet.
//! The accepted frozen setup runner and target are never rebuilt by this package.
#![forbid(unsafe_code)]
const SETUP_MANIFEST_SHA: &str = "d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918";
const PACKAGE_SHA: &str = "61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8";

#[derive(Clone, Copy)]
struct RootOnlyContext {
    package: [u8; 32],
    credential: [u8; 32],
    action: [u8; 32],
    root: [u8; 32],
    root_version: u64,
    policy_version: u32,
    allocation_epoch: u64,
}

fn admit_root_only(_base: &RootOnlyContext, _target: &RootOnlyContext) -> Result<(), &'static str> {
    Err("root-only context admission intentionally unimplemented until observed red gate")
}

fn main() {
    eprintln!("v3 proof qualification unavailable: tests-first scaffold only");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_credential_action_root_only_refresh_is_admitted() {
        assert_eq!(SETUP_MANIFEST_SHA.len(), 64);
        assert_eq!(PACKAGE_SHA.len(), 64);
        let base = RootOnlyContext {
            package: [1; 32],
            credential: [2; 32],
            action: [3; 32],
            root: [4; 32],
            root_version: 1,
            policy_version: 1,
            allocation_epoch: 1,
        };
        let target = RootOnlyContext {
            root: [5; 32],
            root_version: 2,
            ..base
        };
        admit_root_only(&base, &target)
            .expect("same credential and action with a newer root must be admitted");
    }
}
