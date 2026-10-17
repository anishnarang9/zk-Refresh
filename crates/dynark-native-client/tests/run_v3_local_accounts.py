"""Small source tests linked to cached dependencies; no Cargo, witness or proof build.

Requires existing native-client and program debug artifacts from this checkout.
The current v3 action/account source is compiled directly. The program codec comparison compiles the current account codec/action source
against cached program constants and Solana dependencies.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "crates/dynark-native-client"
BUILDS = [NATIVE / "target/debug/build", ROOT / "program/target/debug/build"]


def artifact(build, name):
    candidates = list(build.glob(name.replace("_", "-") + "/*/out/lib" + name + "*.rmeta"))
    if len(candidates) != 1:
        raise RuntimeError("exact cached dependency required: " + name)
    return candidates[0]


def main():
    with tempfile.TemporaryDirectory(prefix="v3-local-accounts-") as directory:
        directory = Path(directory)
        tests = directory / "account_tests.rs"
        tests.write_text((NATIVE / "tests/support/v3_local_accounts.rs").read_text() + r"""
#[test]
fn current_program_codecs_and_action_match_native_account_checks() {
    use crate::application_v3::{Config, Issuer, Request, Queue, PublisherHead, action_hash};
    let f = Fixture::new();
    let c = Config::decode(&f.config).expect("current Config codec");
    let i = Issuer::decode(&f.issuer).expect("current Issuer codec");
    let r = Request::decode(&f.request).expect("current Request codec");
    let q = Queue::decode(&f.queue).expect("current Queue codec");
    let h = PublisherHead::decode(&f.head).expect("current PublisherHead codec");
    assert_eq!(c.encode(), f.config);
    assert_eq!(i.encode(), f.issuer);
    assert_eq!(r.encode(), f.request);
    assert_eq!(q.encode(), f.queue);
    assert_eq!(h.encode(), f.head);
    let action = action_hash(&solana_program::pubkey::Pubkey::new_from_array([20;32]), &c, &r).unwrap();
    assert_eq!(action, f.check().unwrap().action_be());
}
""")
        account_source = directory / "accounts.rs"
        source = (NATIVE / "src/v3_local_accounts.rs").read_text()
        source = source.replace('../tests/support/v3_local_accounts.rs', str(tests))
        account_source.write_text(source)
        harness = directory / "tests.rs"
        harness.write_text('extern crate dynark_native_client;\npub use dynark_native_client::*;\n'
            + '#[path="' + str(NATIVE / 'src/v3_action.rs') + '"]\nmod v3_action;\npub use v3_action::*;\n'
            + 'pub use zk_fresh_program::{canonical, FIELD_MODULUS, generated_vk_v3};\n'
            + '#[allow(dead_code)]\n#[path="' + str(ROOT / 'program/src/application_v3.rs') + '"]\nmod application_v3;\n'
            + '#[path="' + str(account_source) + '"]\nmod v3_local_accounts;\n')
        binary = directory / "tests"
        args = ["rustc", "--edition=2021", "--test", str(harness), "-o", str(binary)]
        directories = set(p.parent for build in BUILDS for p in build.glob("*/*/out/lib*"))
        for path in sorted(directories):
            args += ["-L", "dependency=" + str(path)]
        for name in ["dynark_native_client", "ark_bn254", "ark_ff", "ark_serialize", "sha2",
                     "zk_fresh_program", "solana_program"]:
            path = artifact(BUILDS[int(name in ("zk_fresh_program", "solana_program"))], name)
            # Cached Cargo artifacts keep full metadata beside the code archive.
            args += ["--extern", name + "=" + str(path),
                     "--extern", name + "=" + str(path.with_suffix(".rlib"))]
        subprocess.run(args, check=True, timeout=45)
        subprocess.run([str(binary)], check=True, timeout=15)


if __name__ == "__main__":
    main()
