import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('v3_build_prep', Path(__file__).with_name('queue_v3_build_prep.py'))
m = importlib.util.module_from_spec(spec)
if spec.loader and spec.origin and Path(spec.origin).exists():
    spec.loader.exec_module(m)


class BuildPrepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name).resolve() / 'repo'
        shutil.copytree(Path(__file__).resolve().parents[2] / 'program' / 'src', self.repo / 'program/src')
        for name in ('Cargo.toml', 'Cargo.lock'):
            shutil.copyfile(Path(__file__).resolve().parents[2] / 'program' / name, self.repo / 'program' / name)

    def manifest(self):
        self.assertTrue(hasattr(m, 'source_manifest'), 'v3 source manifest is not implemented')
        return m.source_manifest(self.repo)

    def test_inventory_includes_all_versions_nested_tests_and_six_public_identity(self):
        manifest = self.manifest()
        for name in ('generated_vk.rs', 'generated_vk_v2.rs', 'generated_vk_v3.rs', 'application_runtime_v3/execute_effect_tests.rs'):
            self.assertIn('program/src/' + name, manifest['source_pins'])
        self.assertEqual(manifest['v3_vk']['public_inputs'], 6)
        self.assertEqual(manifest['v3_vk']['ic_count'], 7)
        self.assertEqual(len(manifest['v3_vk']['setup_manifest_sha256']), 64)
        m.check_manifest(self.repo, manifest)

    def test_changed_added_and_missing_source_are_rejected(self):
        frozen = self.manifest()
        p = self.repo / 'program/src/new.rs'
        p.write_text('')
        with self.assertRaises(ValueError): m.check_manifest(self.repo, frozen)
        p.unlink()
        p = self.repo / 'program/src/generated_vk_v3.rs'
        p.write_text(p.read_text() + '\n')
        with self.assertRaises(ValueError): m.check_manifest(self.repo, frozen)
        p.unlink()
        with self.assertRaises(ValueError): m.check_manifest(self.repo, frozen)

    def test_include_path_build_script_and_symlink_require_review(self):
        self.manifest()
        p = self.repo / 'program/src/extra.rs'
        for text in ('include ! ("outside.rs");', '# [ path = "outside.rs" ] mod extra;'):
            p.write_text(text)
            with self.assertRaises(ValueError): m.source_manifest(self.repo)
        p.unlink()
        p = self.repo / 'program/build.rs'
        p.write_text('fn main() {}')
        with self.assertRaises(ValueError): m.source_manifest(self.repo)
        p.unlink()
        (self.repo / 'program/src/link.rs').symlink_to(self.repo / 'program/src/lib.rs')
        with self.assertRaises(ValueError): m.source_manifest(self.repo)

    def test_local_config_addition_and_change_are_pinned(self):
        frozen = self.manifest()
        config = self.repo / '.cargo/config.toml'
        config.parent.mkdir()
        config.write_text('[build]\njobs = 1\n')
        with self.assertRaises(ValueError): m.check_manifest(self.repo, frozen)
        frozen = self.manifest()
        self.assertIn('.cargo/config.toml', frozen['source_pins'])
        config.write_text('[build]\njobs = 2\n')
        with self.assertRaises(ValueError): m.check_manifest(self.repo, frozen)

    def test_ancestor_workspace_manifest_requires_review(self):
        frozen = self.manifest()
        builder = self.repo.parent / 'builder'
        builder.write_bytes(b'not executed')
        output = self.repo / 'artifacts/dynark/part5/application-v3-sbf-test'
        plan = m.prepare_build(self.repo, frozen, builder, m.digest(builder.read_bytes()), output)
        for directory in (self.repo, self.repo.parent):
            with self.subTest(directory=directory):
                cargo = directory / 'Cargo.toml'
                lock = directory / 'Cargo.lock'
                cargo.write_text('[workspace]\nmembers = ["program"]\n')
                lock.write_text('version = 4\n')
                try:
                    with self.assertRaisesRegex(ValueError, 'ancestor Cargo manifest'):
                        m.source_manifest(self.repo)
                    with self.assertRaises(ValueError): m.check_manifest(self.repo, frozen)
                    with self.assertRaises(ValueError): m.check_build_plan(self.repo, plan)
                finally:
                    cargo.unlink()
                    lock.unlink()

    def test_five_public_vk_cannot_be_relabelled(self):
        self.manifest()
        vk = self.repo / 'program/src/generated_vk_v3.rs'
        vk.write_text(vk.read_text().replace('PUBLIC_INPUTS: usize = 6', 'PUBLIC_INPUTS: usize = 5'))
        with self.assertRaises(ValueError): m.source_manifest(self.repo)

    def test_plan_requires_pinned_builder_fresh_protected_output_and_caps(self):
        frozen = self.manifest()
        builder = Path(self.tmp.name).resolve() / 'builder'
        builder.write_bytes(b'fake tool, never executed')
        output = self.repo / 'artifacts/dynark/part5/application-v3-sbf-build-test'
        plan = m.prepare_build(self.repo, frozen, builder, m.digest(builder.read_bytes()), output)
        argv = plan['argv']
        self.assertEqual(argv[-2:], ['--', '--locked'])
        self.assertIn('--offline', argv)
        self.assertIn('--skip-tools-install', argv)
        self.assertEqual(plan['outer_limits_required'], {'runtime_seconds': 180, 'rss_bytes': 4294967296, 'storage_growth_bytes': 536870912})
        self.assertIsNone(plan['loaded_elf_sha256'])
        self.assertFalse(output.exists())
        with self.assertRaises(ValueError): m.prepare_build(self.repo, frozen, builder, '0' * 64, output)
        with self.assertRaises(ValueError): m.prepare_build(self.repo, frozen, builder, m.digest(builder.read_bytes()), self.repo / 'program/target/deploy')
        output.mkdir(parents=True)
        with self.assertRaises(ValueError): m.prepare_build(self.repo, frozen, builder, m.digest(builder.read_bytes()), output)

    def test_prelaunch_recheck_rejects_external_config_and_tool_drift(self):
        frozen = self.manifest()
        builder = self.repo.parent / 'builder'
        builder.write_bytes(b'not executed')
        output = self.repo / 'artifacts/dynark/part5/application-v3-sbf-test'
        plan = m.prepare_build(self.repo, frozen, builder, m.digest(builder.read_bytes()), output)
        self.assertTrue(hasattr(m, 'check_build_plan'), 'prelaunch plan recheck is missing')
        m.check_build_plan(self.repo, plan)
        config = self.repo.parent / '.cargo/config.toml'
        config.parent.mkdir()
        config.write_text('[build]\njobs = 1\n')
        with self.assertRaises(ValueError): m.check_build_plan(self.repo, plan)
        config.unlink()
        builder.write_bytes(b'changed')
        with self.assertRaises(ValueError): m.check_build_plan(self.repo, plan)

    def test_elf_identity_is_byte_exact_and_does_not_claim_live_attestation(self):
        self.manifest()
        elf = b'\x7fELF' + bytes(80)
        result = m.compare_elf_payload(elf, elf + bytes(32), m.digest(elf))
        self.assertTrue(result['elf_match'])
        self.assertFalse(result['live_rpc_attestation'])
        for loaded in (elf[:-1], elf + b'\x01', b'\x7fELFchanged'):
            with self.assertRaises(ValueError): m.compare_elf_payload(elf, loaded, m.digest(elf))
        with self.assertRaises(ValueError): m.compare_elf_payload(elf, elf, '0' * 64)


if __name__ == '__main__':
    unittest.main()
