#!/usr/bin/env python3
"""Offline v3 build preparation. This module never launches a build or validator.

The reviewed inventory conservatively includes every program/src Rust file,
including cfg(test) modules. It is not an exact compiler dependency graph.
Dependency/toolchain source identities require the later reviewed build gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib

LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 536870912}
VK_FIELDS = ('CIRCUIT_ID', 'PACKAGE_ID', 'PROFILE_ID', 'SEMANTIC_SCHEMA_ID',
             'ORDINARY_VK_DIGEST', 'ORDINARY_VK_FILE_SHA256',
             'ENGINE_EXTENDED_VK_DIGEST', 'SETUP_MANIFEST_SHA256')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, cap=1024 * 1024):
    path = Path(path)
    if path.resolve() != path or not path.is_file() or path.stat().st_size > cap:
        raise ValueError('bounded nonsymlink absolute regular file required: ' + str(path))
    data = path.read_bytes()
    if len(data) > cap:
        raise ValueError('file grew beyond cap')
    return data


def canonical_sha(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('canonical SHA256 required')
    return value


def vk_identity(data):
    text = data.decode()
    result = {'source_sha256': digest(data)}
    for name, expected in (('PUBLIC_INPUTS', 6), ('IC_COUNT', 7)):
        values = re.findall(r'pub const ' + name + r': usize\s*=\s*(\d+)\s*;', text)
        if values != [str(expected)]:
            raise ValueError('v3 six-public/seven-IC identity required')
        result[name.lower()] = expected
    for name in VK_FIELDS:
        values = re.findall(r'pub const ' + name + r': \[u8; 32\]\s*=\s*hex\(b"([0-9a-f]{64})"\)', text)
        if len(values) != 1:
            raise ValueError('missing or ambiguous v3 VK identity: ' + name)
        result[name.lower()] = values[0]
    return result


def source_manifest(repo):
    repo = Path(repo)
    if not repo.is_absolute() or repo.resolve() != repo:
        raise ValueError('absolute nonsymlink repository required')
    # This preparer admits a standalone program package only. Cargo workspace
    # discovery can otherwise move dependency/profile/lock authority above it.
    for directory in (repo, *repo.parents):
        ancestor = directory / 'Cargo.toml'
        if ancestor.exists() or ancestor.is_symlink():
            raise ValueError('ancestor Cargo manifest requires workspace source review: ' + str(ancestor))
    if (repo / 'program/build.rs').exists() or (repo / 'program/build.rs').is_symlink():
        raise ValueError('local build script requires review')
    paths = {repo / 'program/Cargo.toml', repo / 'program/Cargo.lock'}
    # Cargo is launched from repo; pin both repo and manifest-dir local configs.
    for directory in (repo, repo / 'program'):
        for name in ('.cargo/config', '.cargo/config.toml', 'rust-toolchain', 'rust-toolchain.toml'):
            candidate = directory / name
            if candidate.exists() or candidate.is_symlink():
                paths.add(candidate)
    src = repo / 'program/src'
    if src.resolve() != src:
        raise ValueError('source directory symlink requires review')
    for path in src.rglob('*'):
        if path.is_symlink():
            raise ValueError('source symlink requires review')
        if path.suffix == '.rs':
            text = regular(path).decode()
            if path == src / 'application_runtime_v3.rs':
                text = text.replace('#[cfg(test)]\n#[path = "application_runtime_v3/execute_effect_tests.rs"]', '#[cfg(test)]')
            if re.search(r'\binclude(?:_bytes|_str)?\s*!|#\s*\[\s*(?:cfg_attr\b|path\b)', text):
                raise ValueError('external include/path or cfg_attr requires review')
            paths.add(path)
    cargo = tomllib.loads(regular(repo / 'program/Cargo.toml').decode())
    if cargo.get('package', {}).get('build') or cargo.get('lib', {}).get('path', 'src/lib.rs') != 'src/lib.rs':
        raise ValueError('alternate build input requires review')
    # A local path/workspace/patch dependency expands the source boundary.
    def local_dependency(value):
        if isinstance(value, dict):
            return any(k in value for k in ('path', 'workspace', 'patch', 'replace')) or any(local_dependency(v) for v in value.values())
        if isinstance(value, list):
            return any(local_dependency(v) for v in value)
        return False
    if local_dependency(cargo):
        raise ValueError('local/workspace dependency requires source review')
    pins = {str(path.relative_to(repo)): digest(regular(path)) for path in sorted(paths)}
    required = ('lib.rs', 'application_v3.rs', 'application_runtime_v3.rs',
                'application_preflight_v3.rs', 'generated_vk_v3.rs')
    if any('program/src/' + name not in pins for name in required):
        raise ValueError('v3 source closure missing')
    return {'schema': 1, 'scope': 'v3 reviewed program source inventory',
            'source_pins': pins, 'v3_vk': vk_identity(regular(src / 'generated_vk_v3.rs'))}


def check_manifest(repo, manifest):
    if manifest != source_manifest(repo):
        raise ValueError('reviewed source inventory or v3 VK identity changed')


def external_config_pins(repo):
    """Record Cargo config discovery outside the repo without exposing contents."""
    paths = set()
    for directory in Path(repo).parents:
        for name in ('.cargo/config', '.cargo/config.toml'):
            paths.add(directory / name)
    cargo_home = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')))
    if not cargo_home.is_absolute():
        raise ValueError('absolute Cargo home required')
    paths.update(cargo_home / name for name in ('config', 'config.toml'))
    return {str(p): digest(regular(p)) for p in sorted(paths) if p.exists() or p.is_symlink()}


def prepare_build(repo, manifest, builder, builder_sha256, output):
    repo, builder, output = Path(repo), Path(builder), Path(output)
    check_manifest(repo, manifest)
    if digest(regular(builder, 128 * 1024 * 1024)) != canonical_sha(builder_sha256):
        raise ValueError('builder pin mismatch')
    base = repo / 'artifacts/dynark/part5'
    if (not output.is_absolute() or not output.is_relative_to(base) or output == base
            or output.resolve() != output or output.exists()
            or not output.name.startswith('application-v3-sbf-')):
        raise ValueError('fresh protected v3 SBF output required')
    argv = [str(builder), '--offline', '--skip-tools-install', '--tools-version', 'v1.54',
            '--arch', 'v0', '--manifest-path', str(repo / 'program/Cargo.toml'),
            '--sbf-out-dir', str(output / 'elf'), '-j', '1', '--', '--locked']
    return {'schema': 1, 'status': 'prepared_only', 'argv': argv, 'cwd': str(repo),
            'source_manifest': manifest, 'external_cargo_config_pins': external_config_pins(repo),
            'builder_sha256': builder_sha256, 'outer_limits_required': dict(LIMITS),
            'child_timeout_seconds': 165, 'environment_required': {'CARGO_BUILD_JOBS': '1',
                'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1'},
            'environment_remove': ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'CARGO_TARGET_DIR',
                'SBF_OUT_PATH', 'SBF_SDK_PATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
                'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'],
            'loaded_elf_sha256': None,
            'remaining_gates': ['recheck complete plan immediately before bounded launch',
                'review dependency/toolchain identity and inherited Cargo environment',
                'fresh output; successful build; reject stack diagnostics in either log',
                'recheck source pins after build; pin actual ELF bytes/hash separately',
                'select fresh v3 program id and mint; pin local ledger genesis',
                'authenticated finalized RPC loader/programdata exact byte comparison',
                'genuine request-bound six-public v3 proof and protected effect']}


def check_build_plan(repo, plan):
    argv = plan['argv']
    output = Path(argv[argv.index('--sbf-out-dir') + 1]).parent
    current = prepare_build(repo, plan['source_manifest'], Path(argv[0]),
                            plan['builder_sha256'], output)
    if current != plan:
        raise ValueError('reviewed build plan or external Cargo config changed')


def compare_elf_payload(local, loaded_payload, expected_sha256):
    """Compare an already stripped loader payload; no RPC provenance is implied.

    The later live runner must validate executable owner, linked ProgramData,
    genesis and finalized commitment before stripping loader metadata. Loader
    allocation may have zero padding after the complete ELF, as in the v2 gate.
    """
    canonical_sha(expected_sha256)
    if (len(local) > 4 * 1024 * 1024 or not local.startswith(b'\x7fELF')
            or digest(local) != expected_sha256 or len(loaded_payload) < len(local)
            or len(loaded_payload) > 4 * 1024 * 1024
            or loaded_payload[:len(local)] != local or any(loaded_payload[len(local):])):
        raise ValueError('loaded ELF payload mismatch')
    return {'elf_match': True, 'elf_sha256': expected_sha256,
            'local_bytes': len(local), 'loaded_payload_bytes': len(loaded_payload),
            'live_rpc_attestation': False, 'application_effect': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--check-manifest', type=Path)
    parser.add_argument('--builder', type=Path)
    parser.add_argument('--builder-sha256')
    parser.add_argument('--build-output', type=Path)
    args = parser.parse_args()
    manifest = source_manifest(args.repo)
    if args.check_manifest:
        check_manifest(args.repo, json.loads(regular(args.check_manifest)))
    if any((args.builder, args.builder_sha256, args.build_output)):
        if not all((args.builder, args.builder_sha256, args.build_output)):
            parser.error('builder, builder-sha256 and build-output are required together')
        result = prepare_build(args.repo, manifest, args.builder, args.builder_sha256, args.build_output)
    else:
        result = manifest
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
