"""Private CLI I/O RED; keys/DER exist only in memory and private temp files.

The independently signed fixture and pure-builder oracle come from the frozen
test source below. No old test class is inherited or automatically rerun here.
Actual subprocesses test status, silence, permissions and exclusive output.
Deterministic in-process syscall hooks exercise races and foreign-owner metadata
without requiring another OS user or relying on scheduler timing. They do not
establish chain authentication, full relation admission, or proof authority.
"""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
REFERENCE_PATH = TESTS / 'test_v3_input_worker.py'
reference_bytes = REFERENCE_PATH.read_bytes()
if len(reference_bytes) > 128 * 1024 or hashlib.sha256(reference_bytes).hexdigest() != (
        'd2985f3d6cec3a254f3c6bb5b548d0138503f25d0cbbb5697c6c3cd66f945729'):
    raise RuntimeError('CLI fixture reference source identity')
reference = types.ModuleType('frozen_v3_input_worker_tests')
reference.__file__ = str(REFERENCE_PATH)
exec(compile(reference_bytes, str(REFERENCE_PATH), 'exec'), reference.__dict__)
del reference_bytes
worker = reference.worker
WORKER_PATH = Path(worker.__file__)


class MetadataOwner:
    def __init__(self, original):
        self.original = original
        self.st_uid = original.st_uid + 1

    def __getattr__(self, name):
        return getattr(self.original, name)


class V3InputCliTests(unittest.TestCase):
    fixture = reference.V3InputWorkerTests.fixture

    @classmethod
    def setUpClass(cls):
        reference.V3InputWorkerTests.setUpClass.__func__(cls)

    def setUp(self):
        # This dedicated private child is disjoint from runner reports/monitors.
        self.temporary = tempfile.TemporaryDirectory(prefix='.v3-input-cli-', dir=TESTS)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.directory.chmod(0o700)
        self.request, _, _, _ = self.fixture()
        self.request_path = self.directory / 'request.bin'
        self.output_path = self.directory / 'output.bin'
        self.write_private(self.request_path, self.request)

    @staticmethod
    def write_private(path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)

    def call(self, directory=None):
        process = subprocess.run(
            [sys.executable, '-B', str(WORKER_PATH), 'build',
             str(self.directory if directory is None else directory)],
            env={'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False, umask=0,
        )
        self.assertEqual(len(process.stdout), 0, 'CLI must emit no stdout')
        self.assertEqual(len(process.stderr), 0, 'CLI must emit no stderr')
        return process.returncode

    def in_process(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', [str(WORKER_PATH), 'build', str(self.directory)]):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    status = worker.main()
                except worker.InputFailure:
                    status = 2
                except NotImplementedError:
                    status = 3
        self.assertEqual(len(stdout.getvalue()), 0, 'CLI must emit no stdout')
        self.assertEqual(len(stderr.getvalue()), 0, 'CLI must emit no stderr')
        return status

    def assert_rejected(self, directory=None):
        self.assertEqual(self.call(directory), 2, 'private CLI rejection status required')
        self.assertFalse(self.output_path.exists(), 'rejected input creates no output')

    def test_fresh_private_cli_output_matches_pure_build_exactly(self):
        expected = worker.build(self.request)
        self.assertEqual(self.call(), 0, 'closed exit3 must become successful private CLI')
        metadata = self.output_path.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode), 'regular output required')
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, os.getuid())
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_size, 24495)
        self.assertTrue(self.output_path.read_bytes() == expected,
                        'CLI output must exactly equal pure verified response')

    def test_relative_symlinked_and_nonprivate_directories_reject(self):
        alias = self.directory / 'directory-alias'
        alias.symlink_to(self.directory, target_is_directory=True)
        self.assert_rejected(alias)
        self.assert_rejected(os.path.relpath(self.directory, Path.cwd()))
        for mode in (0o755, 0o750, 0o777):
            with self.subTest(mode=mode):
                self.directory.chmod(mode)
                self.assert_rejected()
        self.directory.chmod(0o700)

    def test_request_mode_type_exact_size_and_single_link_are_required(self):
        for mode in (0o644, 0o400, 0o666):
            with self.subTest(mode=mode):
                self.request_path.chmod(mode)
                self.assert_rejected()
        self.request_path.chmod(0o600)
        for data in (self.request[:-1], self.request + b'\x00'):
            with self.subTest(size=len(data)):
                self.request_path.write_bytes(data)
                self.assert_rejected()
        self.request_path.write_bytes(self.request)
        alias = self.directory / 'request-hardlink'
        os.link(self.request_path, alias)
        self.assert_rejected()
        alias.unlink()
        self.request_path.unlink()
        self.request_path.mkdir(mode=0o700)
        self.assert_rejected()

    def test_request_symlink_rejects_without_touching_target(self):
        target = self.directory / 'request-target'
        self.write_private(target, self.request)
        self.request_path.unlink()
        self.request_path.symlink_to(target)
        self.assert_rejected()
        self.assertTrue(target.read_bytes() == self.request, 'symlink target stays intact')

    def test_wrong_request_owner_rejects_with_no_output(self):
        original = Path.lstat
        def foreign_owner(path, *args, **kwargs):
            metadata = original(path, *args, **kwargs)
            return MetadataOwner(metadata) if path == self.request_path else metadata
        with mock.patch.object(Path, 'lstat', foreign_owner):
            self.assertEqual(self.in_process(), 2, 'foreign request owner must reject')
        self.assertFalse(self.output_path.exists())

    def test_wrong_directory_owner_rejects_with_no_output(self):
        original = Path.lstat
        def foreign_owner(path, *args, **kwargs):
            metadata = original(path, *args, **kwargs)
            return MetadataOwner(metadata) if path == self.directory else metadata
        with mock.patch.object(Path, 'lstat', foreign_owner):
            self.assertEqual(self.in_process(), 2, 'foreign directory owner must reject')
        self.assertFalse(self.output_path.exists())

    def test_output_reuse_symlink_and_hardlink_are_never_overwritten(self):
        target = self.directory / 'output-target'
        sentinel = b'preserve-existing-output'
        self.write_private(target, sentinel)
        for kind in ('regular', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                if kind == 'regular':
                    self.write_private(self.output_path, sentinel)
                elif kind == 'symlink':
                    self.output_path.symlink_to(target)
                else:
                    os.link(target, self.output_path)
                before = self.output_path.lstat()
                self.assertEqual(self.call(), 2, 'output must be created exclusively')
                after = self.output_path.lstat()
                self.assertEqual((before.st_dev, before.st_ino, before.st_size),
                                 (after.st_dev, after.st_ino, after.st_size))
                self.assertTrue(self.output_path.read_bytes() == sentinel, 'existing output intact')
                self.assertTrue(target.read_bytes() == sentinel, 'output target intact')
                self.output_path.unlink()

    def test_second_successful_invocation_cannot_reuse_output(self):
        self.assertEqual(self.call(), 0, 'first invocation succeeds')
        before = self.output_path.lstat()
        expected = self.output_path.read_bytes()
        self.assertEqual(self.call(), 2, 'second invocation rejects exclusive output')
        after = self.output_path.lstat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        self.assertTrue(self.output_path.read_bytes() == expected, 'successful output retained')

    def test_request_and_output_open_flags_enforce_nofollow_and_exclusivity(self):
        original = os.open
        seen = set()
        def checked_open(path, flags, mode=0o777, *, dir_fd=None):
            absolute = Path(path) if dir_fd is None else self.directory / Path(path)
            if absolute in (self.request_path, self.output_path):
                self.assertTrue(flags & os.O_NOFOLLOW, 'private leaf open must use O_NOFOLLOW')
                seen.add(absolute.name)
                if absolute == self.output_path:
                    self.assertTrue(flags & os.O_EXCL and flags & os.O_CREAT,
                                    'output creation must be exclusive')
                    self.assertEqual(mode, 0o600)
            return original(path, flags, mode, dir_fd=dir_fd)
        with mock.patch.object(worker.os, 'open', checked_open):
            self.assertEqual(self.in_process(), 0)
        self.assertEqual(seen, {'request.bin', 'output.bin'})

    def test_regular_request_replacement_between_stat_and_open_rejects(self):
        original = os.open
        triggered = []
        def replace_then_open(path, flags, mode=0o777, *, dir_fd=None):
            absolute = Path(path) if dir_fd is None else self.directory / Path(path)
            if absolute == self.request_path and not triggered:
                triggered.append(True)
                self.request_path.rename(self.directory / 'retained-original-request')
                # A separate inode with identical valid bytes must still reject.
                self.request_path.write_bytes(self.request)
                self.request_path.chmod(0o600)
            return original(path, flags, mode, dir_fd=dir_fd)
        with mock.patch.object(worker.os, 'open', replace_then_open):
            self.assertEqual(self.in_process(), 2)
        self.assertTrue(triggered, 'request open hook must execute')
        self.assertFalse(self.output_path.exists())

    def test_symlink_request_swap_between_stat_and_open_rejects(self):
        original = os.open
        target = self.directory / 'swap-target'
        self.write_private(target, self.request)
        triggered = []
        def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
            absolute = Path(path) if dir_fd is None else self.directory / Path(path)
            if absolute == self.request_path and not triggered:
                triggered.append(True)
                self.request_path.unlink()
                self.request_path.symlink_to(target)
            return original(path, flags, mode, dir_fd=dir_fd)
        with mock.patch.object(worker.os, 'open', swap_then_open):
            self.assertEqual(self.in_process(), 2)
        self.assertTrue(triggered, 'request open hook must execute')
        self.assertFalse(self.output_path.exists())
        self.assertTrue(target.read_bytes() == self.request, 'swapped target stays intact')

    def test_request_change_after_open_is_detected_on_the_same_handle(self):
        original_fstat, original_fdopen = os.fstat, os.fdopen
        before = self.request_path.lstat()
        observed = []
        changed = []
        case = self
        def observed_stat(fd):
            metadata = original_fstat(fd)
            if (metadata.st_dev, metadata.st_ino) == (before.st_dev, before.st_ino):
                observed.append(fd)
            return metadata

        class ChangeAfterRead:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                self.handle.__enter__()
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.handle, name)

            def read(self, size=-1):
                case.assertTrue(0 <= size <= 1919, 'request read must have a finite exact bound')
                data = self.handle.read(size)
                if not changed:
                    changed.append(True)
                    os.utime(case.request_path, ns=(before.st_atime_ns,
                                                   before.st_mtime_ns + 1_000_000_000))
                return data

        def change_on_read(fd, *args, **kwargs):
            metadata = original_fstat(fd)
            handle = original_fdopen(fd, *args, **kwargs)
            if (metadata.st_dev, metadata.st_ino) == (before.st_dev, before.st_ino):
                return ChangeAfterRead(handle)
            return handle

        with mock.patch.object(worker.os, 'fstat', observed_stat):
            with mock.patch.object(worker.os, 'fdopen', change_on_read):
                self.assertEqual(self.in_process(), 2)
        self.assertTrue(changed, 'bounded request read hook must execute')
        self.assertGreaterEqual(len(observed), 2, 'same-handle metadata checked before and after read')
        self.assertEqual(len(set(observed)), 1, 'request checks must use one handle')
        self.assertFalse(self.output_path.exists())


if __name__ == '__main__':
    unittest.main()
