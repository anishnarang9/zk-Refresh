"""One bounded v1 request. Exit 2 means unsupported shape, never validation failure."""
import hashlib
import os
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent

PINS = {
    'suffix_evaluator.py': 'f03ebe9da8ee29296942685fb7e401041382649394a4fed10ea6810a6b511a9b',
    'far_evaluator.py': '1ffb20759e65752692a870bc47ae8bcb9f1e1ada2a78c51ba71a11a0c7ac9e3c',
    'trace_component.py': '0476d6e9712fba4b8152d2cc0a4dfdab15eade10a747f024b5fd813296786601',
}


def read_file(path, cap):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > cap:
        raise ValueError('bounded_regular_input')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError('input_bound')
    return raw


def classify(before_raw, target_raw):
    load_accepted()
    from far_evaluator import ScopeError, parse_inputs
    from suffix_evaluator import validate_suffix_scope
    before, target = parse_inputs(before_raw), parse_inputs(target_raw)
    try:
        return validate_suffix_scope(before, target)
    except ScopeError:
        return None


def load_accepted():
    # Compile the verified source bytes directly. Importing cached .pyc files
    # would not bind executable code to the accepted source digest.
    sources = {}
    for name, digest in PINS.items():
        raw = read_file(HERE / 'accepted-v1' / name, 65536)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('source_identity')
        sources[name] = raw
    for name in ('far_evaluator.py', 'trace_component.py', 'suffix_evaluator.py'):
        module_name = name[:-3]
        module = types.ModuleType(module_name)
        module.__file__ = str(HERE / 'accepted-v1' / name)
        sys.modules[module_name] = module
        exec(compile(sources[name], module.__file__, 'exec'), module.__dict__)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('incremental', 'normalize'):
        raise ValueError('invocation')
    load_accepted()
    from far_evaluator import FixturePins, parse_inputs
    from suffix_evaluator import SuffixProgram, refresh_suffix
    directory = Path(sys.argv[2])
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError('private_directory')
    target = read_file(directory / 'target.json', 65536)
    parse_inputs(target)
    if sys.argv[1] == 'normalize':
        # Parsing here rejects duplicate keys, floats, malformed schemas and all
        # bounds before the unchanged calculator's ordinary JSON parser runs.
        return 0
    before = read_file(directory / 'before.json', 65536)
    if classify(before, target) is None:
        return 2
    baseline = read_file(directory / 'before.wtns', 20594092)
    result = refresh_suffix(SuffixProgram.load(), before, target, baseline,
        FixturePins(hashlib.sha256(before).hexdigest(), hashlib.sha256(baseline).hexdigest()))
    fd = os.open(directory / 'output.wtns', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(result.wtns)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # No credential bytes, paths, field values or traceback on this channel.
        raise SystemExit(1) from None
