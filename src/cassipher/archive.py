"""File packaging and defensive extraction. ZIP_STORED is an inner container only."""
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ENTRIES = 100_000
MAX_UNPACKED = 2 * 1024**4


def _require_safe_input(path: Path):
    if path.is_symlink():
        raise ValueError(f'Symbolic links are not supported: {path}')
    if not path.exists():
        raise FileNotFoundError(str(path))


def pack(inputs, target, cancelled=None):
    """Produce ZIP_STORED archive preserving input basename(s) and folder hierarchy."""
    inputs = [Path(x).expanduser().resolve() for x in inputs]
    if not inputs:
        raise ValueError('No input files selected.')
    root_names = set()
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as z:
        count = 0
        for root in inputs:
            _require_safe_input(root)
            if root.name.casefold() in root_names:
                raise ValueError(f'Duplicate root name: {root.name}')
            root_names.add(root.name.casefold())
            if root.is_file():
                z.write(root, arcname=root.name)
                count += 1
            elif root.is_dir():
                z.writestr(root.name + '/', b'')
                for base, dirs, files in os.walk(root, followlinks=False):
                    if cancelled and cancelled():
                        raise InterruptedError('Cancelled.')
                    dirs.sort()
                    files.sort()
                    for name in dirs + files:
                        _require_safe_input(Path(base) / name)
                    for name in files:
                        p = Path(base) / name
                        arcname = (PurePosixPath(root.name) / PurePosixPath(p.relative_to(root).as_posix())).as_posix()
                        z.write(p, arcname=arcname)
                        count += 1
                        if count > MAX_ENTRIES:
                            raise ValueError('Too many files in one package.')
            else:
                raise ValueError(f'Unsupported file type: {root}')
            if count > MAX_ENTRIES:
                raise ValueError('Too many files in one package.')
    return os.path.getsize(target)


def _safe_member(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe archive path.')
    p = PurePosixPath(name)
    parts = p.parts
    if p.is_absolute() or not parts or any(c in ('.', '..') for c in parts):
        raise ValueError('Unsafe path traversal in archive.')
    for c in parts:
        if not c or ':' in c or c.endswith((' ', '.')):
            raise ValueError('Invalid Windows path in archive.')
        if c.split('.')[0].casefold() in {'con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),*(f'lpt{i}' for i in range(1,10))}:
            raise ValueError('Reserved Windows archive path.')
    return parts


def inspect_archive(path):
    """Validate entries before extraction; archive is not trusted until checked."""
    seen = set()
    total = 0
    entries = []
    with zipfile.ZipFile(path, 'r') as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError('Archive contains too many entries.')
        for info in infos:
            # On Windows, zipfile.ZipInfo normalizes backslashes in `filename`
            # to forward slashes, even when *reading* a ZIP. Validate the raw
            # name captured by ZipInfo before that normalization, otherwise a
            # crafted entry such as "dir\\bad" would silently become "dir/bad".
            # ZipInfo.orig_filename is available in supported Python versions.
            parts = _safe_member(info.orig_filename)
            if info.compress_type != zipfile.ZIP_STORED:
                raise ValueError('Nested ZIP compression is not supported.')
            if info.flag_bits & 1:
                raise ValueError('Nested encrypted ZIP is not supported.')
            unix_mode = info.external_attr >> 16
            if stat.S_IFMT(unix_mode) == stat.S_IFLNK:
                raise ValueError('Archive contains symbolic links.')
            norm = '/'.join(parts).casefold()
            if norm in seen:
                raise ValueError('Duplicate archive entry.')
            seen.add(norm)
            total += info.file_size
            if total > MAX_UNPACKED:
                raise ValueError('Archive is too large.')
            entries.append((info, parts))
        # Reject a file that is also an ancestor of another file.
        files = {'/'.join(parts).casefold() for info, parts in entries if not info.is_dir()}
        for _, parts in entries:
            for n in range(1, len(parts)):
                if '/'.join(parts[:n]).casefold() in files:
                    raise ValueError('Archive path conflict.')
    return entries


def _unused_path(directory, basename):
    candidate = directory / basename
    for i in range(1, 10001):
        if not candidate.exists():
            return candidate
        candidate = directory / f'{basename} ({i})'
    raise ValueError('Cannot find a free destination name.')


def extract_archive(path, destination, cancelled=None):
    """Extract into temporary area; publish only after all bytes are verified.

    For one file, restores directly under destination. Otherwise creates a
    distinct directory per restoration. Never overwrites existing outputs.
    """
    dest = Path(destination).expanduser().resolve()
    dest.mkdir(parents=True, exist_ok=True)
    entries = inspect_archive(path)
    with tempfile.TemporaryDirectory(prefix='.cw-restore-', dir=dest) as staging:
        temp = Path(staging)
        with zipfile.ZipFile(path, 'r') as z:
            for info, parts in entries:
                if cancelled and cancelled():
                    raise InterruptedError('Cancelled.')
                p = temp.joinpath(*parts)
                if info.is_dir():
                    p.mkdir(parents=True, exist_ok=True)
                else:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info, 'r') as inp, p.open('xb') as out:
                        shutil.copyfileobj(inp, out, length=256 * 1024)
        # One top-level file -> direct output; otherwise publish a new named folder.
        top = sorted(temp.iterdir())
        if len(top) == 1 and top[0].is_file():
            source = top[0]
            # os.link ensures no overwrite even if path appears concurrently.
            output = _unused_path(dest, source.name)
            os.link(source, output)
            return [str(output)]
        basename = Path(path).stem or 'restored'
        target = _unused_path(dest, basename + '_restored')
        target.mkdir(exist_ok=False)
        try:
            for p in top:
                p.rename(target / p.name)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
        return [str(target)]
