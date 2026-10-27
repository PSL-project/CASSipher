"""CWBOX v1 streaming file container. THIS FORMAT HAS NOT BEEN EXTERNALLY AUDITED.

Header: magic(8), header_len(big-endian uint32), canonical JSON <= 4096 bytes.
AEAD payload: repeated uint32 length + encrypted chunk; final empty AEAD chunk.
OTP payload: ciphertext of exactly packed_size bytes, then 32-byte HMAC tag.
Historical payload: transformed packed_size bytes then 32-byte SHA256 checksum.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import secrets
import sqlite3
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import __version__
from . import archive, compression, historical
from .catalog import METHOD_BY_CODE, MODERN, HISTORICAL

MAGIC = b'CWBOX1\r\n'
MAX_HEADER = 4096
BLOCK = 256 * 1024
MAX_FRAME = BLOCK + 16
MAX_PAYLOAD = 2 * 1024**4
KDF_MEMORY = 64 * 1024  # KiB
KDF_ITERATIONS = 3
KDF_LANES = 2

class ContainerError(ValueError):
    pass

class AuthenticationError(ContainerError):
    pass

@dataclass
class Options:
    method: str = 'aes256'
    compression: str = 'zlib'
    password: str = ''
    key: str = ''
    pad_path: str = ''
    generate_pad: bool = True


def _cancel(cancelled):
    if cancelled and cancelled():
        raise InterruptedError('Operation cancelled.')


def _note(callback, label, fraction):
    if callback:
        callback(label, max(0., min(1., float(fraction))))


def _b64(b):
    return base64.b64encode(b).decode('ascii')


def _unb64(s, n):
    try:
        val = base64.b64decode(s, validate=True)
    except Exception as exc:
        raise ContainerError('Invalid header encoding.') from exc
    if len(val) != n:
        raise ContainerError('Invalid header field size.')
    return val


def _head_bytes(header):
    b = json.dumps(header, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(b) > MAX_HEADER:
        raise ValueError('Header is too large.')
    return MAGIC + struct.pack('>I', len(b)) + b


def inspect_file(path):
    with open(path, 'rb') as file:
        head, raw = _read_header(file)
    return head


def _read_header(file):
    if file.read(len(MAGIC)) != MAGIC:
        raise ContainerError('Not a CASSipher container or unsupported version.')
    length_b = file.read(4)
    if len(length_b) != 4:
        raise ContainerError('Truncated header.')
    length = struct.unpack('>I', length_b)[0]
    if not 1 <= length <= MAX_HEADER:
        raise ContainerError('Invalid header length.')
    raw = file.read(length)
    if len(raw) != length:
        raise ContainerError('Truncated header.')
    try:
        head = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerError('Invalid header data.') from exc
    if not isinstance(head, dict) or head.get('version') != 1:
        raise ContainerError('Unsupported format version.')
    method = head.get('method')
    if method not in MODERN | HISTORICAL | {'otp'}:
        raise ContainerError('Unknown algorithm.')
    if head.get('compression') not in compression.CODECS:
        raise ContainerError('Unknown compression.')
    for field in ('packed_size', 'archive_size'):
        n = head.get(field)
        if type(n) is not int or not 0 <= n <= MAX_PAYLOAD:
            raise ContainerError('Invalid file size in header.')
    if method in MODERN:
        _unb64(head.get('salt', ''), 16)
        _unb64(head.get('nonce_prefix', ''), 8)
        if head.get('kdf') != 'argon2id-v1':
            raise ContainerError('Unsupported password KDF.')
        # These bounds prevent a malicious header from consuming excessive memory/time.
        if head.get('memory_kib') != KDF_MEMORY or head.get('iterations') != KDF_ITERATIONS or head.get('lanes') != KDF_LANES:
            raise ContainerError('Unsupported Argon2id parameters.')
    if method == 'otp' and head.get('pad_bytes') != head['packed_size'] + 32:
        raise ContainerError('Invalid OTP size.')
    return head, MAGIC + length_b + raw


def _password_key(password, salt):
    if not isinstance(password, str) or len(password) < 10:
        raise ValueError('Password must contain at least 10 characters.')
    kdf = Argon2id(salt=salt, length=32, iterations=KDF_ITERATIONS, lanes=KDF_LANES, memory_cost=KDF_MEMORY)
    return kdf.derive(password.encode('utf-8'))


def _cipher(method, key):
    if method == 'chacha':
        return ChaCha20Poly1305(key)
    if method == 'aes128':
        return AESGCM(key[:16])
    if method == 'aes256':
        return AESGCM(key)
    raise ValueError('Invalid modern cipher.')


def _nonce(prefix, index):
    if index >= (1 << 32):
        raise ContainerError('File exceeds nonce counter capacity.')
    return prefix + struct.pack('>I', index)


def _u32(n):
    return struct.pack('>I', n)


def _exact(reader, size):
    b = reader.read(size)
    if len(b) != size:
        raise ContainerError('Truncated container.')
    return b


def _pad_ledger():
    appdata = os.getenv('LOCALAPPDATA')
    # Keep the original v0.1.0 ledger location for OTP pad reuse protection.
    # Changing it would allow pads used by the prior release to be reused.
    directory = Path(appdata) / 'CipherWorkbench' if appdata else Path.home() / '.cipher-workbench'
    directory.mkdir(parents=True, exist_ok=True)
    return directory / 'pad_usage.sqlite3'


def _mark_pad_used(pad):
    with open(pad, 'rb') as f:
        fingerprint = hashlib.sha256(f.read(32)).hexdigest()
    # Reservation before encryption is intentional; cancellation still burns this pad.
    with sqlite3.connect(_pad_ledger(), timeout=30) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS used_pads (fingerprint TEXT PRIMARY KEY, used_at TEXT DEFAULT CURRENT_TIMESTAMP)')
        try:
            conn.execute('INSERT INTO used_pads(fingerprint) VALUES (?)', (fingerprint,))
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError('This pad has already been used on this device. Never reuse an OTP pad.') from exc


def _generate_pad(path, n, cancelled=None):
    if n > MAX_PAYLOAD + 32:
        raise ValueError('Pad is too large.')
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as f:
        try:
            os.chmod(target, 0o600)
            remain = n
            while remain:
                _cancel(cancelled)
                take = min(BLOCK, remain)
                f.write(secrets.token_bytes(take))
                remain -= take
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            f.close()
            target.unlink(missing_ok=True)
            raise


def _encrypt_aead(source, out, raw_header, head, password, progress, cancelled):
    key = _password_key(password, _unb64(head['salt'], 16))
    cipher = _cipher(head['method'], key)
    prefix = _unb64(head['nonce_prefix'], 8)
    written = 0
    index = 0
    aad = hashlib.sha256(raw_header).digest()
    with open(source, 'rb') as inp:
        while block := inp.read(BLOCK):
            _cancel(cancelled)
            ct = cipher.encrypt(_nonce(prefix, index), block, aad + b'D' + struct.pack('>Q', index))
            out.write(_u32(len(ct)))
            out.write(ct)
            index += 1
            written += len(block)
            _note(progress, 'Encrypting authenticated chunks', 0.30 + 0.65 * written / max(1, head['packed_size']))
        final_ad = aad + b'F' + struct.pack('>QQ', index, written)
        final = cipher.encrypt(_nonce(prefix, index), b'', final_ad)
        out.write(_u32(len(final)))
        out.write(final)
    if written != head['packed_size']:
        raise ValueError('Input changed while encrypting.')


def _decrypt_aead(inp, dest, raw_header, head, password, progress, cancelled):
    key = _password_key(password, _unb64(head['salt'], 16))
    cipher = _cipher(head['method'], key)
    prefix = _unb64(head['nonce_prefix'], 8)
    aad = hashlib.sha256(raw_header).digest()
    expected = head['packed_size']
    done = 0
    index = 0
    try:
        with open(dest, 'wb') as out:
            while done < expected:
                _cancel(cancelled)
                clen = struct.unpack('>I', _exact(inp, 4))[0]
                if not 16 < clen <= MAX_FRAME or clen - 16 > min(BLOCK, expected - done):
                    raise ContainerError('Invalid encrypted chunk length.')
                block = cipher.decrypt(_nonce(prefix, index), _exact(inp, clen), aad + b'D' + struct.pack('>Q', index))
                out.write(block)
                done += len(block)
                index += 1
                _note(progress, 'Authenticating and decrypting', 0.65 * done / max(1, expected))
            final_length = struct.unpack('>I', _exact(inp, 4))[0]
            if final_length != 16:
                raise AuthenticationError('Final authentication record is missing.')
            final = cipher.decrypt(_nonce(prefix, index), _exact(inp, 16), aad + b'F' + struct.pack('>QQ', index, done))
            if final != b'' or inp.read(1):
                raise AuthenticationError('Unexpected final data or trailing bytes.')
    except Exception as exc:
        if isinstance(exc, (ContainerError, InterruptedError, ValueError)):
            raise
        raise AuthenticationError('Decryption failed: wrong password or altered file.') from exc


def _encrypt_pad(source, out, raw_header, head, pad, progress, cancelled):
    written = 0
    mac = hmac.new(_last32(pad), raw_header, hashlib.sha256)
    with open(source, 'rb') as inp, open(pad, 'rb') as keyfile:
        while plain := inp.read(BLOCK):
            _cancel(cancelled)
            stream = _exact(keyfile, len(plain))
            ciphertext = bytes(a ^ b for a, b in zip(plain, stream))
            out.write(ciphertext)
            mac.update(ciphertext)
            written += len(plain)
            _note(progress, 'Applying one-time pad', 0.30 + 0.65 * written / max(1, head['packed_size']))
        out.write(mac.digest())
    if written != head['packed_size']:
        raise ValueError('Input changed while encrypting.')


def _last32(pad):
    with open(pad, 'rb') as f:
        f.seek(-32, os.SEEK_END)
        return _exact(f, 32)


def _decrypt_pad(inp, dest, raw_header, head, pad, progress, cancelled):
    if not pad or os.path.getsize(pad) != head['pad_bytes']:
        raise ValueError('The pad file is missing or has the wrong size.')
    mac = hmac.new(_last32(pad), raw_header, hashlib.sha256)
    expected = head['packed_size']
    done = 0
    with open(dest, 'wb') as out, open(pad, 'rb') as keyfile:
        while done < expected:
            _cancel(cancelled)
            block = _exact(inp, min(BLOCK, expected-done))
            mac.update(block)
            ks = _exact(keyfile, len(block))
            out.write(bytes(a ^ b for a, b in zip(block, ks)))
            done += len(block)
            _note(progress, 'Reading OTP ciphertext', 0.65 * done / max(1, expected))
    if not hmac.compare_digest(mac.digest(), _exact(inp, 32)) or inp.read(1):
        raise AuthenticationError('OTP authentication failed: incorrect pad or altered file.')


def _encrypt_historical(source, out, raw_header, head, key, progress, cancelled):
    method = head['method']
    check = hashlib.sha256(raw_header)
    offset = 0
    if method == 'railfence':
        with open(source, 'rb') as f:
            block = f.read(historical.LIMIT_RAIL+1)
        if len(block) > historical.LIMIT_RAIL:
            raise ValueError('Rail fence is limited to 16 MiB input.')
        ciphertext = historical.transform(block, method, key, False)
        out.write(ciphertext)
        check.update(ciphertext)
    else:
        with open(source, 'rb') as f:
            while block := f.read(BLOCK):
                _cancel(cancelled)
                ct = historical.transform(block, method, key, False, offset)
                out.write(ct)
                check.update(ct)
                offset += len(block)
                _note(progress, 'Applying educational cipher', 0.30 + 0.65*offset/max(1,head['packed_size']))
    out.write(check.digest())


def _decrypt_historical(inp, dest, raw_header, head, key, progress, cancelled):
    method = head['method']
    historical.validate(method, key)
    check = hashlib.sha256(raw_header)
    expected = head['packed_size']
    done = 0
    with open(dest, 'wb') as out:
        if method == 'railfence':
            if expected > historical.LIMIT_RAIL:
                raise ContainerError('Rail fence size limit exceeded.')
            ct = _exact(inp, expected)
            check.update(ct)
            out.write(historical.transform(ct, method, key, True))
        else:
            while done < expected:
                _cancel(cancelled)
                ct = _exact(inp, min(BLOCK, expected-done))
                check.update(ct)
                out.write(historical.transform(ct, method, key, True, done))
                done += len(ct)
                _note(progress, 'Reversing educational cipher', 0.65*done/max(1, expected))
    if not hmac.compare_digest(check.digest(), _exact(inp, 32)) or inp.read(1):
        raise ContainerError('Educational container checksum mismatch (not cryptographic authentication).')


def _unused_named(directory, name):
    path = Path(directory) / name
    if path.exists():
        raise FileExistsError(f'Output exists: {path}. Please select another output.')
    return path


def encrypt(inputs, output, options: Options, progress=None, cancelled=None):
    """Encrypt a file/folder package; returns paths. Never intentionally overwrites."""
    if options.method not in MODERN | HISTORICAL | {'otp'}:
        raise ValueError('Selected algorithm is not implemented.')
    if options.compression not in compression.OPTIONS:
        raise ValueError('Unknown compression.')
    if options.method in HISTORICAL:
        historical.validate(options.method, options.key)
    if options.method in MODERN and len(options.password) < 10:
        raise ValueError('Use a password of at least 10 characters.')
    outpath = Path(output).expanduser().resolve()
    outpath.parent.mkdir(parents=True, exist_ok=True)
    _unused_named(outpath.parent, outpath.name)
    selected = [Path(p).expanduser().resolve() for p in inputs]
    if outpath in selected or (options.pad_path and outpath == Path(options.pad_path).expanduser().resolve()):
        raise ValueError('Output would overwrite an input or keyfile.')
    pad = None
    with tempfile.TemporaryDirectory(prefix='cw-work-') as temp:
        raw_zip = Path(temp) / 'pack.zip'
        packed = Path(temp) / 'packed.bin'
        _note(progress, 'Packaging selected files', 0.04)
        raw_size = archive.pack(selected, raw_zip, cancelled)
        _note(progress, 'Compressing data', 0.13)
        actual_compression = options.compression
        if actual_compression == 'auto':
            # Compare lossless codecs on the exact same inner ZIP payload.
            # This is intentionally slower and uses temporary disk space.
            candidates = ['none', 'zlib', 'lzma', 'bz2']
            try:
                import zstandard  # noqa: F401
                candidates.append('zstd')
            except ImportError:
                pass
            best_size = None
            best_path = None
            for candidate in candidates:
                _cancel(cancelled)
                _note(progress, 'Comparing compression methods: ' + candidate, 0.12 + 0.16*candidates.index(candidate)/len(candidates))
                candidate_path = Path(temp) / ('try-'+candidate+'.bin')
                compression.compress_file(raw_zip, candidate_path, candidate, cancelled=cancelled)
                size = candidate_path.stat().st_size
                if best_size is None or size < best_size:
                    best_size, best_path, actual_compression = size, candidate_path, candidate
            os.replace(best_path, packed)
        else:
            compression.compress_file(raw_zip, packed, actual_compression, cancelled=cancelled)
        packed_size = packed.stat().st_size
        if packed_size > MAX_PAYLOAD:
            raise ValueError('Package exceeds supported size.')
        head = dict(version=1, method=options.method, compression=actual_compression,
                    packed_size=packed_size, archive_size=raw_size, created_by=f'CASSipher {__version__}')
        if options.method in MODERN:
            head.update(kdf='argon2id-v1', salt=_b64(os.urandom(16)), nonce_prefix=_b64(os.urandom(8)),
                        memory_kib=KDF_MEMORY, iterations=KDF_ITERATIONS, lanes=KDF_LANES)
        if options.method == 'otp':
            if not options.pad_path:
                raise ValueError('Specify a separate pad file path.')
            pad = str(Path(options.pad_path).expanduser().resolve())
            if Path(pad) in selected:
                raise ValueError('Pad cannot be one of the input files.')
            if options.generate_pad:
                if Path(pad).exists():
                    raise FileExistsError('Pad destination exists. Never overwrite key material.')
                _note(progress, 'Generating random pad', 0.22)
                _generate_pad(pad, packed_size + 32, cancelled)
            if os.path.getsize(pad) != packed_size + 32:
                raise ValueError(f'Pad must contain exactly {packed_size+32} bytes (data pad + 32-byte HMAC key).')
            _mark_pad_used(pad)
            head['pad_bytes'] = packed_size + 32
        raw_header = _head_bytes(head)
        tmp_output = Path(temp) / 'encrypted.tmp'
        with tmp_output.open('wb') as dest:
            dest.write(raw_header)
            if options.method in MODERN:
                _encrypt_aead(packed, dest, raw_header, head, options.password, progress, cancelled)
            elif options.method == 'otp':
                _encrypt_pad(packed, dest, raw_header, head, pad, progress, cancelled)
            else:
                _encrypt_historical(packed, dest, raw_header, head, options.key, progress, cancelled)
            dest.flush()
            os.fsync(dest.fileno())
        _cancel(cancelled)
        # Copy to same-volume staging, then atomically publish via a no-overwrite hard-link.
        # Crucially, staging is created only AFTER packaging, so an output inside an
        # input folder cannot recursively include its own temporary files.
        with tempfile.TemporaryDirectory(prefix='.cw-publish-', dir=outpath.parent) as publish:
            staged = Path(publish) / 'complete.cwbox'
            with tmp_output.open('rb') as src, staged.open('xb') as dst:
                shutil.copyfileobj(src, dst, length=BLOCK)
                dst.flush()
                os.fsync(dst.fileno())
            _cancel(cancelled)
            os.link(staged, outpath)
    _note(progress, 'Encryption completed', 1.)
    return {'output': str(outpath), 'pad': pad if options.method == 'otp' else None,
            'input_bytes': raw_size, 'compressed_bytes': packed_size, 'output_bytes': outpath.stat().st_size}


def decrypt(source, output_directory, password='', key='', pad_path='', progress=None, cancelled=None):
    source = Path(source).expanduser().resolve()
    dest = Path(output_directory).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(str(source))
    dest.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as f:
        head, raw_header = _read_header(f)
        if head['method'] in MODERN and len(password) < 10:
            raise ValueError('Enter the original encryption password.')
        if head['method'] in HISTORICAL:
            historical.validate(head['method'], key)
        with tempfile.TemporaryDirectory(prefix='.cw-decrypt-', dir=dest) as temp:
            packed = Path(temp) / 'packed.bin'
            raw_zip = Path(temp) / 'pack.zip'
            _note(progress, 'Authenticating encrypted file', 0.)
            if head['method'] in MODERN:
                _decrypt_aead(f, packed, raw_header, head, password, progress, cancelled)
            elif head['method'] == 'otp':
                _decrypt_pad(f, packed, raw_header, head, pad_path, progress, cancelled)
            else:
                _decrypt_historical(f, packed, raw_header, head, key, progress, cancelled)
            _cancel(cancelled)
            _note(progress, 'Decompressing authenticated data', 0.70)
            compression.decompress_file(packed, raw_zip, head['compression'], head['archive_size'], cancelled)
            _cancel(cancelled)
            _note(progress, 'Validating archive and restoring files', 0.88)
            outputs = archive.extract_archive(raw_zip, dest, cancelled)
    _note(progress, 'Files restored successfully', 1.)
    return {'outputs': outputs, 'method': head['method'], 'compression': head['compression']}
