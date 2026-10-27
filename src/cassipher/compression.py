"""Streaming compression with bounded-output decompression."""
import bz2
import lzma
import zlib

CHUNK = 256 * 1024
CODECS = ('none', 'zlib', 'lzma', 'bz2', 'zstd')
OPTIONS = CODECS + ('auto',)


def _codec(method, decompress=False):
    if method == 'none':
        return None
    if method == 'zlib':
        return zlib.decompressobj() if decompress else zlib.compressobj(level=6)
    if method == 'bz2':
        return bz2.BZ2Decompressor() if decompress else bz2.BZ2Compressor(9)
    if method == 'lzma':
        return lzma.LZMADecompressor() if decompress else lzma.LZMACompressor(preset=6)
    if method == 'zstd':
        try:
            import zstandard as zstd
        except ImportError as exc:
            raise RuntimeError('Zstandard is optional. Install: pip install zstandard') from exc
        return zstd.ZstdDecompressor() if decompress else zstd.ZstdCompressor(level=6).compressobj()
    raise ValueError('Unknown compression method')


def compress_file(source, target, method, progress=None, cancelled=None):
    codec = _codec(method)
    done = 0
    with open(source, 'rb') as reader, open(target, 'wb') as writer:
        while part := reader.read(CHUNK):
            if cancelled and cancelled():
                raise InterruptedError('Operation cancelled.')
            writer.write(codec.compress(part) if codec is not None else part)
            done += len(part)
            if progress:
                progress(done)
        if codec is not None:
            writer.write(codec.flush())
    return done


def decompress_file(source, target, method, expected_bytes, cancelled=None):
    """Decode at most CHUNK output bytes per read, requiring exact expected length."""
    if type(expected_bytes) is not int or not 0 <= expected_bytes <= 2 * (1024**4):
        raise ValueError('Invalid unpacked size.')
    codec = _codec(method, True)
    written = 0
    def put(out, data):
        nonlocal written
        written += len(data)
        if written > expected_bytes:
            raise ValueError('Decompressed content exceeds declared size.')
        out.write(data)

    with open(source, 'rb') as reader, open(target, 'wb') as writer:
        if method == 'zstd':
            # zstandard stream_reader enforces bounded reads and checks the frame.
            import zstandard as zstd
            with zstd.ZstdDecompressor().stream_reader(reader, read_across_frames=False, closefd=False) as stream:
                while part := stream.read(CHUNK):
                    if cancelled and cancelled():
                        raise InterruptedError('Operation cancelled.')
                    put(writer, part)
            if reader.read(1):
                raise ValueError('Trailing zstd data.')
        elif codec is None:
            while part := reader.read(CHUNK):
                if cancelled and cancelled():
                    raise InterruptedError('Operation cancelled.')
                put(writer, part)
        elif method == 'zlib':
            while part := reader.read(CHUNK):
                if cancelled and cancelled():
                    raise InterruptedError('Operation cancelled.')
                pending = part
                while pending:
                    # cap every decompressor allocation; use unconsumed_tail.
                    output = codec.decompress(pending, CHUNK)
                    put(writer, output)
                    pending = codec.unconsumed_tail
                    if not output and pending:
                        raise ValueError('Invalid zlib stream.')
            while True:
                remain = codec.flush(CHUNK)
                if not remain:
                    break
                put(writer, remain)
            if not codec.eof or codec.unused_data:
                raise ValueError('Truncated or trailing zlib data.')
        else:
            # BZ2 and LZMA support bounded max_length and needs_input.
            for part in iter(lambda:reader.read(CHUNK),b''):
                if cancelled and cancelled():
                    raise InterruptedError('Operation cancelled.')
                put(writer, codec.decompress(part, max_length=CHUNK))
                while not codec.needs_input and not codec.eof:
                    put(writer, codec.decompress(b'', max_length=CHUNK))
            if not codec.eof or codec.unused_data:
                raise ValueError('Truncated or trailing compressed data.')
        if written != expected_bytes:
            raise ValueError('Unexpected decompressed size.')
    return written
