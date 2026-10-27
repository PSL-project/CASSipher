"""Insecure, reversible byte-level educational ciphers. Not historical-text exact."""
import math

LIMIT_RAIL = 16 * 1024 * 1024

class HistoricalKeyError(ValueError):
    pass


def validate(method: str, key: str) -> None:
    if method == 'atbash':
        return
    if method == 'caesar':
        try:
            n = int(key.strip())
        except ValueError as exc:
            raise HistoricalKeyError('Caesar shift must be an integer from 0 to 255.') from exc
        if not 0 <= n <= 255:
            raise HistoricalKeyError('Caesar shift must be from 0 to 255.')
    elif method == 'vigenere':
        if not key:
            raise HistoricalKeyError('A nonempty Vigenère key is required.')
    elif method == 'affine':
        try:
            a, b = [int(part.strip()) for part in key.split(',')]
        except (ValueError, TypeError) as exc:
            raise HistoricalKeyError('Use a,b (example: 5,8).') from exc
        if not (0 <= a <= 255 and 0 <= b <= 255 and math.gcd(a, 256) == 1):
            raise HistoricalKeyError('Affine a must be odd (1..255), b must be 0..255.')
    elif method == 'railfence':
        try:
            n = int(key.strip())
        except ValueError as exc:
            raise HistoricalKeyError('Rails must be an integer from 2 to 20.') from exc
        if not 2 <= n <= 20:
            raise HistoricalKeyError('Rails must be from 2 to 20.')
    else:
        raise HistoricalKeyError('Unsupported educational cipher.')


def transform(data: bytes, method: str, key: str, decrypt: bool, offset: int = 0) -> bytes:
    validate(method, key)
    if method == 'atbash':
        return bytes(255 - b for b in data)
    if method == 'caesar':
        shift = int(key)
        return bytes((b - shift if decrypt else b + shift) % 256 for b in data)
    if method == 'vigenere':
        kb = key.encode('utf-8')
        if decrypt:
            return bytes((b - kb[(offset + i) % len(kb)]) % 256 for i, b in enumerate(data))
        return bytes((b + kb[(offset + i) % len(kb)]) % 256 for i, b in enumerate(data))
    if method == 'affine':
        a, b = [int(p) for p in key.split(',')]
        inv = pow(a, -1, 256)
        if decrypt:
            return bytes((inv * (p - b)) % 256 for p in data)
        return bytes((a * p + b) % 256 for p in data)
    if method == 'railfence':
        if len(data) > LIMIT_RAIL:
            raise ValueError('Rail fence educational mode is limited to 16 MiB.')
        rails = int(key)
        sequence = [min(i % (2*rails-2), 2*rails-2 - i % (2*rails-2)) for i in range(len(data))]
        if not decrypt:
            return bytes(data[i] for rail in range(rails) for i, r in enumerate(sequence) if r == rail)
        out = bytearray(len(data))
        index = 0
        for rail in range(rails):
            for i, r in enumerate(sequence):
                if r == rail:
                    out[i] = data[index]
                    index += 1
        return bytes(out)
    raise ValueError('Unknown method')
