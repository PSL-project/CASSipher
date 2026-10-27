"""Human-readable catalog. Availability matches implemented engine capabilities."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Method:
    code: str
    name: str
    family: str
    security: str
    speed: str
    year: str
    key: str
    summary: str
    mathematics: str
    pros: str
    cons: str
    implemented: bool = True

METHODS = [
    Method('aes256', 'AES-256-GCM', 'Modern', 'Recommended', 'Fast', '2007', 'Password',
           'NIST-standard AES in Galois/Counter Mode with a 256-bit key. Authenticated, chunked file protection.',
           'AES operates on 128-bit blocks. GCM uses CTR encryption C=P xor AES_K(counter), while GHASH authenticates the ciphertext and associated data. Each chunk is independently authenticated with a unique 96-bit nonce.',
           'Widely analyzed; accelerated on many CPUs; provides confidentiality and integrity.',
           'Nonce reuse is dangerous. Our container enforces unique per-chunk nonces within each file.'),
    Method('aes128', 'AES-128-GCM', 'Modern', 'Recommended', 'Very fast', '2007', 'Password',
           'AES-GCM with a 128-bit encryption key.',
           'The GCM structure is identical to AES-256-GCM, but AES-128 uses 10 AES rounds instead of 14.',
           'Wide interoperability; excellent performance and a strong security margin.',
           'Requires strict nonce uniqueness. Smaller key than AES-256.'),
    Method('chacha', 'ChaCha20-Poly1305', 'Modern', 'Recommended', 'Very fast', '2015', 'Password',
           'RFC 8439 authenticated encryption with a 256-bit key.',
           'ChaCha20 produces a keystream through additions mod 2^32, rotation and XOR. Ciphertext = plaintext xor stream. Poly1305 produces a 128-bit authentication tag.',
           'Excellent performance without AES hardware acceleration; built-in authentication.',
           'Each nonce must be unique with a given key; unauthenticated streaming is disallowed.'),
    Method('otp', 'OTP-style XOR pad', 'Experimental', 'Special requirements', 'Fast', '1917', 'Separate pad file',
           'Bytewise XOR with a secret pad equal to the data size, plus an independent 32-byte HMAC key in the pad file.',
           'For each byte, C_i=P_i xor K_i; P_i=C_i xor K_i. HMAC-SHA256 authenticates the container using 32 additional pad bytes.',
           'Data confidentiality approaches an OTP construction if the pad is truly uniformly random and never reused.',
           'OS CSPRNG is computational, not a physical true-random source; no formal perfect secrecy claim. Pad reuse catastrophically destroys confidentiality; pad distribution is difficult. HMAC is computational authentication.'),
    Method('caesar', 'Caesar (byte variant)', 'Historical', 'Broken', 'Fast', 'Antiquity', 'Shift 0–255',
           'Invertible byte-oriented adaptation of the Caesar shift cipher.',
           'C_i=(P_i+k) mod 256; P_i=(C_i-k) mod 256.',
           'Simple; handles any file bytes; educational.',
           'Brute-forceable in 256 attempts. NOT secure; adaptation is not the original letter-only cipher.'),
    Method('atbash', 'Atbash (byte variant)', 'Historical', 'Broken', 'Fast', 'Antiquity', 'None',
           'Byte-oriented adaptation of an alphabet reversal cipher.',
           'C_i=255-P_i; decryption is the same function.',
           'Reversible without a key; demonstrates substitution.',
           'No secrecy: anybody can reverse it. Not the traditional alphabetic Atbash.'),
    Method('vigenere', 'Vigenère (byte variant)', 'Historical', 'Broken', 'Fast', '1553', 'Repeating text key',
           'An additive repeating-key cipher applied to arbitrary bytes.',
           'C_i=(P_i+K_(i mod m)) mod 256, where the key is the UTF-8 encoding of the entered text. Decryption subtracts key bytes.',
           'Reversible for arbitrary file data; illustrative of polyalphabetic methods.',
           'Statistically vulnerable and NOT secure; reusing a repeating key exposes patterns.'),
    Method('affine', 'Affine (byte variant)', 'Historical', 'Broken', 'Fast', 'Classical', 'a,b integers',
           'Invertible byte substitution using an odd multiplier.',
           'C_i=(a P_i+b) mod 256; P_i=a^(-1)(C_i-b) mod 256. a must be coprime to 256.',
           'Simple algebraic encryption demonstration for arbitrary files.',
           'Small key space and trivially broken; NOT secure.'),
    Method('railfence', 'Rail fence (byte variant)', 'Historical', 'Broken', 'Slow', '19th c.', '2–20 rails',
           'Zigzag transposition of bytes across multiple rails.',
           'Write positions onto rails 0,1,...,r-1,...,1 repeatedly and concatenate. Decrypt by reconstructing the rail occupancy.',
           'Shows transposition rather than substitution.',
           'No meaningful security. For safety this implementation limits input to 16 MiB per file payload.'),
    Method('xchacha', 'XChaCha20-Poly1305', 'Modern', 'Recommended', 'Fast', 'Modern', 'Password',
           'Extended-nonce authenticated cipher supported by libsodium.',
           'HChaCha20 derives a subkey from part of the 192-bit nonce; ChaCha20-Poly1305 handles authenticated encryption.',
           'Long random nonces reduce accidental collision risk.',
           'Planned for a later release, not currently available.', False),
    Method('mlkem', 'ML-KEM hybrid encryption', 'Post-quantum', 'Research', 'Varies', '2024', 'Public/private key',
           'Post-quantum key encapsulation combined with authenticated symmetric file encryption.',
           'ML-KEM encapsulates a shared secret, which is turned into an AEAD key using a KDF.',
           'Standardized post-quantum key establishment.',
           'Not yet implemented or interoperability-tested here.', False),
    Method('enigma', 'Enigma machine', 'Historical', 'Broken', 'Slow', '1920s', 'Rotor configuration',
           'Historical electromechanical rotor encryption.',
           'Rotor permutation composition varies at each keypress; a reflector makes conversion reciprocal.',
           'Interesting mechanical history and cryptanalysis.',
           'Planned historical simulator; not for secure file encryption.', False),
]
METHOD_BY_CODE = {m.code: m for m in METHODS}
MODERN = {'aes256', 'aes128', 'chacha'}
HISTORICAL = {'caesar', 'atbash', 'vigenere', 'affine', 'railfence'}
