# CWBOX version 1 container specification (experimental)

**This format is not standardized and has not been audited.** The implementation in `src/cassipher/engine.py` is authoritative for v0.1.x.

## File structure

```
[8-byte MAGIC = ASCII "CWBOX1\\r\\n"]
[4-byte BE unsigned header length N, 1 <= N <= 4096]
[N UTF-8 bytes of compact sorted-key JSON header]
[payload selected by header.method]
```

JSON fields include `version=1`, `method`, `compression`, `packed_size` (compressed bytes), `archive_size` (size of uncompressed inner ZIP_STORED), and `created_by`. With modern encryption, public metadata also includes `kdf=argon2id-v1`, `salt` (Base64 16 bytes), `nonce_prefix` (Base64 8 bytes), and KDF parameters `memory_kib=65536`, `iterations=3`, `lanes=2`. With OTP-style encryption, `pad_bytes=packed_size+32`.

**No original file names are in the public header**; filenames live in the encrypted inner ZIP archive. Compression type, approximate file size, and algorithm are public.

## Modern encryption framing

Key: Argon2id(password UTF-8, salt) => 32 bytes; AES-128-GCM uses first 16 bytes. For each 256KiB plaintext chunk `i`:

- `nonce_i = 8-byte random nonce_prefix || BE32(i)`.
- `AAD_i = SHA256(complete serialized header, including magic + length) || b'D' || BE64(i)`.
- `ciphertext_i = AEAD(key, nonce_i, compressed_plain_chunk, AAD_i)`; includes 16-byte tag.
- Write `BE32(len(ciphertext_i)) || ciphertext_i`.

When finished, write a **final authenticated empty record**:

- `AAD_final = SHA256(complete header) || b'F' || BE64(next_index) || BE64(total_packed_plaintext_bytes)`.
- `final = AEAD(key, nonce_next_index, b'', AAD_final)`; 16 bytes.
- Write `BE32(16) || final` and no other trailing data.

Decrypting verifies each AEAD tag and the final record before releasing restored files. Incomplete decompressed and extracted temporary files are deleted on ordinary errors. Plaintext temp files may persist on crash or be forensically recoverable.

## OTP-style educational format

`pad_file = random bytes[packed_size] || independent random 32-byte HMAC key`. Ciphertext is `compressed_zip XOR pad_bytes`; trailer is `HMAC-SHA256(mac_key, complete_header || ciphertext)`. There is no computationally independent key-exchange mechanism; pad must be distributed offline. This construction is labeled OTP-style, not as an unconditional perfect-secrecy system. A local SQLite ledger stores SHA256(first 32 pad bytes) for reuse checks.

## Historical educational format

`ciphertext = selected byte-adapted historical transformation(compressed_zip)`. Trailer `SHA256(complete_header || ciphertext)`. This checksum is unkeyed; anyone can forge it, and no confidentiality or integrity against attackers is claimed.

## Compression / payload contents

Before encryption, the selected files/folders are packaged into an **inner uncompressed ZIP** with relative paths. The ZIP byte stream is then optionally compressed using zlib, LZMA, Bzip2 or Zstandard. Decryption reverses the selected compression and then checks the ZIP paths before extraction. These are successive **layers**, not ordinary ZIP AES encryption.

## Compatibility and versioning

Only CWBOX `version=1` is recognized. Changes to the AAD, key derivation or framing require a new format version. Renaming an encrypted file to `.pdf` or another extension does not change its internal format or magically make it compatible with that type.

**Product rename compatibility:** CASSipher retains `CWBOX1\r\n` and the `.cwbox` extension to decrypt earlier v0.1.0 files; only branding/package names changed.
