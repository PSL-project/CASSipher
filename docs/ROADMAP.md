# Development roadmap

## Implemented — v0.1.0 research preview

- Windows-first offline GUI with three tabs and method catalog.
- Three modern authenticated password ciphers, plus five historical byte adaptations.
- OTP-style pad XOR with HMAC and local reuse registry.
- Versioned native format with robust end-of-stream authentication for modern methods.
- Inner ZIP packaging + optional compression; import, output-format settings, validation.
- Tests, source packaging, GitHub workflows and Windows EXE build script.

## Priority 1 — Production-hardening

- Eliminate *all* plaintext disk staging via direct streaming package+compression+encryption and authenticated stream-to-staged-extraction design.
- Independent security audit and format review; test vectors, fuzz testing, reproducible release builds, signed executable, tamper-safe upgrades.
- Safe Windows folder/clipboard integration, stable large-file cancel/resume semantics, screenreader/accessibility review.
- Improve password-strength guidance and handling of volatile key material.

## Priority 2 — More algorithms

- XChaCha20-Poly1305 using vetted libsodium bindings.
- SHA-2/SHA-3/BLAKE3 utilities, scrypt / configurable Argon2id with bounded resource limits.
- ML-KEM hybrid public-key encryption and recipient identities, post-quantum interoperability tests.
- AES-GCM-SIV and other well-analyzed constructions where library support is stable.
- Historical Enigma/M-209/Playfair/Hill and interactive step-by-step visualizations.

## Priority 3 — Compression & advanced lab

- Zstd in built binary, LZ4 and Brotli; measured compression benchmark dashboard (initial auto-select already compares existing codecs).
- Optional authenticated outer-layer packaging with post-encryption compression (likely no meaningful savings).
- Advanced reversible operation chains strictly separated from secure defaults.
- File-format converters: PGP/age/ZIP where technical and legal compatibility supports it.
- Measured speed/compression dashboards, algorithm-reference bibliography and export.

## Priority 4 — Distribution

- Windows signed installer and versioned GitHub releases.
- Android port only when the Windows core is stable; shared format and interoperability tests.
