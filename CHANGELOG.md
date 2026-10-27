# Changelog

## 0.1.1 — 2026-10-28

- Renamed the project, interface, Python package, command-line entrypoints, Windows executable, and GitHub artifacts to **CASSipher** (Cassander Cipher).
- Preserved the `CWBOX1` container format and `.cwbox` extension for v0.1.0 decryption compatibility.
- Preserved the legacy OTP pad-reuse ledger path to retain prior reuse protection.
- No cryptographic algorithm changes.


## 0.1.0 — 2026-10-28

Initial Windows-first research preview:

- Three-tab Tkinter desktop GUI and method library.
- AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 using Argon2id KDF.
- Optional compression and packaged folders, auto-detecting native CWBOX v1 format.
- OTP-style pad-file and local reuse ledger.
- Five historical byte-oriented, insecure cipher modes.
- Authentication / corruption handling and defensive ZIP extraction.
- CLI, automated unit tests, source and Windows GitHub Actions build workflows.

Known limitations: no independent audit; plaintext staging files; no actual Windows EXE verification in Linux development environment; no Android build.
