# Security policy

## Project security status

**Version 0.1.1 is a research preview, not a security-audited product.** Its custom file format and implementations have not been independently reviewed. It is inappropriate to use as the sole protection for critical or highly sensitive information.

### Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x | Best-effort development support only |

### Confidentiality notes

The library uses established cryptographic primitives from `cryptography` for AES-GCM, ChaCha20-Poly1305 and Argon2id. **Composition, file parsing, key handling and UI code are project-specific** and may contain defects. It also creates plaintext temporary files on disk, which may persist after deletion or a crash.

Non-AEAD educational ciphers (Caesar, affine, Atbash, Vigenère, rail fence) use an **unkeyed SHA-256 checksum only**, providing no cryptographic authentication and no confidentiality against real attackers.

The OTP-style feature uses OS CSPRNG output and 32 additional independent random bytes for HMAC-SHA256. It is *not* asserted to provide information-theoretic security. The pad ledger is local and a key should never be used to encrypt more than one container.

### Responsible reporting

If you discover a suspected vulnerability, please avoid publishing keys, ciphertext, sensitive files, or exploit details in a public GitHub issue. Open a private repository security advisory if the GitHub repository has security advisories enabled. Otherwise contact the maintainer through a private channel listed on the repository profile. This project does not promise a specific response SLA.

### Threat model and scope

The target threat is casual offline access to an encrypted container while the password or key remains private. The project does not protect against malware, side-channel attacks, memory forensics, device seizure, compromised operating systems, password theft, synchronized pad reuse, or plaintext remnants on local storage. No telemetry or server-side file processing is used.

### Operating guidance

- Use a unique high-entropy passphrase (longer than the minimum 10 characters).
- Keep secure backups of plaintext while testing this preview.
- Restore and compare data before deleting source files.
- Never put an OTP pad beside the ciphertext in the same public archive.
- Never reuse pads, including after canceled operations.
- Validate downloads and source of EXEs; GitHub Actions build output is not digitally signed.
- Keep dependencies up to date and check third-party license obligations.
