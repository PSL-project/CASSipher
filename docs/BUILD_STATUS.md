# Initial development verification — 2026-10-28

The Python cryptographic engine was exercised in a Linux environment using Python 3.13 and `cryptography` 46.0.4. Built-in unit tests are configured for Windows and Linux through GitHub Actions. The application’s Tkinter windows were opened under a virtual X11 server for layout smoke tests, and the three UI previews under `assets/` were captured in that environment.

**Not yet verified:** `.exe` execution on Windows, Windows drag/drop, Windows installer, optional zstandard integration (package not installed in development environment), or a formal cryptographic audit. The GitHub Windows EXE workflow is supplied, but no Windows binary is included with this source release.

**Known security blocker for serious use:** plaintext staging files are created on disk before encryption and after decryption. The priority post-preview improvement is a streaming processing pipeline with no temporary plaintext archives.

To reproduce tests:

```
python -m pip install -e .
python -m unittest discover -s tests -v
```

CASSipher v0.1.1 updates product branding, package name, and Windows build artifact names; the original v1 file format remains unchanged.
