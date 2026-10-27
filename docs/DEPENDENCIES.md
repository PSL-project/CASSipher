# Third-party dependencies and licensing

The repository's own code is MIT licensed, but a standalone executable also bundles third-party libraries and possibly Tcl/Tk. Check their license notices before publication. Dependencies include:

- [`cryptography`](https://cryptography.io/en/latest/) (Apache-2.0 or BSD variants, depending on component), including OpenSSL-related obligations when packaged.
- Python and Tkinter/Tcl/Tk runtime (Python Software Foundation and Tcl/Tk licensing terms).
- Optional [`zstandard`](https://github.com/indygreg/python-zstandard) Python package (BSD licensing; includes zstd C library).
- Optional [`tkinterdnd2`](https://github.com/pmgagne/tkinterdnd2) and its underlying TkDND library (review installed distributions' notices).
- Development-time PyInstaller (GPL with special bootloader exception, subject to its license).

The above is a checklist, not a legal opinion or exhaustive license inventory. Preserve applicable attribution and license text when shipping compiled binary artifacts. A release build should generate a bill of materials and include applicable third-party notices.
