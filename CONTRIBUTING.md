# Contributing

Thanks for improving CASSipher. Please open a GitHub issue before large changes. Keep cryptographic processing separate from the GUI. Any new encryption method must document its intended security status and include published test vectors and authenticated streaming tests where applicable. Mark incomplete methods **Planned**.

Local checks:

```sh
python -m pip install -e '.[full]'
python -m unittest discover -s tests -v
python -m compileall -q src main.py
```

Do not commit secret keys, sample private files, plaintext captures, or `.venv`. Use `ruff`/typing as desired; style changes should not obscure algorithm logic. File-format changes must include migration/compatibility notes and a version bump. Treat the custom format as unstable until v1.0. Send security issues privately under SECURITY.md.
