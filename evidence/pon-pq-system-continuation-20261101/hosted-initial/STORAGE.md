# Lossless CI evidence storage

Large UTF-8 evidence files and original files with significant trailing whitespace use gzip (zero mtime) plus Base64 for source-backed Git-data publication. Original logs and patch context are never trimmed. This is not an evidence reduction or a new execution. Every encoded file has both stored-byte and original-byte SHA-256, sizes and a path in `manifest.json`. The original provenance manifest is retained as `manifest.json.gz.b64`.

Restore into a new directory:

```text
python3 restore.py --output /absolute/path/to/new-evidence-directory
python3 /absolute/path/to/new-evidence-directory/recheck.py --repo /absolute/path/to/exact-candidate-checkout
```

`README.md` explains the actual failures and limitations. The stored files contain no original artifact ZIP, ELF executable or SQLite database.
