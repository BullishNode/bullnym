#!/usr/bin/env python3
"""Hash a release content tree exactly like Bullnym's build.rs."""

import hashlib
import os
import pathlib
import stat
import sys


def fail(message: str) -> None:
    raise SystemExit(f"content hash failed: {message}")


if len(sys.argv) != 2:
    fail(f"usage: {sys.argv[0]} DIRECTORY")

root = pathlib.Path(sys.argv[1]).resolve()
if not root.is_dir():
    fail(f"directory is missing: {root}")

files: list[pathlib.Path] = []
for directory, directory_names, file_names in os.walk(root, followlinks=False):
    base = pathlib.Path(directory)
    for name in directory_names:
        path = base / name
        if path.is_symlink():
            fail(f"content must not contain symlinks: {path}")
    for name in file_names:
        path = base / name
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            fail(f"content must not contain symlinks: {path}")
        if not stat.S_ISREG(mode):
            fail(f"content must contain only regular files: {path}")
        files.append(path.relative_to(root))

digest = hashlib.sha256()
for relative in sorted(files, key=lambda path: path.as_posix()):
    encoded_path = relative.as_posix().encode("utf-8")
    contents = (root / relative).read_bytes()
    digest.update(len(encoded_path).to_bytes(8, "big"))
    digest.update(encoded_path)
    digest.update(len(contents).to_bytes(8, "big"))
    digest.update(contents)

print(digest.hexdigest())
