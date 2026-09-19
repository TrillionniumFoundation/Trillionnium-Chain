"""Narrow, content-bound Git documentation aliases for source archives.

Only a direct relative Markdown alias to a non-executable regular Markdown
file in the same tracked inventory is accepted. No filesystem resolution or
link following is performed by this validator.
"""
from __future__ import annotations
import pathlib
import posixpath

LINK_MODE = 0o120000


def validate_alias(path: str, data: bytes, modes: dict[str, int]) -> str:
    if not path.startswith('docs/') or not path.endswith('.md') or modes.get(path) != LINK_MODE:
        raise ValueError('source aliases are limited to tracked Markdown docs')
    if not 0 < len(data) <= 4096:
        raise ValueError('documentation alias target length differs')
    target = data.decode('utf-8')
    if any(c in target for c in ('\x00','\n','\r','\\')) or target.startswith('/'):
        raise ValueError('documentation alias target must be a relative canonical path')
    pure = pathlib.PurePosixPath(target)
    if pure.as_posix() != target or not pure.parts or any(p == '.' for p in pure.parts):
        raise ValueError('documentation alias target is not canonical')
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if not resolved.startswith('docs/') or not resolved.endswith('.md') or modes.get(resolved) != 0o644:
        raise ValueError('documentation alias target must be one tracked non-executable regular Markdown document')
    # The complete inventory also forbids an alias as any path's parent.
    for parent in pathlib.PurePosixPath(resolved).parents:
        if str(parent) in modes:
            raise ValueError('documentation alias traverses a file or link')
    return resolved
