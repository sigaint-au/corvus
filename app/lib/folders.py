"""S3-style folder/key path utilities for secrets (pure, no DB)."""
import re

_SEGMENT_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
_HAS_ALNUM_RE = re.compile(r'[A-Za-z0-9]')
_MAX_DEPTH = 16


def split_key(key: str) -> tuple[str | None, str]:
    """Split a secret key into (folder_path | None, leaf)."""
    if not key:
        return None, ''
    if '/' not in key:
        return None, key
    idx = key.rindex('/')
    folder = key[:idx]
    leaf = key[idx + 1:]
    return folder, leaf


def join_key(folder_path: str | None, leaf: str) -> str:
    """Join a folder path and leaf back into a full secret key."""
    if folder_path:
        return f'{folder_path}/{leaf}'
    return leaf


def segments(path: str) -> list[str]:
    """Split a folder path into its segments."""
    raw = path.strip('/')
    if not raw:
        return []
    return raw.split('/')


def validate_path(path: str) -> str:
    """Normalize and validate a folder path, or raise ValueError."""
    norm = path.strip('/')
    if not norm:
        raise ValueError('Path cannot be empty')
    segs = norm.split('/')
    if len(segs) > _MAX_DEPTH:
        raise ValueError(f'Path exceeds maximum depth of {_MAX_DEPTH}')
    for s in segs:
        if not _SEGMENT_RE.match(s):
            raise ValueError(f'Invalid segment: {s!r}')
        if '..' in s or not _HAS_ALNUM_RE.search(s):
            raise ValueError(f'Invalid segment: {s!r}')
    if len(segs) == 1 and path != norm:
        raise ValueError(f'Invalid path: {path!r}')
    return norm


def validate_key(key: str) -> str:
    """Validate a full secret key (folder path + leaf), or raise ValueError."""
    root, leaf = split_key(key)
    if root:
        validate_path(root)
    if not leaf or not _SEGMENT_RE.match(leaf):
        raise ValueError(f'Invalid leaf name: {leaf!r}')
    return key
