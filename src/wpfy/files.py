from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import BinaryIO

from .site_layout import chown_skip_requested
from .site_paths import app_dir, env_path, read_env, site_exists, validate_domain


MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_EDIT_BYTES = 1024 * 1024
ALLOWED_MODES = {"0600", "0640", "0644", "0700", "0750", "0755"}
_CHUNK_BYTES = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


@dataclass(frozen=True)
class Download:
    name: str
    size: int
    stream: BinaryIO


def _path_parts(rel_path: str) -> tuple[str, ...]:
    if not isinstance(rel_path, str):
        raise ValueError("path must be a string")
    if "\x00" in rel_path:
        raise ValueError("path contains a NUL byte")
    if rel_path.startswith("/"):
        raise ValueError("absolute paths are not allowed")

    parts = rel_path.split("/")
    while parts and parts[0] == ".":
        parts.pop(0)
    parts = [part for part in parts if part]
    if any(part == ".." for part in parts):
        raise ValueError("parent path components are not allowed")
    if any(part == "." for part in parts):
        raise ValueError("path must be plain and relative")
    return tuple(parts)


def normalise_path(rel_path: str) -> str:
    return "/".join(_path_parts(rel_path))


def _open_directory(path: Path | str, *, dir_fd: int | None = None) -> int:
    try:
        return os.open(path, _DIRECTORY_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError(f"unsafe path component: {path}") from None
        raise


def resolve_in_jail(domain: str, rel_path: str) -> Path:
    validate_domain(domain)
    if not site_exists(domain):
        raise FileNotFoundError(f"site not found: {domain}")

    root = app_dir(domain)
    try:
        root_metadata = os.lstat(root)
    except FileNotFoundError:
        raise FileNotFoundError(f"site app directory not found: {domain}") from None
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("site app directory is unsafe")

    parts = _path_parts(rel_path)
    candidate = root.joinpath(*parts)
    directory_fd = _open_directory(root)
    try:
        for index, part in enumerate(parts):
            try:
                metadata = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                break
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"symlink path component is not allowed: {part}")
            if index < len(parts) - 1:
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError("path contains a non-directory component")
                child_fd = _open_directory(part, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
    finally:
        os.close(directory_fd)

    root_real = os.path.realpath(root)
    candidate_real = os.path.realpath(candidate)
    if os.path.commonpath((root_real, candidate_real)) != root_real:
        raise ValueError("path escapes the site app directory")
    return candidate


def _open_parent_fd(domain: str, rel_path: str) -> tuple[int, str]:
    resolve_in_jail(domain, rel_path)
    parts = _path_parts(rel_path)
    if not parts:
        raise ValueError("the site app directory itself cannot be modified")
    directory_fd = _open_directory(app_dir(domain))
    try:
        for part in parts[:-1]:
            child_fd = _open_directory(part, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
    except Exception:
        os.close(directory_fd)
        raise
    return directory_fd, parts[-1]


def _open_target_fd(domain: str, rel_path: str, flags: int) -> int:
    resolve_in_jail(domain, rel_path)
    parts = _path_parts(rel_path)
    directory_fd = _open_directory(app_dir(domain))
    if not parts:
        return directory_fd
    try:
        for part in parts[:-1]:
            child_fd = _open_directory(part, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        try:
            target_fd = os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError(f"unsafe path component: {parts[-1]}") from None
            raise
    finally:
        os.close(directory_fd)
    return target_fd


def _site_uid(domain: str) -> int:
    value = read_env(env_path(domain)).get("SITE_UID", "")
    if not value.isdigit():
        raise ValueError("site has no valid SITE_UID")
    return int(value)


def _chown_fd(domain: str, fd: int) -> None:
    if chown_skip_requested() or (hasattr(os, "geteuid") and os.geteuid() != 0):
        return
    uid = _site_uid(domain)
    os.fchown(fd, uid, uid)


def _chown_at(domain: str, directory_fd: int, name: str) -> None:
    if chown_skip_requested() or (hasattr(os, "geteuid") and os.geteuid() != 0):
        return
    uid = _site_uid(domain)
    os.chown(name, uid, uid, dir_fd=directory_fd, follow_symlinks=False)


def _require_non_root(rel_path: str) -> str:
    normalised = normalise_path(rel_path)
    if not normalised:
        raise ValueError("the site app directory itself cannot be modified")
    return normalised


def _entry_type(metadata: os.stat_result) -> str:
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    if stat.S_ISDIR(metadata.st_mode):
        return "dir"
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    return "other"


def list_files(domain: str, rel_path: str = "") -> dict:
    directory_fd = _open_target_fd(domain, rel_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        entries = []
        with os.scandir(directory_fd) as children:
            for child in children:
                metadata = child.stat(follow_symlinks=False)
                entries.append({
                    "name": child.name,
                    "type": _entry_type(metadata),
                    "size": metadata.st_size,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "modified": int(metadata.st_mtime),
                })
    finally:
        os.close(directory_fd)
    entries.sort(key=lambda entry: (entry["type"] != "dir", entry["name"].casefold(), entry["name"]))
    return {"path": normalise_path(rel_path), "entries": entries}


def _read_limited(fd: int, limit: int) -> bytes:
    chunks = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(_CHUNK_BYTES, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > limit:
        raise ValueError(f"file exceeds the {limit}-byte editor limit")
    return b"".join(chunks)


def read_file(domain: str, rel_path: str) -> dict:
    fd = _open_target_fd(domain, rel_path, os.O_RDONLY)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("path is not a regular file")
        if metadata.st_size > MAX_EDIT_BYTES:
            raise ValueError(f"file exceeds the {MAX_EDIT_BYTES}-byte editor limit")
        data = _read_limited(fd, MAX_EDIT_BYTES)
    finally:
        os.close(fd)
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("file is not valid UTF-8 text") from None
    return {"path": normalise_path(rel_path), "content": content}


def _target_mode(directory_fd: int, name: str) -> int:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return 0o644
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"symlink path component is not allowed: {name}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("path is not a regular file")
    return stat.S_IMODE(metadata.st_mode)


def _replace_from_writer(domain: str, directory_fd: int, name: str, writer) -> None:
    mode = _target_mode(directory_fd, name)
    temp_name = ""
    temp_fd = -1
    for _ in range(10):
        temp_name = f".{name}.{secrets.token_hex(8)}"
        try:
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            break
        except FileExistsError:
            continue
    if temp_fd < 0:
        raise OSError("failed to allocate a temporary file")
    try:
        os.fchmod(temp_fd, mode)
        writer(temp_fd)
        os.fsync(temp_fd)
        _chown_fd(domain, temp_fd)
        os.close(temp_fd)
        temp_fd = -1
        os.replace(temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    except Exception:
        if temp_fd >= 0:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def write_file(domain: str, rel_path: str, content: str) -> dict:
    _require_non_root(rel_path)
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    data = content.encode("utf-8")
    if len(data) > MAX_EDIT_BYTES:
        raise ValueError(f"content exceeds the {MAX_EDIT_BYTES}-byte editor limit")
    directory_fd, name = _open_parent_fd(domain, rel_path)

    def writer(fd: int) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]

    try:
        _replace_from_writer(domain, directory_fd, name, writer)
    finally:
        os.close(directory_fd)
    return {"path": normalise_path(rel_path)}


def upload_file(domain: str, rel_path: str, stream: BinaryIO, content_length: int) -> dict:
    _require_non_root(rel_path)
    if not isinstance(content_length, int) or content_length < 0:
        raise ValueError("invalid upload length")
    if content_length > MAX_UPLOAD_BYTES:
        raise ValueError(f"upload exceeds the {MAX_UPLOAD_BYTES}-byte limit")
    directory_fd, name = _open_parent_fd(domain, rel_path)

    def writer(fd: int) -> None:
        remaining = content_length
        while remaining:
            chunk = stream.read(min(_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("upload body ended before Content-Length")
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            remaining -= len(chunk)

    try:
        _replace_from_writer(domain, directory_fd, name, writer)
    finally:
        os.close(directory_fd)
    return {"path": normalise_path(rel_path), "size": content_length}


def open_download(domain: str, rel_path: str) -> Download:
    fd = _open_target_fd(domain, rel_path, os.O_RDONLY)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("path is not a regular file")
        stream = os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise
    return Download(name=_path_parts(rel_path)[-1], size=metadata.st_size, stream=stream)


def make_directory(domain: str, rel_path: str) -> dict:
    _require_non_root(rel_path)
    directory_fd, name = _open_parent_fd(domain, rel_path)
    try:
        try:
            os.mkdir(name, 0o755, dir_fd=directory_fd)
        except FileExistsError:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(
                    f"path already exists and is not a directory: {normalise_path(rel_path)}"
                ) from None
        else:
            _chown_at(domain, directory_fd, name)
    finally:
        os.close(directory_fd)
    return {"path": normalise_path(rel_path)}


def _rename_noreplace(source_fd: int, source_name: str, target_fd: int, target_name: str) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                source_fd,
                os.fsencode(source_name),
                target_fd,
                os.fsencode(target_name),
                1,
            )
            if result == 0:
                return
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise ValueError(f"destination already exists: {target_name}")
            if error not in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
                raise OSError(error, os.strerror(error), target_name)
    os.rename(source_name, target_name, src_dir_fd=source_fd, dst_dir_fd=target_fd)


def rename_path(domain: str, rel_path: str, to_path: str) -> dict:
    source_normalised = _require_non_root(rel_path)
    target_normalised = _require_non_root(to_path)
    if source_normalised == target_normalised:
        return {"path": target_normalised}
    source_fd, source_name = _open_parent_fd(domain, rel_path)
    try:
        target_fd, target_name = _open_parent_fd(domain, to_path)
        try:
            source_metadata = os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
            if stat.S_ISLNK(source_metadata.st_mode):
                raise ValueError(f"symlink path component is not allowed: {source_name}")
            try:
                os.stat(target_name, dir_fd=target_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError(f"destination already exists: {target_normalised}")
            _rename_noreplace(source_fd, source_name, target_fd, target_name)
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)
    return {"path": target_normalised}


def _remove_tree(parent_fd: int, name: str) -> None:
    directory_fd = _open_directory(name, dir_fd=parent_fd)
    try:
        with os.scandir(directory_fd) as iterator:
            entries = list(iterator)
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                _remove_tree(directory_fd, entry.name)
            else:
                os.unlink(entry.name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def delete_path(domain: str, rel_path: str, confirm: str | None = None) -> dict:
    normalised = _require_non_root(rel_path)
    directory_fd, name = _open_parent_fd(domain, rel_path)
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"symlink path component is not allowed: {name}")
        if stat.S_ISDIR(metadata.st_mode):
            target_fd = _open_directory(name, dir_fd=directory_fd)
            try:
                with os.scandir(target_fd) as entries:
                    non_empty = next(entries, None) is not None
            finally:
                os.close(target_fd)
            if non_empty:
                if confirm != name:
                    raise ValueError(f"type {name!r} to delete this non-empty directory")
                _remove_tree(directory_fd, name)
            else:
                os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    return {"path": normalised}


def chmod_path(domain: str, rel_path: str, mode: str) -> dict:
    _require_non_root(rel_path)
    if not isinstance(mode, str) or mode not in ALLOWED_MODES:
        raise ValueError("mode must be one of: " + ", ".join(sorted(ALLOWED_MODES)))
    fd = _open_target_fd(domain, rel_path, os.O_RDONLY)
    try:
        os.fchmod(fd, int(mode, 8))
    finally:
        os.close(fd)
    return {"path": normalise_path(rel_path), "mode": mode}
