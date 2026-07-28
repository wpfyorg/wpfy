from __future__ import annotations

import errno
from io import BytesIO
import os
from pathlib import Path
import stat

import pytest


def _seed_site(paths, domain: str = "files.example", uid: int = 1806) -> Path:
    site = Path(paths.sites_dir) / domain
    app = site / "app"
    app.mkdir(parents=True)
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / ".env").write_text(f"DOMAIN={domain}\nSITE_UID={uid}\n", encoding="utf-8")
    return app


def test_resolve_in_jail_rejects_hostile_paths(tmp_wpfy_home):
    from wpfy.files import resolve_in_jail

    app = _seed_site(tmp_wpfy_home)
    (app / "nested").mkdir()
    assert resolve_in_jail("files.example", "./nested//file.txt") == app / "nested" / "file.txt"

    for path in ("..", "../.env", "nested/../../.env", "/etc/passwd", "//etc/passwd", "a/./b", "x\x00y"):
        with pytest.raises(ValueError):
            resolve_in_jail("files.example", path)


def test_resolve_in_jail_refuses_symlink_components_inside_and_outside(tmp_wpfy_home):
    from wpfy.files import resolve_in_jail

    app = _seed_site(tmp_wpfy_home)
    (app / "nested").mkdir()
    (app / "nested" / "safe.txt").write_text("safe\n", encoding="utf-8")
    os.symlink("nested", app / "inside")
    os.symlink("../.env", app / "outside")

    for path in ("inside", "inside/safe.txt", "outside"):
        with pytest.raises(ValueError, match="symlink"):
            resolve_in_jail("files.example", path)


def test_list_reports_symlinks_without_following(tmp_wpfy_home):
    from wpfy.files import list_files

    app = _seed_site(tmp_wpfy_home)
    (app / "folder").mkdir()
    (app / "file.txt").write_text("hello", encoding="utf-8")
    os.symlink("file.txt", app / "link")

    result = list_files("files.example")
    entries = {entry["name"]: entry for entry in result["entries"]}
    assert result["path"] == ""
    assert [entry["name"] for entry in result["entries"]][:1] == ["folder"]
    assert entries["folder"]["type"] == "dir"
    assert entries["file.txt"]["type"] == "file"
    assert entries["link"]["type"] == "symlink"
    assert entries["file.txt"]["mode"].startswith("0")


def test_read_write_upload_and_download(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    (app / "nested").mkdir()

    assert files.write_file("files.example", "nested/edit.txt", "edited\n") == {"path": "nested/edit.txt"}
    assert files.read_file("files.example", "nested/edit.txt")["content"] == "edited\n"

    payload = bytes(range(256)) * 4
    assert files.upload_file("files.example", "nested/plugin.zip", BytesIO(payload), len(payload))["size"] == len(payload)
    download = files.open_download("files.example", "nested/plugin.zip")
    with download.stream:
        assert download.stream.read() == payload
    assert download.name == "plugin.zip"
    assert download.size == len(payload)


def test_editor_and_upload_caps_refuse_without_truncating(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    monkeypatch.setattr(files, "MAX_EDIT_BYTES", 8)
    monkeypatch.setattr(files, "MAX_UPLOAD_BYTES", 10)
    app = _seed_site(tmp_wpfy_home)
    (app / "large.txt").write_text("123456789", encoding="utf-8")

    with pytest.raises(ValueError, match="editor limit"):
        files.read_file("files.example", "large.txt")
    with pytest.raises(ValueError, match="editor limit"):
        files.write_file("files.example", "write.txt", "123456789")
    with pytest.raises(ValueError, match="upload"):
        files.upload_file("files.example", "upload.bin", BytesIO(b"x"), 11)
    assert not (app / "upload.bin").exists()


def test_special_file_target_opens_are_nonblocking(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    app = _seed_site(tmp_wpfy_home)
    os.mkfifo(app / "pipe")
    original_open = files.os.open
    flags_seen = []

    def recording_open(path, flags, *args, **kwargs):
        if path == "pipe":
            flags_seen.append(flags)
            raise OSError(errno.EINVAL, "recorded target open")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(files.os, "open", recording_open)
    with pytest.raises(OSError, match="recorded target open"):
        files._open_target_fd("files.example", "pipe", os.O_RDONLY)
    assert flags_seen == [os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK]


@pytest.mark.parametrize("error", [errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP])
def test_rename_noreplace_falls_back_when_linux_filesystem_rejects_flag(monkeypatch, error):
    import wpfy.files as files

    class UnsupportedRename:
        def __call__(self, *args):
            ctypes.set_errno(error)
            return -1

    class FakeLibc:
        renameat2 = UnsupportedRename()

    import ctypes

    recorded = []
    monkeypatch.setattr(files.sys, "platform", "linux")
    monkeypatch.setattr(files.ctypes, "CDLL", lambda *args, **kwargs: FakeLibc())
    monkeypatch.setattr(
        files.os,
        "rename",
        lambda source, target, **kwargs: recorded.append((source, target, kwargs)),
    )

    files._rename_noreplace(3, "source.txt", 4, "target.txt")

    assert recorded == [("source.txt", "target.txt", {"src_dir_fd": 3, "dst_dir_fd": 4})]


def test_mkdir_rename_chmod_and_delete_confirmation(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    (app / "source.txt").write_text("source\n", encoding="utf-8")

    files.make_directory("files.example", "tree")
    files.rename_path("files.example", "source.txt", "tree/renamed.txt")
    files.chmod_path("files.example", "tree/renamed.txt", "0640")
    assert stat.S_IMODE((app / "tree" / "renamed.txt").stat().st_mode) == 0o640

    for mode in (644, "0777", "4755", "0o644", "0644 "):
        with pytest.raises(ValueError):
            files.chmod_path("files.example", "tree/renamed.txt", mode)

    with pytest.raises(ValueError, match="tree"):
        files.delete_path("files.example", "tree")
    assert (app / "tree" / "renamed.txt").exists()
    files.delete_path("files.example", "tree", confirm="tree")
    assert not (app / "tree").exists()


def test_delete_accepts_unneeded_confirmation(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    (app / "file.txt").write_text("x", encoding="utf-8")
    (app / "empty").mkdir()

    files.delete_path("files.example", "file.txt", confirm="anything")
    files.delete_path("files.example", "empty", confirm="anything")
    assert not (app / "file.txt").exists()
    assert not (app / "empty").exists()


def test_created_paths_are_chowned_to_site_uid(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    app = _seed_site(tmp_wpfy_home, uid=1806)
    monkeypatch.delenv("WPFY_SKIP_CHOWN", raising=False)
    monkeypatch.setattr(files.os, "geteuid", lambda: 0)
    recorded = []
    monkeypatch.setattr(files.os, "fchown", lambda fd, uid, gid: recorded.append((uid, gid)))
    monkeypatch.setattr(files.os, "chown", lambda path, uid, gid, **kwargs: recorded.append((uid, gid)))

    files.write_file("files.example", "owned.txt", "owned\n")
    files.upload_file("files.example", "owned.bin", BytesIO(b"owned"), 5)
    files.make_directory("files.example", "owned-dir")

    assert recorded == [(1806, 1806), (1806, 1806), (1806, 1806)]
    assert (app / "owned.txt").exists()


def test_site_files_cli_roundtrip(tmp_wpfy_home, tmp_path, monkeypatch):
    from wpfy.cli import build_parser

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    (app / "hello.txt").write_text("hello\n", encoding="utf-8")
    source = tmp_path / "source.bin"
    source.write_bytes(b"uploaded")
    parser = build_parser()

    listed = parser.parse_args(["site", "files", "files.example", "ls"])
    assert listed.handler(listed).exit_code == 0
    assert "hello.txt" in listed.handler(listed).message

    read = parser.parse_args(["site", "files", "files.example", "cat", "hello.txt"])
    assert read.handler(read).message == "hello\n"

    put = parser.parse_args([
        "site", "files", "files.example", "put", "upload.bin", "--content-file", str(source),
    ])
    assert put.handler(put).exit_code == 0
    assert (app / "upload.bin").read_bytes() == b"uploaded"

    remove = parser.parse_args(["site", "files", "files.example", "rm", "upload.bin"])
    assert remove.handler(remove).exit_code == 0
    assert not (app / "upload.bin").exists()


def test_parent_symlink_swap_after_resolution_is_refused(tmp_wpfy_home, monkeypatch):
    import wpfy.files as files

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    nested = app / "nested"
    nested.mkdir()
    env_file = app.parent / ".env"
    before = env_file.read_bytes()
    original = files.resolve_in_jail

    def swap_parent(domain, rel_path):
        result = original(domain, rel_path)
        nested.rename(app / "nested-real")
        os.symlink("..", nested)
        return result

    monkeypatch.setattr(files, "resolve_in_jail", swap_parent)
    with pytest.raises(ValueError, match="unsafe path component"):
        files.write_file("files.example", "nested/.env", "escaped\n")
    assert env_file.read_bytes() == before


def test_site_files_cat_preserves_exact_output(tmp_wpfy_home, monkeypatch, capsys):
    from wpfy.cli import run

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    (app / "hello.txt").write_text("hello\n", encoding="utf-8")

    assert run(["site", "files", "files.example", "cat", "hello.txt"]) == 0
    assert capsys.readouterr().out == "hello\n"


def test_site_files_ls_escapes_terminal_control_characters(tmp_wpfy_home, monkeypatch):
    from wpfy.cli import build_parser

    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    app = _seed_site(tmp_wpfy_home)
    hostile = "line\n\x1b[31m.txt"
    (app / hostile).write_text("x", encoding="utf-8")

    args = build_parser().parse_args(["site", "files", "files.example", "ls"])
    message = args.handler(args).message
    assert hostile not in message
    assert "line\\n\\x1b[31m.txt" in message
