import pytest

from wpfy.site_paths import read_env


def test_read_env_preserves_format_contract(tmp_path):
    path = tmp_path / "config.env"
    path.write_text("# comment\n\nA=one\nmalformed\nB= two = three \n", encoding="utf-8")

    assert read_env(path) == {"A": "one", "B": " two = three "}
    assert read_env(tmp_path / "missing.env") == {}


def test_read_env_refuses_file_symlink(tmp_path):
    external = tmp_path / "external.env"
    external.write_text("SECRET=outside\n", encoding="utf-8")
    link = tmp_path / "config.env"
    link.symlink_to(external)

    with pytest.raises(OSError):
        read_env(link)

    assert external.read_text(encoding="utf-8") == "SECRET=outside\n"


def test_read_env_refuses_parent_symlink(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    (external / "config.env").write_text("SECRET=outside\n", encoding="utf-8")
    link = tmp_path / "linked"
    link.symlink_to(external, target_is_directory=True)

    with pytest.raises(OSError):
        read_env(link / "config.env")
