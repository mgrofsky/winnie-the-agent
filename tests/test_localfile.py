"""Reading a small file another container wrote (agents/localfile.py)."""

from __future__ import annotations

import errno
import os

import pytest

from agents.localfile import NotRegularFile, read_regular


def test_a_regular_file_reads_as_open_would(tmp_path):
    path = tmp_path / "f"
    path.write_bytes(b"0123456789")
    assert read_regular(path, 100) == b"0123456789"
    # At most cap + 1 bytes, so the caller can tell an oversize file.
    assert read_regular(path, 4) == b"01234"
    path.write_bytes(b"")
    assert read_regular(path, 4) == b""


def test_missing_is_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_regular(tmp_path / "nothing", 10)


def test_a_fifo_is_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(NotRegularFile):
        read_regular(tmp_path / "fifo", 10)


def test_a_directory_is_refused(tmp_path):
    (tmp_path / "dir").mkdir()
    with pytest.raises(OSError) as info:
        read_regular(tmp_path / "dir", 10)
    assert not isinstance(info.value, FileNotFoundError)


@pytest.mark.parametrize("target", ["file", "missing", "fifo"])
def test_a_symlink_is_not_followed(tmp_path, target):
    real = tmp_path / "real"
    if target == "file":
        real.write_bytes(b"secret")
    elif target == "fifo":
        os.mkfifo(real)
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(OSError) as info:
        read_regular(tmp_path / "link", 10)
    assert not isinstance(info.value, FileNotFoundError)
    assert info.value.errno == errno.ELOOP     # O_NOFOLLOW on Linux and macOS


def test_not_regular_is_an_os_error():
    # Callers already treat OSError as "unreadable"; this keeps them doing so.
    assert issubclass(NotRegularFile, OSError)
