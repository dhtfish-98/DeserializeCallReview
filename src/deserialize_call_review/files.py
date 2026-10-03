"""Read bounded regular local files without following any symlink component."""

import os
import stat


def read_regular_file(path, limit):
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
    directory_capabilities = getattr(os, "supports_dir_fd", None)
    directory_relative_open = (
        isinstance(directory_capabilities, (set, frozenset)) and os.open in directory_capabilities
    )
    if os.name != "posix" or any(
        type(getattr(os, flag, None)) is not int or getattr(os, flag) <= 0 for flag in required
    ):
        raise ValueError("safe_open_unsupported")
    if not directory_relative_open:
        raise ValueError("directory_relative_open_unsupported")
    name = os.fspath(path)
    if not isinstance(name, str) or not name or len(name) > 4096 or "\0" in name:
        raise ValueError("invalid_path")
    if ".." in name.split(os.sep):
        raise ValueError("parent_traversal")
    parts = os.path.abspath(name).split(os.sep)[1:]
    if not parts or not parts[-1]:
        raise ValueError("not_regular")
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("not_regular_or_byte_limit")
            chunks = []
            length = 0
            while length <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
            after = os.fstat(fd)
            if (
                length > limit
                or length != after.st_size
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
            ):
                raise ValueError("too_large_or_changed")
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
