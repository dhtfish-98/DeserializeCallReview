import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from deserialize_call_review import Limits, review_bytes, review_file
from deserialize_call_review.cli import main


@pytest.mark.parametrize(
    "data",
    [
        b"",
        "not bytes",
        b"x=\x00",
        b"x=\xff",
        b"x=(",
        b"x" * 262145,
        b"# coding: latin1\nx=1",
        b"def f(a,a):pass",
        b"def f():\n x=1\n global x",
        b"return 1",
    ],
)
def test_rejected_source_open_and_no_contents(data):
    report = review_bytes(data)
    assert report.status == "OPEN"
    assert not report.findings


@pytest.mark.parametrize(
    "limit",
    [
        Limits(max_bytes=1),
        Limits(max_nodes=1),
        Limits(max_depth=1),
        Limits(max_bindings=1),
        Limits(max_binding_updates=1),
    ],
)
def test_resource_limits_open(limit):
    report = review_bytes(b"import pickle,yaml\npickle.loads(data)", limits=limit)
    assert report.status == "OPEN"


@pytest.mark.parametrize(
    "limit",
    [
        Limits(max_findings=0),
        Limits(max_bytes=True),
        Limits(max_bytes=262145),
        Limits(max_report_bytes=100),
        None,
    ],
)
def test_invalid_limits(limit):
    assert review_bytes(b"x=1", limits=limit).status == "OPEN"


def test_scope_limit():
    report = review_bytes(b"def f():pass\ndef g():pass", limits=Limits(max_scopes=1))
    assert report.status == "OPEN"
    assert report.reason == "scope_limit"


def test_report_finding_and_byte_budgets_keep_partial_ledger():
    data = b"import pickle\n" + b"pickle.loads(data)\n" * 100
    finding_limited = review_bytes(data, limits=Limits(max_findings=2))
    byte_limited = review_bytes(data, limits=Limits(max_report_bytes=1024))
    assert finding_limited.status == byte_limited.status == "OPEN"
    assert finding_limited.truncated and byte_limited.truncated
    assert len(finding_limited.findings) == 2
    assert len(json.dumps(byte_limited.to_dict(), ensure_ascii=True).encode()) <= 1024
    assert finding_limited.review_required and byte_limited.review_required


@pytest.mark.parametrize("prefix", [b"", b"\xef\xbb\xbf"])
def test_unicode_utf8_positions_bom_and_no_literal_output(prefix):
    body = "import pickle; 秘密='PRIVATE_LITERAL_9281'; pickle.loads(data)\n".encode()
    report = review_bytes(prefix + body)
    finding = report.findings[0]
    assert (prefix + body)[finding.byte_start : finding.byte_end] == b"pickle.loads(data)"
    assert finding.column_utf8 == body.index(b"pickle.loads")
    assert finding.line == finding.end_line == 1
    assert "PRIVATE_LITERAL_9281" not in json.dumps(report.to_dict())
    assert "秘密" not in json.dumps(report.to_dict())


def test_crlf_multiline_locations_and_hash_determinism():
    data = b"import pickle\r\nx=pickle.loads(\r\n data\r\n)\r\n"
    a = review_bytes(data)
    b = review_bytes(data)
    assert a.to_dict() == b.to_dict()
    finding = a.findings[0]
    assert data[finding.byte_start : finding.byte_end] == b"pickle.loads(\r\n data\r\n)"
    assert finding.line == 2 and finding.end_line == 4
    assert len(a.source_sha256) == 64


def test_compiler_warnings_do_not_echo_literals(capsys):
    review_bytes(b"secret='\\qPRIVATE'; x is 'PRIVATE_LITERAL'\n")
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\ndef f[yaml]():\n yaml.safe_load(data)",
        "import yaml\nclass C[yaml]:\n def f(self):\n  yaml.safe_load(data)",
        "import yaml\ntype yaml = int\nyaml.safe_load(data)",
        "import yaml\n@decorate\ndef f():\n yaml.safe_load(data)",
        "import yaml\ndef f(x=callback()):\n yaml.safe_load(data)",
        "import yaml\nwith context:\n yaml.safe_load(data)",
        "import yaml\ndef f(x:yaml.safe_load(data)):\n pass",
    ],
)
def test_unsupported_scope_or_dynamic_effect_not_safety(source):
    report = review_bytes(source.encode())
    assert report.status == "OPEN"
    assert not any(f.kind == "SAFE_CALL_SHAPE" for f in report.findings)


def test_regular_file_input_unchanged(tmp_path):
    source = tmp_path / "private_filename.py"
    data = b"import pickle\npickle.loads(private_input)"
    source.write_bytes(data)
    before = source.stat()
    report = review_file(source)
    assert report.status == "REVIEW"
    assert source.read_bytes() == data
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert "private_filename" not in json.dumps(report.to_dict())
    assert "private_input" not in json.dumps(report.to_dict())


def test_symlink_parent_leaf_traversal_directory_and_limits(tmp_path):
    folder = tmp_path / "real"
    folder.mkdir()
    source = folder / "input.py"
    source.write_bytes(b"import pickle\npickle.loads(data)")
    leaf = tmp_path / "leaf.py"
    leaf.symlink_to(source)
    parent = tmp_path / "alias"
    parent.symlink_to(folder, target_is_directory=True)
    for path in [
        leaf,
        parent / "input.py",
        tmp_path,
        tmp_path / "missing",
        "bad\x00path",
        "",
        "a/../b",
    ]:
        assert review_file(path).status == "OPEN"
    assert review_file(source, limits=Limits(max_bytes=1)).status == "OPEN"


def test_fifo_device_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    before = time.monotonic()
    assert review_file(fifo).status == "OPEN"
    assert time.monotonic() - before < 1
    assert review_file("/dev/null").status == "OPEN"


def test_read_changed_input_open(tmp_path, monkeypatch):
    source = tmp_path / "input.py"
    source.write_bytes(b"x=1")
    original = os.fstat
    calls = []

    def changing(fd):
        item = original(fd)
        calls.append(fd)
        return SimpleNamespace(
            st_mode=item.st_mode,
            st_dev=item.st_dev,
            st_ino=item.st_ino,
            st_size=item.st_size,
            st_mtime_ns=item.st_mtime_ns + len(calls),
            st_ctime_ns=item.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", changing)
    assert review_file(source).status == "OPEN"


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_ctime_ns"])
def test_read_file_identity_metadata_change_open(tmp_path, monkeypatch, field):
    source = tmp_path / "input.py"
    source.write_bytes(b"x=1")
    original = os.fstat
    seen = 0

    def changed(fd):
        nonlocal seen
        seen += 1
        item = original(fd)
        fields = {
            name: getattr(item, name)
            for name in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        if seen == 2:
            fields[field] += 1
        return SimpleNamespace(**fields)

    monkeypatch.setattr(os, "fstat", changed)
    assert review_file(source).status == "OPEN"


def test_read_length_mismatch_and_dir_fd_unsupported_open(tmp_path, monkeypatch):
    source = tmp_path / "input.py"
    source.write_bytes(b"x=1")
    with monkeypatch.context() as context:
        context.setattr(os, "read", lambda *args: b"")
        assert review_file(source).status == "OPEN"
    monkeypatch.setattr(os, "supports_dir_fd", set())
    assert review_file(source).status == "OPEN"


def test_safe_open_unavailable_and_bad_pathlike_open(tmp_path, monkeypatch):
    class BadPath:
        def __fspath__(self):
            raise RuntimeError("PRIVATE_PATH")

    assert review_file(BadPath()).status == "OPEN"
    monkeypatch.delattr(os, "O_NOFOLLOW")
    assert review_file(tmp_path / "input.py").status == "OPEN"


@pytest.mark.parametrize(
    ("source", "exit_code", "status"),
    [
        (b"import yaml\nyaml.safe_load(data)", 0, "NO_REVIEW_FINDINGS"),
        (b"import pickle\npickle.loads(data)", 1, "REVIEW"),
        (b"fn(data)", 2, "OPEN"),
        (b"bad(", 2, "OPEN"),
    ],
)
def test_cli_exit_json_privacy(source, exit_code, status, tmp_path, capsys):
    path = tmp_path / "PRIVATE_PATH.py"
    path.write_bytes(source)
    assert main([str(path)]) == exit_code
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == status
    assert "PRIVATE_PATH" not in output.out
    assert output.err == ""


@pytest.mark.parametrize("args", [[], ["PRIVATE_PATH", "--execute"], ["PRIVATE_PATH", "other"]])
def test_cli_bad_args_json_open(args, capsys):
    assert main(args) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "OPEN"
    assert "PRIVATE_PATH" not in output.out + output.err


def test_module_cli_subprocess(tmp_path):
    path = tmp_path / "input.py"
    path.write_bytes(b"import pickle\npickle.loads(data)")
    output = subprocess.run(
        [sys.executable, "-m", "deserialize_call_review", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert output.returncode == 1
    assert json.loads(output.stdout)["status"] == "REVIEW"
