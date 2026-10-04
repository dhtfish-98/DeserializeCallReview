"""Verify freshly built wheel/sdist content, metadata, licenses and RECORD."""

import argparse
import base64
import csv
import hashlib
import io
import json
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(wheel, sdist):
    root = Path(__file__).resolve().parents[1]
    with zipfile.ZipFile(wheel) as package:
        names = package.namelist()
        require(len(names) == len(set(names)), "duplicate wheel member")
        require(all(".." not in Path(name).parts for name in names), "unsafe wheel member")
        metadata_path = next(name for name in names if name.endswith(".dist-info/METADATA"))
        prefix = metadata_path.rsplit("/", 1)[0]
        metadata = Parser().parsestr(package.read(metadata_path).decode())
        require(metadata["Name"] == "deserialize-call-review", "name")
        require(metadata["Version"] == "0.1.2", "version")
        require(metadata["Requires-Python"] == ">=3.11", "Python version")
        require(metadata["License-Expression"] == "Apache-2.0", "SPDX license")
        require(
            all('extra == "test"' in row for row in metadata.get_all("Requires-Dist", [])),
            "unexpected runtime dependency",
        )
        require(
            set(metadata.get_all("License-File", []))
            == {
                "项目文档/LICENSE",
                "项目文档/NOTICE",
                "项目文档/THIRD_PARTY_LICENSES/Bandit-Apache-2.0.txt",
            },
            "license-file metadata",
        )
        for name in (
            "项目文档/LICENSE",
            "项目文档/NOTICE",
            "项目文档/THIRD_PARTY_LICENSES/Bandit-Apache-2.0.txt",
        ):
            require(package.read(f"{prefix}/licenses/{name}") == (root / name).read_bytes(), name)
        entry = package.read(f"{prefix}/entry_points.txt").decode()
        require("deserialize-call-review = deserialize_call_review.cli:main" in entry, "entrypoint")
        runtime = [
            path
            for path in (root / "src" / "deserialize_call_review").iterdir()
            if path.suffix == ".py" or path.name == "py.typed"
        ]
        for path in runtime:
            require(
                package.read(f"deserialize_call_review/{path.name}") == path.read_bytes(),
                "runtime source does not match wheel",
            )
        allowed = {f"deserialize_call_review/{path.name}" for path in runtime}
        require(
            all(name in allowed or name.startswith(prefix + "/") for name in names),
            "non-runtime source or private artifact in wheel",
        )
        rows = list(csv.reader(io.StringIO(package.read(f"{prefix}/RECORD").decode())))
        require({row[0] for row in rows} == set(names), "RECORD completeness")
        require(len(rows) == len(names), "RECORD duplicates")
        verified = 0
        for name, digest, size in rows:
            if name == f"{prefix}/RECORD":
                require(digest == size == "", "RECORD self entry")
                continue
            content = package.read(name)
            expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            require(
                digest == "sha256=" + expected.decode() and size == str(len(content)),
                "RECORD hash/length",
            )
            verified += 1
    with tarfile.open(sdist) as archive:
        members = archive.getmembers()
        require(
            all(not member.issym() and not member.islnk() for member in members),
            "sdist link member",
        )
        base = members[0].name.split("/", 1)[0]
        names = {member.name for member in members}
        for name in (
            "项目文档/LICENSE",
            "项目文档/NOTICE",
            "项目文档/THIRD_PARTY_LICENSES/Bandit-Apache-2.0.txt",
            "项目文档/README.md",
            "项目文档/ORIGIN.md",
            "项目文档/DEFENSIVE_SCOPE.md",
            "项目文档/VALIDATION.md",
            "项目文档/SOURCE_AUDIT.json",
            "requirements-dev.txt",
            ".github/workflows/ci.yml",
            "scripts/verify_package.py",
            "scripts/installed_smoke.py",
            "scripts/installed_cli_check.py",
        ):
            require(f"{base}/{name}" in names, "sdist required source/docs missing")
            member = archive.extractfile(f"{base}/{name}")
            require(
                member is not None and member.read() == (root / name).read_bytes(),
                "sdist required source mismatch",
            )
        forbidden = {".venv", ".install-check", "validation-local", "__pycache__", ".git"}
        require(
            all(not forbidden.intersection(Path(name).parts) for name in names),
            "private/build artifact in sdist",
        )
    return {
        "status": "PASS",
        "runtime_dependencies": 0,
        "wheel_record_files_verified": verified,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "sdist_sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.wheel, args.sdist), sort_keys=True))
