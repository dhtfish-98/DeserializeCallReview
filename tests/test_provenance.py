import hashlib
import json
from pathlib import Path

import pytest

from deserialize_call_review import review_bytes

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "项目文档/SOURCE_AUDIT.json").read_text())


@pytest.mark.parametrize("name", ["pickle_deserialize", "yaml_load", "shelve_open"])
def test_frozen_upstream_source_examples_hash_and_selected_ledger(name):
    path = ROOT / "tests" / "fixtures" / "upstream" / f"{name}.py.txt"
    data = path.read_bytes()  # TEXT input only; never imported or executed.
    record = next(item for item in MANIFEST["files"] if item["path"] == f"examples/{name}.py")
    assert hashlib.sha256(data).hexdigest() == record["sha256"]
    report = review_bytes(data)
    assert report.status == "OPEN"
    expected = {
        "pickle_deserialize": {7: "pickle.loads", 12: "pickle.load", 15: "pickle.Unpickler"},
        "yaml_load": {9: "yaml.load", 22: "yaml.load"},
        "shelve_open": {8: "shelve.open", 11: "shelve.open"},
    }[name]
    for line, binding in expected.items():
        assert any(
            item.line == line
            and item.kind in {"REVIEW", "OPEN"}
            and binding in item.possible_bindings
            for item in report.findings
        )
    assert report.input_control_status == report.runtime_module_origin_status == "OPEN"
    assert path.read_bytes() == data


def test_complete_original_license_copies_are_exact():
    original = (ROOT / "LICENSE").read_bytes()
    assert (
        original == (ROOT / "项目文档/THIRD_PARTY_LICENSES" / "Bandit-Apache-2.0.txt").read_bytes()
    )
    record = next(item for item in MANIFEST["files"] if item["path"] == "LICENSE")
    assert hashlib.sha256(original).hexdigest() == record["sha256"]
    assert b"Apache License" in original
    assert b"Version 2.0, January 2004" in original
    assert b"9. Accepting Warranty or Additional Liability." in original
