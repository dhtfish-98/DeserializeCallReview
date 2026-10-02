"""Verify console entrypoint and module CLI from an independent installed wheel."""

import json
import os
import subprocess
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


root = Path(__file__).resolve().parents[1]
executable = Path(sys.executable).parent / "deserialize-call-review"
cases = [
    (root / "examples/selected_review.py", "REVIEW", 1),
    (root / "examples/nominal_yaml_shape.py", "NO_REVIEW_FINDINGS", 0),
    (root / "examples/open_dynamic_loader.py", "OPEN", 2),
    (root / "validation-local/PRIVATE_MISSING.py", "OPEN", 2),
]
environment = dict(os.environ)
environment.pop("PYTHONPATH", None)
for path, status, code in cases:
    result = subprocess.run(
        [str(executable), str(path)],
        cwd=Path(sys.prefix),
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    report = json.loads(result.stdout)
    require(
        result.returncode == code and report["status"] == status and not result.stderr,
        "installed console result",
    )
    require(
        str(path) not in result.stdout and "PRIVATE_MISSING" not in result.stdout,
        "input path leaked",
    )
result = subprocess.run(
    [sys.executable, "-m", "deserialize_call_review", str(root / "examples/selected_review.py")],
    cwd=Path(sys.prefix),
    env=environment,
    capture_output=True,
    text=True,
    timeout=10,
    check=False,
)
require(
    result.returncode == 1 and json.loads(result.stdout)["status"] == "REVIEW",
    "installed module result",
)
require(not result.stderr, "installed module stderr")
print(json.dumps({"status": "PASS", "installed_cli_cases": len(cases) + 1}, sort_keys=True))
