"""Run with a fresh wheel installation; reject target imports, exec and sockets."""

import contextlib
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import deserialize_call_review
from deserialize_call_review import review_bytes
from deserialize_call_review.cli import main


def require(condition, message):
    if not condition:
        raise ValueError(message)


wheel = Path(sys.argv[1]).resolve()
installed = Path(deserialize_call_review.__file__).resolve().parent
require(Path(sys.prefix).resolve() in installed.parents, "not independent installed runtime")
with zipfile.ZipFile(wheel) as package:
    count = 0
    for name in package.namelist():
        if name.startswith("deserialize_call_review/"):
            relative = name.removeprefix("deserialize_call_review/")
            require((installed / relative).read_bytes() == package.read(name), "installed mismatch")
            count += 1

# Prewarm standard-library internals before denying exec/import events.
review_bytes(b"import yaml\nyaml.safe_load(data)")
with contextlib.redirect_stdout(io.StringIO()):
    main([])
seen = {"exec": 0, "socket": 0, "target_import": 0}


def audit(event, arguments):
    if event == "exec":
        seen["exec"] += 1
        raise RuntimeError("unexpected execution event")
    if event.startswith("socket."):
        seen["socket"] += 1
        raise RuntimeError("unexpected socket event")
    if event == "import" and arguments[0].split(".", 1)[0] in {
        "pickle",
        "_pickle",
        "marshal",
        "shelve",
        "yaml",
    }:
        seen["target_import"] += 1
        raise RuntimeError("unexpected target import event")


sys.addaudithook(audit)
cases = [
    (b"import pickle as p\np.loads(data)", "REVIEW"),
    (b"import yaml\nyaml.load(data,Loader=yaml.SafeLoader)", "NO_REVIEW_FINDINGS"),
    (b"import yaml\nyaml.load(data,Loader=SafeLoader)", "OPEN"),
    (b"import pickle\ndef f():\n pickle.loads(data)\npickle=other", "OPEN"),
    (b"import pickle\nraise RuntimeError('must-not-execute')\npickle.loads(data)", "OPEN"),
]
for source, expected in cases:
    report = review_bytes(source)
    require(report.status == expected, "installed review smoke result")
    require(report.source_sha256 == hashlib.sha256(source).hexdigest(), "installed source hash")
with contextlib.redirect_stdout(io.StringIO()) as output:
    require(main([]) == 2, "installed CLI error code")
require(json.loads(output.getvalue())["status"] == "OPEN", "installed CLI error JSON")
require(not any(seen.values()), "prohibited event occurred")
print(
    json.dumps(
        {
            "status": "PASS",
            "cases": len(cases),
            "prohibited_events": seen,
            "installed_runtime_files_verified": count,
        },
        sort_keys=True,
    )
)
