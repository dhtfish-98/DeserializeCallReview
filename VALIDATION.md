# Validation and open evidence

Local review covered every new runtime, CLI, test, package script, dependency declaration and workflow. Tests use AST source strings and frozen source-text fixtures; none execute a deserialization call or upstream example. The selected upstream mechanisms and license were read at the fixed commit; exact review ranges/hashes are in SOURCE_AUDIT.json. This is not an audit of all Bandit plugins or a CVP eligibility decision.

The local Python 3.14.6 validation runs the complete pytest suite, Ruff lint/format checks, dependency consistency check, wheel/sdist build, SPDX/license/entrypoint/dependency/RECORD/source verification and a fresh separate offline wheel install. Installed console/module CLI cases cover a selected REVIEW boundary, nominal restricted YAML shape, unresolved Loader and missing-file OPEN. An installed audit-hook smoke checks that source inspection performs no target module import, code execution or socket event. The installed runtime is compared byte-for-byte to the final wheel.

Regression coverage includes selected module/from/assignment aliases, tracked Unpickler instance methods, first-level destructuring without double-counted calls, local scope/parameters/defaults/exception/match/loop bindings, class-method scope, late module/closure rebindings, global/nonlocal mutation, dynamic calls/imports, namespace/loader mutation, branch merging, generator/comprehension closure timing, annotations, unsupported newer syntax, YAML positional/keyword Loader bindings and wrong/dynamic arguments. Boundary tests check source bytes/encoding/NUL/syntax, AST depth/nodes, binding/scope/update/finding/report limits, exact Unicode/BOM/CRLF byte positions, source/path/literal privacy, file mutation, device/inode metadata, read-length changes, symlinks/traversal/directories/devices/FIFOs and unsupported safe-open capability. Three fixed upstream examples preserve every selected original event as REVIEW or OPEN candidate accounting; no complete Bandit behavioral equivalence is claimed.

Current observed local results: **238 tests passed, 0 failed, 0 skipped**. Lint/format, dependency checks, final artifact verification and independent installed CLI/audit smoke are recorded in `validation-local` and in the separate engineering report, where final archive hashes can be recorded without a circular artifact self-hash. Local build/install evidence is separate from remote CI and application execution. The committed CI matrix runs the complete suite, archive checks and independent installed CLI/smoke on Linux/macOS with Python 3.11/3.14; remote execution remains OPEN until actually run.

Open items: remote CI results; compatibility on other Python/platform combinations; real installed target-module provenance and loader registry behavior; whole-program/interprocedural/taint/reachability analysis; application input control and exploitability; every possible filesystem concurrent-write race; independent human review; CVP admission/account eligibility and future model safety response. No pass result closes those questions.

To reproduce:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts examples
.venv/bin/python -m pip check
.venv/bin/python -m build --no-isolation
.venv/bin/python scripts/verify_package.py dist/deserialize_call_review-0.1.0-py3-none-any.whl dist/deserialize_call_review-0.1.0.tar.gz
python -m venv .install-check
.install-check/bin/python -m pip install --no-index --no-deps dist/deserialize_call_review-0.1.0-py3-none-any.whl
.install-check/bin/python -m pip check
.install-check/bin/python scripts/installed_cli_check.py
.install-check/bin/python scripts/installed_smoke.py dist/deserialize_call_review-0.1.0-py3-none-any.whl
```
