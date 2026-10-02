# DeserializeCallReview

Review selected Python deserialization calls from one local source file without running that file. The new implementation resolves AST import bindings, straightforward assignment aliases and Python scope boundaries. It distinguishes nominal PyYAML restricted loader bindings from a variable merely named `SafeLoader`.

The result is a review ledger, not an exploitability verdict. Source input control, runtime module integrity and exploitability always remain `OPEN`. `NO_REVIEW_FINDINGS` means no selected review boundary or unresolved event was recorded within the declared subset; it does not certify an application as safe.

```sh
python -m pip install .
deserialize-call-review examples/selected_review.py
python -m deserialize_call_review examples/open_dynamic_loader.py
```

The first example returns exit 1 (`REVIEW`); the second returns exit 2 (`OPEN`). `examples/nominal_yaml_shape.py` returns exit 0 with a `SAFE_CALL_SHAPE` row. Examples are source text for inspection; the CLI never imports or executes them. JSON is the only normal/error output. Help and version are explicit informational exceptions.

```python
from deserialize_call_review import Limits, review_bytes, review_file

report = review_bytes(b"import pickle as p\np.loads(data)\n")
print(report.status)                    # REVIEW
print(report.exploitability_status)     # OPEN
print(report.to_dict())
report = review_file("source.py", limits=Limits(max_bytes=32768))
```

Python 3.11 or newer is required. Runtime dependencies are limited to the Python standard library. File input additionally requires directory-relative open, `O_DIRECTORY`, `O_NOFOLLOW` and `O_NONBLOCK`; unsupported platforms return `OPEN`. UTF-8 source, including a UTF-8 BOM, is supported. A different declared encoding, invalid syntax, NUL, special file, symlink component or input budget failure returns `OPEN`.

| Status | Meaning | CLI exit |
| --- | --- | --- |
| `REVIEW` | A selected nominal loading boundary needs review | 1 |
| `OPEN` | Unresolved binding, control flow, input error or partial/budget-limited review | 2 |
| `NO_REVIEW_FINDINGS` | No selected review boundary or unresolved event within the subset | 0 |

An `OPEN` report can retain known `REVIEW` rows and `review_required=true`. `SAFE_CALL_SHAPE` only records a recognized nominal import/call form. It does not prove installed module origin, loader registry integrity, resource safety, execution, reachability or trusted input. Findings include one-based lines, zero-based UTF-8 byte columns and original byte offsets; they omit source excerpts, literal values, user-defined names, filenames and absolute paths. The source SHA-256 and positions are metadata and should be handled as such.

Selected paths are pickle/`_pickle` `load`, `loads`, `Unpickler` (including tracked instance `.load`), marshal `load`/`loads`, shelve opening/Shelf constructors, and PyYAML load/safe/full/unsafe entry points. The exact set and limitations are in [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md). Alias and scope behavior is deliberately conservative: late rebinding, wildcard/relative imports, dynamic calls, `global`/`nonlocal`, uncertain Loader values, mutation, unsupported scopes and branches remain explicit `OPEN` entries. This is not whole-program data flow, taint analysis or a full rewrite of the Bandit platform.

The parser constructs AST and symbol-table information and compiles a bounded AST to a discarded code object to validate semantic syntax such as a module-level `return`. That object is never executed or written. No payload is loaded, deserialized or supplied to a target callable. There is no network client, plugin discovery or recursive repository scanner.

See [ORIGIN.md](ORIGIN.md) for the frozen Bandit design source, exact Apache-2.0 license and AI-assisted contribution, and [VALIDATION.md](VALIDATION.md) for actual checks and remaining open items. CVP admission, account eligibility and any model's future safety response remain `OPEN`; this project promises none of those outcomes.
