# Defensive scope and contract

Input is one local Python source, reviewed offline as text. The tool performs no remote request, dynamic import of target modules, plugin loading, source execution, `eval`, actual deserialization, binary pickle opcode inspection or payload generation. The semantic syntax check creates a discarded code object; compiling it does not execute it. This selected mechanism is independent of ModelOpcode and is not the entire Bandit platform.

## Selected nominal boundaries

* `pickle` / `_pickle`: `load`, `loads`, `Unpickler`; Python `pickle._Unpickler`; tracked constructor result `.load` and straightforward method aliases.
* `marshal`: `load`, `loads`.
* `shelve`: `open`, `DbfilenameShelf`, `Shelf`, `BsdDbShelf`.
* PyYAML: `load`, `load_all`, `safe_load`, `safe_load_all`, `full_load`, `full_load_all`, `unsafe_load`, `unsafe_load_all`.
* Restricted loader nominal imports: `yaml.SafeLoader`, `yaml.CSafeLoader`, `yaml.loader.SafeLoader`, `yaml.cyaml.CSafeLoader`.

Dill, jsonpickle, pandas pickle helpers, manual loader instances/APIs, extension APIs and custom deserializers have no selected safety policy. Manual recognized YAML loader use is OPEN. Statically nonselected imported APIs are outside the policy; unknown/dynamic calls are recorded OPEN. `full_load`, `FullLoader`, BaseLoader and other YAML loader contracts are not accepted as the selected restricted-loader shape. A defaultless `yaml.load` is a review boundary; whether it runs or raises in a particular PyYAML version remains unverified.

## Binding model

Recognized imports carry canonical nominal paths rather than trusting variable names. Module/from/import aliases, simple assignment aliases, chain assignments and first-level equal-length literal destructuring are tracked. Parameters and all Python block-local bindings shadow outer names even when the binding occurs later. Function and lambda bodies are analyzed at lexical-parent completion. A free alias must have the same observed value at definition and parent completion with a stable binding history; later rebinding, late imports, `global`/`nonlocal` and selected namespace mutation make it uncertain. Class bodies have their own scope; method/lambda free variables skip class locals. Nested function closures are subject to the same deferred checks.

A branch condition is not executed; possible bindings are merged conservatively with an OPEN branch row. A known nominal call in a branch may retain its shape and `conditional=true`, but branch reachability remains OPEN. Loops, try/except, match, context managers, termination, decorators, class construction effects, comprehensions/generators, type parameter scopes and annotation call timing are conservative or unsupported and explicitly accounted OPEN. Calls nested inside unknown scopes are kept as unresolved rows. Captured comprehension bindings are uncertain because generator/closure evaluation may happen after rebinding.

For `yaml.load`/`load_all`, positional or keyword Loader must resolve to a selected nominal restricted class binding; `SafeLoader` spelling by itself is insufficient. Unknown/custom/parameter/default-derived/conditional Loader values remain OPEN. Missing or duplicate arguments, extra keywords, `*args`/`**kwargs` and manual loader APIs remain OPEN. `safe_load`/`safe_load_all` accepts only the ordinary single stream argument shape. Loader subclasses, constructor registries, installed module origin and monkeypatch effects in other files are not proven.

This is not a full interpreter, interprocedural analysis, application model, type checker or complete side-effect/data-flow proof. Nominal imported paths do not verify `sys.path`, the installed module or alias value at runtime. No finding proves malicious input, a reachable exploit, a safe application or a CVP-qualified applicant. Input control, exploitability and runtime module integrity remain OPEN on every report.

## Budgets and input handling

Defaults can be lowered through `Limits`, not increased: 262144 source bytes, 20000 AST nodes, AST depth 96, 2048 per-frame bindings, 256 scopes, 16384 binding updates, 256 finding rows and 131072 encoded JSON report bytes. JSON budget minimum is 1024. Reaching a budget produces partial OPEN accounting and preserves `review_required` when a known review boundary was encountered, including when rows are dropped to fit JSON. Parsing/symbol-table construction necessarily happens before the AST structural checks; bounded source bytes constrain that work, but this is not an OS memory/time sandbox. Use process limits externally when required.

Only nonempty UTF-8/UTF-8-BOM bytes are accepted. Syntax, encoding, NUL and semantic block errors are sanitized OPEN. File reading opens every component relative to a directory descriptor and refuses symlink traversal and raw `..`; final open is nonblocking to reject FIFO/device/directory inputs. Read length and device/inode/size/mtime/ctime are checked before/after. Unsupported safe-open facilities and detected concurrent changes are OPEN. This detects observed metadata changes, not a guarantee against every possible concurrent rewrite. Input is not intentionally modified; ordinary filesystem access time may change when read.

Reports expose a source hash, line/UTF-8-byte coordinates, canonical selected binding names, budget counters and constant reason codes. Raw input, literal/variable/import names outside the policy, source paths, exception text and excerpts are omitted. Hashes and positions are still source metadata. CLI results use exit 0/1/2 and JSON. OPEN never masquerades as a complete clean result.
