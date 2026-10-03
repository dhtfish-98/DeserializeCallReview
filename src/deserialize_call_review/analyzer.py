# SPDX-License-Identifier: Apache-2.0
# New implementation by dhtfish98; see ORIGIN.md. No Bandit runtime code reused.
"""A bounded abstract interpreter for lexical import/call bindings, not execution.

Only standard-library AST/symbol-table construction operates on input. No target
module is imported; no callable, loader, source statement, or payload is executed.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import io
import json
import symtable
import tokenize
import warnings
from dataclasses import asdict, dataclass, field

from .files import read_regular_file

_ROOTS = {"pickle", "_pickle", "marshal", "shelve", "yaml", "builtins", "importlib"}
_LOADERS = {
    "yaml.SafeLoader",
    "yaml.CSafeLoader",
    "yaml.loader.SafeLoader",
    "yaml.cyaml.CSafeLoader",
}
_REVIEW = {
    "pickle.load",
    "pickle.loads",
    "pickle.Unpickler",
    "pickle._Unpickler",
    "pickle.Unpickler.load",
    "pickle._Unpickler.load",
    "_pickle.load",
    "_pickle.loads",
    "_pickle.Unpickler",
    "_pickle.Unpickler.load",
    "marshal.load",
    "marshal.loads",
    "shelve.open",
    "shelve.DbfilenameShelf",
    "shelve.Shelf",
    "shelve.BsdDbShelf",
}
_SAFE_FUNCTIONS = {"yaml.safe_load", "yaml.safe_load_all"}
_YAML_FUNCTIONS = {"yaml.load", "yaml.load_all"}
_YAML_REVIEW = {"yaml.full_load", "yaml.full_load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}
_MUTATION = {"yaml.add_constructor", "yaml.add_multi_constructor"}
_DYNAMIC = {
    "builtins.__import__",
    "builtins.eval",
    "builtins.exec",
    "builtins.globals",
    "builtins.locals",
    "importlib.import_module",
    "importlib.reload",
}
_BENIGN = {
    "pickle.dump",
    "pickle.dumps",
    "marshal.dump",
    "marshal.dumps",
    "yaml.dump",
    "yaml.safe_dump",
}
_YAML_CLASSES = {
    f"yaml.{name}"
    for name in (
        "SafeLoader",
        "CSafeLoader",
        "Loader",
        "CLoader",
        "UnsafeLoader",
        "CUnsafeLoader",
        "FullLoader",
        "CFullLoader",
        "BaseLoader",
        "CBaseLoader",
    )
} | _LOADERS
_MODULES = _ROOTS | {"yaml.loader", "yaml.cyaml"}
_SPECIAL = {"builtins.getattr", "builtins.setattr", "builtins.delattr"} | _DYNAMIC
_KNOWN = (
    _MODULES
    | _LOADERS
    | _REVIEW
    | _SAFE_FUNCTIONS
    | _YAML_FUNCTIONS
    | _YAML_REVIEW
    | _MUTATION
    | _BENIGN
    | _YAML_CLASSES
    | _SPECIAL
)
_BUILTINS = frozenset(dir(builtins))


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 262144
    max_nodes: int = 20000
    max_depth: int = 96
    max_bindings: int = 2048
    max_findings: int = 256
    max_report_bytes: int = 131072
    max_scopes: int = 256
    max_binding_updates: int = 16384

    def valid(self):
        return (
            all(
                type(v) is int and 1 <= v <= cap
                for v, cap in zip(
                    asdict(self).values(),
                    (262144, 20000, 96, 2048, 256, 131072, 256, 16384),
                    strict=True,
                )
            )
            and self.max_report_bytes >= 1024
        )


_DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class Value:
    kind: str = "unknown"
    paths: frozenset[str] = frozenset()


UNKNOWN = Value()
OTHER = Value("other")


def uncertain(*values):
    return Value("unknown", frozenset(sorted(set().union(*(v.paths for v in values)))[:16]))


def imported(path):
    if path in _KNOWN:
        return Value("bound", frozenset({path}))
    if path.split(".", 1)[0] in _ROOTS:
        return uncertain(Value("bound", frozenset({path.split(".", 1)[0]})))
    return OTHER


@dataclass(frozen=True)
class Finding:
    kind: str
    reason: str
    binding: str | None
    possible_bindings: tuple[str, ...]
    line: int
    column_utf8: int
    end_line: int
    end_column_utf8: int
    byte_start: int
    byte_end: int
    conditional: bool


@dataclass(frozen=True)
class Report:
    status: str
    reason: str
    findings: tuple[Finding, ...] = ()
    source_sha256: str | None = None
    calls_seen: int = 0
    nodes_seen: int = 0
    review_required: bool = False
    truncated: bool = False
    coverage_status: str = "NOT_ANALYZED"
    diagnostics: tuple[str, ...] = ()
    schema_version: str = "1.0"
    scope: str = "single-file selected Python deserialization call shapes"
    exploitability_status: str = "OPEN"
    input_control_status: str = "OPEN"
    runtime_module_origin_status: str = "OPEN"

    def to_dict(self):
        return asdict(self)


class _Budget(ValueError):
    pass


class _Locals(ast.NodeVisitor):
    """Collect Python block bindings without descending into nested body scopes."""

    def __init__(self):
        self.names = set()
        self.external = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)

    def visit_ImportFrom(self, node):
        self.names.update(alias.asname or alias.name for alias in node.names if alias.name != "*")

    def visit_FunctionDef(self, node):
        self.names.add(node.name)
        for expression in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.names.add(node.name)
        for expression in [*node.bases, *node.decorator_list, *(kw.value for kw in node.keywords)]:
            self.visit(expression)

    def visit_Lambda(self, node):
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_Global(self, node):
        self.external.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_MatchAs(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        if node.name:
            self.names.add(node.name)

    def visit_MatchMapping(self, node):
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)

    def _comprehension(self, node):
        # Comprehension targets have their own scope; walrus targets bind outside it.
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                self.names.add(child.target.id)

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension


@dataclass
class Frame:
    kind: str
    captured: dict[str, Value] = field(default_factory=dict)
    locals: set[str] = field(default_factory=set)
    external: set[str] = field(default_factory=set)
    env: dict[str, Value] = field(default_factory=dict)
    history: dict[str, set[Value]] = field(default_factory=dict)
    pending: list = field(default_factory=list)
    wildcard: bool = False
    lexical: Frame | None = None

    def lookup(self, name):
        if name in self.env:
            return self.env[name]
        if name in self.locals:
            return uncertain(self.captured.get(name, UNKNOWN))
        if name in self.captured:
            return self.captured[name]
        if name in _BUILTINS and not self.wildcard:
            return imported("builtins." + name) if "builtins." + name in _KNOWN else OTHER
        return UNKNOWN

    def visible(self):
        values = dict(self.captured)
        values.update(
            {name: uncertain(values.get(name, UNKNOWN)) for name in self.locals - self.env.keys()}
        )
        values.update(self.env)
        return values


class Analyzer:
    def __init__(self, data, limits, external_names, ambient_mutation):
        self.data = data
        self.limits = limits
        self.findings = []
        self.calls = 0
        self.mutated = set()
        self.external_names = external_names
        self.ambient_mutation = ambient_mutation
        self.scopes = 0
        self.binding_updates = 0
        self.offsets = [0]
        for line in data.splitlines(keepends=True):
            self.offsets.append(self.offsets[-1] + len(line))
        self.bom = 3 if data.startswith(b"\xef\xbb\xbf") else 0

    def emit(self, node, kind, reason, value=UNKNOWN, conditional=False):
        if len(self.findings) >= self.limits.max_findings:
            raise _Budget("finding_limit")
        paths = tuple(sorted(value.paths & _KNOWN))
        binding = paths[0] if value.kind == "bound" and len(paths) == 1 else None
        line = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", line)
        column = getattr(node, "col_offset", 0)
        end_column = getattr(node, "end_col_offset", column)
        self.findings.append(
            Finding(
                kind,
                reason,
                binding,
                paths,
                line,
                column,
                end,
                end_column,
                self.offsets[line - 1] + column + (self.bom if line == 1 else 0),
                self.offsets[end - 1] + end_column + (self.bom if end == 1 else 0),
                conditional,
            )
        )

    def bind(self, frame, name, value):
        self.binding_updates += 1
        if self.binding_updates > self.limits.max_binding_updates:
            raise _Budget("binding_update_limit")
        if len(frame.env) >= self.limits.max_bindings and name not in frame.env:
            raise _Budget("binding_limit")
        if name in frame.external:
            value = uncertain(value, frame.lookup(name))
        frame.env[name] = value
        history = frame.history.setdefault(name, set())
        if len(history) < 16:
            history.add(value)
        else:
            history.add(UNKNOWN)

    def import_value(self, path):
        value = imported(path)
        if any(p.split(".", 1)[0] in self.mutated for p in value.paths):
            return uncertain(value)
        return value

    def scope(self):
        self.scopes += 1
        if self.scopes > self.limits.max_scopes:
            raise _Budget("scope_limit")

    def mutate(self, frame, value):
        roots = {p.split(".", 1)[0] for p in value.paths} & _ROOTS
        self.mutated.update(roots)
        for name, previous in frame.visible().items():
            if any(p.split(".", 1)[0] in roots for p in previous.paths):
                self.bind(frame, name, uncertain(previous))

    def target(self, node, value, frame, conditional=False):
        if isinstance(node, ast.Name):
            self.bind(frame, node.id, value)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for child in node.elts:
                self.target(child, uncertain(value), frame, conditional)
        elif isinstance(node, ast.Starred):
            self.target(node.value, uncertain(value), frame, conditional)
        else:
            base = self.expr(node.value, frame, conditional) if hasattr(node, "value") else UNKNOWN
            self.mutate(frame, base)
            self.emit(node, "OPEN", "attribute_or_item_write_unresolved", base, conditional)

    def expr(self, node, frame, conditional=False):
        if node is None:
            return OTHER
        if isinstance(node, ast.Name):
            return frame.lookup(node.id)
        if isinstance(node, ast.Constant):
            return OTHER
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, frame, conditional)
            values = []
            for path in base.paths:
                path = path.replace("#instance", "") + "." + node.attr
                if path in _KNOWN or (
                    node.attr in {"add_constructor", "add_multi_constructor"}
                    and path.rsplit(".", 1)[0] in _YAML_CLASSES
                ):
                    values.append(Value("bound", frozenset({path})))
                else:
                    values.append(uncertain(base))
            if base.kind == "bound" and len(values) == 1:
                return values[0]
            if base.kind == "other":
                return OTHER
            return uncertain(base, *values)
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, frame, conditional)
            self.target(node.target, value, frame, conditional)
            if frame.kind == "comprehension":
                self.emit(node, "OPEN", "comprehension_walrus_binding", value, True)
            return value
        if isinstance(node, ast.IfExp):
            self.expr(node.test, frame, conditional)
            self.emit(node, "OPEN", "conditional_expression_binding", conditional=True)
            return uncertain(self.expr(node.body, frame, True), self.expr(node.orelse, frame, True))
        if isinstance(node, ast.Lambda):
            self.scope()
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                self.expr(default, frame, conditional)
            owner = frame.lexical if frame.kind == "class" else frame
            owner.pending.append((node, owner.visible(), conditional))
            return Value("local-function")
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self.scope()
            self.emit(node, "OPEN", "comprehension_iterations_unresolved", conditional=True)
            outer = self.expr(node.generators[0].iter, frame, conditional)
            # Generator expressions and closures can run after the enclosing
            # frame changes. Iteration effects/timing are outside our model.
            inner = Frame(
                "comprehension",
                {
                    name: uncertain(value) if value.paths else value
                    for name, value in frame.visible().items()
                },
            )
            for i, generator in enumerate(node.generators):
                if i:
                    self.expr(generator.iter, inner, True)
                self.target(generator.target, uncertain(outer), inner, True)
                for condition in generator.ifs:
                    self.expr(condition, inner, True)
            for child in [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]:
                self.expr(child, inner, True)
            # PEP 572 walrus assignments escape the comprehension target scope.
            for child in ast.walk(node):
                if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                    self.bind(frame, child.target.id, uncertain(frame.lookup(child.target.id)))
            self.flush(inner)
            return UNKNOWN
        if isinstance(node, ast.Call):
            self.calls += 1
            function = self.expr(node.func, frame, conditional)
            arguments = [self.expr(arg, frame, conditional) for arg in node.args]
            keywords = [(kw.arg, self.expr(kw.value, frame, conditional)) for kw in node.keywords]
            if function.kind != "bound" or len(function.paths) != 1:
                if function.kind != "other":
                    self.emit(node, "OPEN", "call_binding_unresolved", function, conditional)
                if function.kind != "other":
                    self.mutate(frame, Value("bound", frozenset(_ROOTS)))
                return UNKNOWN
            path = next(iter(function.paths))
            if path in _REVIEW:
                self.emit(node, "REVIEW", "selected_object_loading_boundary", function, conditional)
                if path.endswith(("Unpickler", "_Unpickler")):
                    return Value("bound", frozenset({path + "#instance"}))
            elif path in _YAML_FUNCTIONS | _SAFE_FUNCTIONS | _YAML_REVIEW:
                self.yaml_call(node, path, arguments, keywords, function, conditional)
            elif path in _DYNAMIC:
                self.emit(node, "OPEN", "dynamic_import_or_namespace_effect", function, conditional)
                self.mutate(frame, Value("bound", frozenset(_ROOTS)))
            elif path in _MUTATION or path.endswith((".add_constructor", ".add_multi_constructor")):
                self.emit(node, "OPEN", "yaml_constructor_mutation", function, conditional)
                self.mutate(frame, function)
            elif path in {"builtins.setattr", "builtins.delattr"}:
                self.emit(node, "OPEN", "dynamic_attribute_mutation", function, conditional)
                self.mutate(frame, arguments[0] if arguments else UNKNOWN)
            elif path == "builtins.getattr":
                self.emit(node, "OPEN", "dynamic_attribute_lookup", function, conditional)
                return uncertain(*arguments)
            elif path in _YAML_CLASSES:
                self.emit(
                    node, "OPEN", "manual_yaml_loader_api_unimplemented", function, conditional
                )
                return uncertain(function)
            return UNKNOWN
        if isinstance(node, ast.BoolOp):
            return uncertain(*(self.expr(child, frame, True) for child in node.values))
        # Scan nested expressions for actual AST Call nodes; never evaluate a value.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.expr(child, frame, conditional)
            elif isinstance(child, ast.keyword):
                self.expr(child.value, frame, conditional)
        return UNKNOWN

    def yaml_call(self, node, path, arguments, keywords, function, conditional):
        names = [name for name, _ in keywords]
        safe_function = path in _SAFE_FUNCTIONS
        allowed = {"stream"} if path not in _YAML_FUNCTIONS else {"stream", "Loader"}
        invalid = (
            any(isinstance(arg, ast.Starred) for arg in node.args)
            or any(name is None or name not in allowed for name in names)
            or len(names) != len(set(names))
            or len(arguments) > (2 if path in _YAML_FUNCTIONS else 1)
            or (arguments and "stream" in names)
            or (not arguments and "stream" not in names)
            or (len(arguments) == 2 and "Loader" in names)
        )
        if invalid:
            self.emit(node, "OPEN", "yaml_call_argument_contract_unresolved", function, conditional)
            return
        if safe_function:
            self.emit(
                node, "SAFE_CALL_SHAPE", "nominal_yaml_safe_function_binding", function, conditional
            )
            return
        if path in _YAML_REVIEW:
            self.emit(node, "REVIEW", "yaml_not_safe_loader_contract", function, conditional)
            return
        loader = (
            arguments[1]
            if len(arguments) == 2
            else next((value for name, value in keywords if name == "Loader"), None)
        )
        if loader is None:
            self.emit(
                node,
                "REVIEW",
                "yaml_loader_not_explicit_version_behavior_unverified",
                function,
                conditional,
            )
        elif (
            loader.kind == "bound"
            and len(loader.paths) == 1
            and next(iter(loader.paths)) in _LOADERS
        ):
            self.emit(
                node, "SAFE_CALL_SHAPE", "nominal_safe_loader_import_binding", function, conditional
            )
        elif loader.kind == "bound" and loader.paths <= _YAML_CLASSES:
            self.emit(node, "REVIEW", "yaml_not_safe_loader_contract", function, conditional)
        else:
            self.emit(node, "OPEN", "yaml_loader_binding_unresolved", function, conditional)

    def statements(self, body, frame, conditional=False):
        for node in body:
            self.statement(node, frame, conditional)

    def branch(self, node, bodies, frame, conditional):
        self.emit(node, "OPEN", "control_flow_paths_not_executed", conditional=True)
        base = dict(frame.env)
        outcomes = [base]
        for body in bodies:
            frame.env = dict(base)
            self.statements(body, frame, True)
            outcomes.append(dict(frame.env))
        merged = {}
        for name in set().union(*(outcome.keys() for outcome in outcomes)):
            values = [outcome.get(name, frame.captured.get(name, UNKNOWN)) for outcome in outcomes]
            merged[name] = values[0] if all(v == values[0] for v in values) else uncertain(*values)
        frame.env = merged

    def statement(self, node, frame, conditional=False):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and getattr(
            node, "type_params", []
        ):
            self.emit(node, "OPEN", "type_parameter_scope_unimplemented", conditional=conditional)
            self.bind(frame, node.name, UNKNOWN)
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    self.emit(child, "OPEN", "call_in_unimplemented_scope", conditional=True)
            self.mutate(frame, Value("bound", frozenset(_ROOTS)))
            return
        if isinstance(node, ast.Import):
            for alias in node.names:
                path = alias.name if alias.asname else alias.name.split(".", 1)[0]
                self.bind(frame, alias.asname or path, self.import_value(path))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                self.emit(
                    node, "OPEN", "relative_import_origin_unresolved", conditional=conditional
                )
            for alias in node.names:
                if alias.name == "*":
                    frame.wildcard = True
                    self.emit(
                        node, "OPEN", "wildcard_import_bindings_unresolved", conditional=conditional
                    )
                    for name, value in frame.visible().items():
                        self.bind(frame, name, uncertain(value))
                else:
                    self.bind(
                        frame,
                        alias.asname or alias.name,
                        UNKNOWN if node.level else self.import_value(f"{node.module}.{alias.name}"),
                    )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            elements = (
                [self.expr(child, frame, conditional) for child in node.value.elts]
                if isinstance(node.value, (ast.Tuple, ast.List))
                else None
            )
            value = OTHER if elements is not None else self.expr(node.value, frame, conditional)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node, ast.AugAssign):
                value = uncertain(value, self.expr(node.target, frame, conditional))
            if isinstance(node, ast.AnnAssign):
                # Annotation evaluation is version/context dependent (including
                # postponed annotations); do not classify its calls as executed.
                for child in ast.walk(node.annotation):
                    if isinstance(child, ast.Call):
                        self.emit(
                            child,
                            "OPEN",
                            "annotation_evaluation_timing_unresolved",
                            conditional=conditional,
                        )
                if any(isinstance(child, ast.Call) for child in ast.walk(node.annotation)):
                    self.mutate(frame, Value("bound", frozenset(_ROOTS)))
                if node.value is None:
                    return
            for target in targets:
                if (
                    isinstance(target, (ast.Tuple, ast.List))
                    and isinstance(node.value, (ast.Tuple, ast.List))
                    and len(target.elts) == len(node.value.elts)
                ):
                    for child, element in zip(target.elts, elements, strict=True):
                        self.target(child, element, frame, conditional)
                else:
                    self.target(target, value, frame, conditional)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self.target(target, UNKNOWN, frame, conditional)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.scope()
            for expression in [
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ]:
                self.expr(expression, frame, conditional)
            parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg:
                parameters.append(node.args.vararg)
            if node.args.kwarg:
                parameters.append(node.args.kwarg)
            for annotation in [node.returns, *(arg.annotation for arg in parameters)]:
                if annotation is not None:
                    for child in ast.walk(annotation):
                        if isinstance(child, ast.Call):
                            self.emit(
                                child,
                                "OPEN",
                                "annotation_evaluation_timing_unresolved",
                                conditional=conditional,
                            )
            if node.decorator_list:
                self.emit(node, "OPEN", "decorator_effects_unresolved", conditional=conditional)
                self.mutate(frame, Value("bound", frozenset(_ROOTS)))
            owner = frame.lexical if frame.kind == "class" else frame
            captured = owner.visible()
            self.bind(frame, node.name, UNKNOWN if node.decorator_list else Value("local-function"))
            owner.pending.append((node, captured, conditional))
        elif isinstance(node, ast.ClassDef):
            self.scope()
            for expression in [
                *node.bases,
                *node.decorator_list,
                *(kw.value for kw in node.keywords),
            ]:
                self.expr(expression, frame, conditional)
            self.bind(frame, node.name, UNKNOWN if node.decorator_list or node.keywords else OTHER)
            if node.decorator_list or node.keywords or node.bases:
                self.emit(
                    node, "OPEN", "class_construction_effects_unresolved", conditional=conditional
                )
                self.mutate(frame, Value("bound", frozenset(_ROOTS)))
            inner = Frame(
                "class", frame.visible(), lexical=frame.lexical if frame.kind == "class" else frame
            )
            self.statements(node.body, inner, conditional)
        elif isinstance(node, ast.If):
            self.expr(node.test, frame, conditional)
            self.branch(node, [node.body, node.orelse], frame, conditional)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            self.expr(node.iter if hasattr(node, "iter") else node.test, frame, conditional)
            collector = _Locals()
            for item in node.body:
                collector.visit(item)
            for name in collector.names:
                self.bind(frame, name, uncertain(frame.lookup(name)))
            if hasattr(node, "target"):
                self.target(node.target, UNKNOWN, frame, True)
            self.branch(node, [node.body, node.orelse], frame, conditional)
        elif isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            bodies = [node.body, node.orelse]
            for handler in node.handlers:
                self.expr(handler.type, frame, conditional)
                if handler.name:
                    self.bind(frame, handler.name, UNKNOWN)
                bodies.append(handler.body)
            self.branch(node, bodies, frame, conditional)
            for handler in node.handlers:
                if handler.name:
                    self.bind(frame, handler.name, UNKNOWN)
            self.statements(node.finalbody, frame, conditional)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self.emit(node, "OPEN", "context_manager_effects_unresolved", conditional=conditional)
            self.mutate(frame, Value("bound", frozenset(_ROOTS)))
            for item in node.items:
                value = self.expr(item.context_expr, frame, conditional)
                if item.optional_vars:
                    self.target(item.optional_vars, uncertain(value), frame, conditional)
            self.statements(node.body, frame, conditional)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            self.emit(node, "OPEN", "external_scope_mutation_unresolved", conditional=conditional)
            for name in node.names:
                self.bind(frame, name, uncertain(frame.lookup(name)))
        elif isinstance(node, ast.Match):
            self.expr(node.subject, frame, conditional)
            for case in node.cases:
                collector = _Locals()
                collector.visit(case.pattern)
                for name in collector.names:
                    self.bind(frame, name, uncertain(frame.lookup(name)))
                self.expr(case.guard, frame, True)
            self.branch(node, [case.body for case in node.cases], frame, conditional)
        elif isinstance(node, (ast.Return, ast.Expr, ast.Raise, ast.Assert)):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, frame, conditional)
            if isinstance(node, (ast.Return, ast.Raise)):
                self.emit(node, "OPEN", "termination_paths_not_modeled", conditional=conditional)
        elif isinstance(node, (ast.Pass, ast.Break, ast.Continue)):
            if not isinstance(node, ast.Pass):
                self.emit(node, "OPEN", "loop_control_paths_not_modeled", conditional=conditional)
        else:
            self.emit(node, "OPEN", "statement_scope_unimplemented", conditional=conditional)
            collector = _Locals()
            collector.visit(node)
            for name in collector.names:
                self.bind(frame, name, UNKNOWN)
            self.mutate(frame, Value("bound", frozenset(_ROOTS)))
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    self.emit(child, "OPEN", "call_in_unimplemented_scope", conditional=True)

    def flush(self, frame):
        while frame.pending:
            node, snapshot, conditional = frame.pending.pop(0)
            final = frame.captured if frame.kind == "class" else frame.visible()
            captured = {}
            for name in snapshot.keys() | final.keys():
                initial = snapshot.get(name, UNKNOWN)
                current = final.get(name, UNKNOWN)
                stable = (
                    initial == current
                    and len(frame.history.get(name, ())) <= 1
                    and name not in self.external_names
                    and not (self.ambient_mutation and current.paths)
                    and not any(p.split(".", 1)[0] in self.mutated for p in current.paths)
                )
                captured[name] = current if stable else uncertain(initial, current)
            collector = _Locals()
            body = [node.body] if isinstance(node, ast.Lambda) else node.body
            for child in body:
                collector.visit(child)
            parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg:
                parameters.append(node.args.vararg)
            if node.args.kwarg:
                parameters.append(node.args.kwarg)
            local_names = (collector.names | {p.arg for p in parameters}) - collector.external
            inner = Frame("function", captured, local_names, collector.external)
            for parameter in parameters:
                self.bind(inner, parameter.arg, UNKNOWN)
            if isinstance(node, ast.Lambda):
                self.expr(node.body, inner, conditional)
                self.flush(inner)
            else:
                self.statements(node.body, inner, conditional)
                self.flush(inner)


def _finish(engine, digest, nodes, diagnostic=None):
    findings = tuple(
        sorted(engine.findings, key=lambda f: (f.byte_start, f.byte_end, f.kind, f.reason))
    )
    has_open = diagnostic is not None or any(f.kind == "OPEN" for f in findings)
    review = any(f.kind == "REVIEW" for f in findings)
    report = Report(
        "OPEN" if has_open else "REVIEW" if review else "NO_REVIEW_FINDINGS",
        diagnostic or "static_review_completed",
        findings,
        digest,
        engine.calls,
        nodes,
        review,
        diagnostic is not None,
        "PARTIAL" if has_open else "DECLARED_SUBSET",
        (diagnostic,) if diagnostic else (),
    )
    while (
        len(json.dumps(report.to_dict(), ensure_ascii=True).encode())
        > engine.limits.max_report_bytes
    ):
        findings = findings[:-1]
        report = Report(
            "OPEN",
            "report_byte_limit",
            findings,
            digest,
            engine.calls,
            nodes,
            review,
            True,
            "PARTIAL",
            ("report_byte_limit",),
        )
    return report


def review_bytes(data: bytes, *, limits: Limits = _DEFAULT_LIMITS) -> Report:
    """Analyze one UTF-8 Python source. No target import/eval/exec/deserialization."""
    try:
        if not isinstance(limits, Limits) or not limits.valid():
            return Report("OPEN", "invalid_limits")
        if not isinstance(data, bytes) or not data or len(data) > limits.max_bytes:
            return Report("OPEN", "input_empty_wrong_type_or_byte_limit")
        if b"\0" in data:
            return Report("OPEN", "nul_in_source")
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        if encoding not in {"utf-8", "utf-8-sig"}:
            return Report("OPEN", "unsupported_source_encoding")
        text = data.decode(encoding)
        with warnings.catch_warnings():
            # Compiler warnings can contain untrusted literal fragments. Reports use codes.
            warnings.simplefilter("ignore")
            tree = ast.parse(text, filename="<source>", mode="exec")
            # Symbol-table checks reject semantic syntax errors without code execution.
            symtable.symtable(text, "<source>", "exec")
        count = 0
        stack = [(tree, 1)]
        external = set()
        ambient_mutation = False
        while stack:
            node, depth = stack.pop()
            count += 1
            if count > limits.max_nodes or depth > limits.max_depth:
                return Report("OPEN", "ast_node_or_depth_limit", nodes_seen=count)
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                external.update(node.names)
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                ambient_mutation = True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {"add_constructor", "add_multi_constructor", "setattr", "delattr"}
            ):
                ambient_mutation = True
            stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            # Validate block-placement rules (e.g. return outside function). The
            # resulting code object is discarded, never executed or written out.
            compile(tree, "<source>", "exec", dont_inherit=True, optimize=0)
        engine = Analyzer(data, limits, external, ambient_mutation)
        digest = hashlib.sha256(data).hexdigest()
        try:
            module = Frame("module")
            engine.statements(tree.body, module)
            engine.flush(module)
        except _Budget as exc:
            return _finish(engine, digest, count, str(exc))
        return _finish(engine, digest, count)
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        return Report("OPEN", "source_syntax_encoding_or_recursion_error")
    except Exception:
        return Report("OPEN", "unexpected_analysis_error")


def review_file(path, *, limits: Limits = _DEFAULT_LIMITS) -> Report:
    """Read one bounded regular file; path/error/source text is never in reports."""
    if not isinstance(limits, Limits) or not limits.valid():
        return Report("OPEN", "invalid_limits")
    try:
        data = read_regular_file(path, limits.max_bytes)
    except Exception:
        return Report("OPEN", "file_read_rejected")
    return review_bytes(data, limits=limits)
