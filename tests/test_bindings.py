import builtins

import pytest

from deserialize_call_review import review_bytes


def findings(source, kind=None):
    report = review_bytes(source.encode())
    return [f for f in report.findings if kind is None or f.kind == kind]


@pytest.mark.parametrize(
    "path",
    [
        "pickle.load",
        "pickle.loads",
        "pickle.Unpickler",
        "pickle._Unpickler",
        "_pickle.load",
        "_pickle.loads",
        "_pickle.Unpickler",
        "marshal.load",
        "marshal.loads",
        "shelve.open",
        "shelve.DbfilenameShelf",
        "shelve.Shelf",
        "shelve.BsdDbShelf",
    ],
)
@pytest.mark.parametrize("form", ["module", "module_alias", "from_alias", "assignment_alias"])
def test_selected_paths_aliases(path, form):
    module, name = path.split(".")
    sources = {
        "module": f"import {module}\n{path}(data)",
        "module_alias": f"import {module} as p\np.{name}(data)",
        "from_alias": f"from {module} import {name} as run\nrun(data)",
        "assignment_alias": f"import {module}\na={path}\nb=a\nb(data)",
    }
    report = review_bytes(sources[form].encode())
    assert report.status == "REVIEW"
    assert [f.binding for f in report.findings if f.kind == "REVIEW"] == [path]
    assert report.input_control_status == report.exploitability_status == "OPEN"


@pytest.mark.parametrize(
    "source",
    [
        "import pickle as p\np=other\np.loads(data)",
        "import pickle as p\ndel p\np.loads(data)",
        "import pickle as p\ndef f(p):\n p.loads(data)",
        "from pickle import loads as run\ndef f(run):\n run(data)",
        "import pickle as p\ndef f():\n p.loads(data)\n p=other",
        "import pickle as p\ndef f():\n p.loads(data)\n import other as p",
        "import yaml\ndef f():\n yaml.safe_load(data)\n yaml: object",
        "import yaml\ndef f():\n yaml.safe_load(data)\n for yaml in things:\n  pass",
        (
            "import yaml\ndef f():\n yaml.safe_load(data)\n try:\n  pass\n"
            " except Exception as yaml:\n  pass"
        ),
        "import yaml\ndef f():\n yaml.safe_load(data)\n match thing:\n  case yaml:\n   pass",
        "import yaml\ndef f():\n yaml.safe_load(data)\nyaml=other",
        "import yaml\ndef f():\n yaml.safe_load(data)\nyaml=other\nimport yaml",
        "def f():\n yaml.safe_load(data)\nimport yaml",
        "import yaml\nclass C:\n def f(self):\n  yaml.safe_load(data)\nyaml=other",
        "import yaml\ndef f():\n global yaml\n yaml.safe_load(data)",
        "import yaml\ndef f():\n yaml.safe_load(data)\ndef g():\n global yaml\n yaml=other",
        "import yaml\ndef f():\n yaml.safe_load(data)\ndef g():\n yaml.safe_load=other",
        "import yaml\nf=lambda yaml: yaml.safe_load(data)",
        "import yaml\ndef f(yaml=yaml):\n yaml.safe_load(data)",
    ],
)
def test_shadowing_or_future_mutation_not_safety(source):
    report = review_bytes(source.encode())
    assert report.status == "OPEN"
    assert not findings(source, "SAFE_CALL_SHAPE")
    assert not findings(source, "REVIEW")


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\ndef f():\n yaml.safe_load(data)",
        "import yaml\nclass C:\n yaml=other\n def f(self):\n  yaml.safe_load(data)",
        "def f():\n import yaml\n yaml.safe_load(data)",
        "def outer():\n import yaml\n def inner():\n  yaml.safe_load(data)",
        "import yaml\nf=lambda data: yaml.safe_load(data)",
        "import yaml\nasync def f(data):\n yaml.safe_load(data)",
        "import yaml\nclass C:\n class D:\n  yaml=other\n  def f(self):\n   yaml.safe_load(data)",
    ],
)
def test_stable_free_bindings_and_class_scope_skip(source):
    safe = findings(source, "SAFE_CALL_SHAPE")
    assert len(safe) == 1
    assert safe[0].binding == "yaml.safe_load"


def test_tuple_and_chain_aliases():
    source = "import pickle, yaml\na,b=(pickle,yaml)\nc=d=a.loads\nc(data)\nb.safe_load(data)"
    assert len(findings(source, "REVIEW")) == 1
    assert len(findings(source, "SAFE_CALL_SHAPE")) == 1


def test_tuple_call_not_double_counted():
    report = review_bytes(b"import pickle\na,b=(pickle.loads(data),0)")
    assert report.calls_seen == 1
    assert len([f for f in report.findings if f.kind == "REVIEW"]) == 1


def test_unpickler_instance_method_alias():
    source = "import pickle\np=pickle.Unpickler(stream)\nrun=p.load\nrun()"
    assert [f.binding for f in findings(source, "REVIEW")] == [
        "pickle.Unpickler",
        "pickle.Unpickler.load",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import json\njson.loads(data)",
        "import pickle\npickle.dumps(data)",
        "import marshal\nmarshal.dump(data, stream)",
        "import yaml\nyaml.dump(data)",
        "from other import loads\nloads(data)",
        "import other as yaml\nyaml.safe_load(data)",
        "def loads(data):\n pass\nloads(data)",
        "import pickle\ndef pickle(data):\n pass",
    ],
)
def test_no_false_selected_loading_or_safety(source):
    assert not findings(source, "REVIEW")
    assert not findings(source, "SAFE_CALL_SHAPE")


@pytest.mark.parametrize(
    "source",
    [
        "loader(data)",
        "callbacks[0](data)",
        "factory()(data)",
        "import pickle\ngetattr(pickle,name)(data)",
        "module=__import__(name)\nmodule.loads(data)",
        "import importlib\nmodule=importlib.import_module(name)\nmodule.loads(data)",
        "from yaml import *\nsafe_load(data)",
        "from .yaml import safe_load\nsafe_load(data)",
        (
            "import yaml\nLoader=yaml.SafeLoader if condition else yaml.Loader\n"
            "yaml.load(data,Loader=Loader)"
        ),
        (
            "import yaml\nif condition:\n Loader=yaml.SafeLoader\nelse:\n Loader=yaml.Loader\n"
            "yaml.load(data,Loader=Loader)"
        ),
        "import yaml\nfor Loader in candidates:\n yaml.load(data,Loader=Loader)",
        "import yaml\n[yaml.safe_load(data) for yaml in choices]",
        "import yaml\n[(yaml:=x) for x in choices]\nyaml.safe_load(data)",
        (
            "import yaml\ntry:\n Loader=yaml.SafeLoader\nexcept Exception:\n Loader=other\n"
            "yaml.load(data,Loader=Loader)"
        ),
    ],
)
def test_dynamic_calls_and_control_flow_preserved_open(source):
    report = review_bytes(source.encode())
    assert report.status == "OPEN"
    assert any(f.kind == "OPEN" for f in report.findings)
    assert not findings(source, "SAFE_CALL_SHAPE")


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.safe_load=other\nyaml.safe_load(data)",
        "import yaml\nsetattr(yaml,name,other)\nyaml.safe_load(data)",
        "import yaml\ndel yaml.safe_load\nyaml.safe_load(data)",
        "import yaml\nyaml.__dict__[name]=other\nyaml.safe_load(data)",
        "import yaml\nyaml.SafeLoader.add_constructor(tag,fn)\nyaml.safe_load(data)",
        "import yaml\nyaml.add_constructor(tag,fn)\nfrom yaml import safe_load\nsafe_load(data)",
        "import yaml\ndef mutate():\n pass\nmutate()\nyaml.safe_load(data)",
        "import yaml\nexec(source)\nyaml.safe_load(data)",
    ],
)
def test_mutation_blocks_later_safety(source):
    assert review_bytes(source.encode()).status == "OPEN"
    assert not findings(source, "SAFE_CALL_SHAPE")


def test_review_never_imports_or_executes_target(monkeypatch, tmp_path):
    original = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in {"pickle", "marshal", "shelve", "yaml"}:
            pytest.fail("target module imported")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    marker = tmp_path / "never-created"
    source = (
        f"import pickle\nopen({str(marker)!r},'w').write('private-literal')\npickle.loads(data)"
    )
    report = review_bytes(source.encode())
    assert not marker.exists()
    assert "private-literal" not in str(report.to_dict())


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\ng=(yaml.safe_load(data) for data in items)\nyaml=other",
        "import yaml\nf=[lambda: yaml.safe_load(data) for data in items]\nyaml=other",
        (
            "import yaml\ndef outer():\n import yaml as y\n def inner():\n"
            "  y.safe_load(data)\n y=other"
        ),
        "import pickle as p\ndef f():\n p.loads(data)\np=other",
        (
            "from yaml import SafeLoader as L\nimport yaml\ndef f():\n"
            " yaml.load(data,Loader=L)\nL=other"
        ),
        "import yaml\nx: yaml.safe_load(data)\nyaml.safe_load(data)",
        "import yaml\nclass C:\n x: yaml.safe_load(data)",
    ],
)
def test_late_binding_comprehension_closure_and_annotation_open(source):
    report = review_bytes(source.encode())
    assert report.status == "OPEN"
    assert not any(item.kind in {"REVIEW", "SAFE_CALL_SHAPE"} for item in report.findings)


def test_nfkc_identifiers_follow_ast_binding_not_text_guess():
    source = "import pickle as ｐ\nｐ.loads(data)".encode()
    report = review_bytes(source)
    assert report.status == "REVIEW"
    assert report.findings[0].binding == "pickle.loads"
    item = report.findings[0]
    assert source[item.byte_start : item.byte_end] == "ｐ.loads(data)".encode()
