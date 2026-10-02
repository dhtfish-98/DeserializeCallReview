import pytest

from deserialize_call_review import review_bytes


@pytest.mark.parametrize(
    "binding",
    [
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.loader.SafeLoader",
        "yaml.cyaml.CSafeLoader",
    ],
)
@pytest.mark.parametrize("form", ["positional", "keyword", "alias"])
@pytest.mark.parametrize("method", ["load", "load_all"])
def test_actual_safe_loader_bindings(binding, form, method):
    sources = {
        "positional": f"import yaml\nyaml.{method}(data,{binding})",
        "keyword": f"import yaml\nyaml.{method}(data,Loader={binding})",
        "alias": f"import yaml\nTrusted={binding}\nyaml.{method}(data,Loader=Trusted)",
    }
    report = review_bytes(sources[form].encode())
    assert report.status == "NO_REVIEW_FINDINGS"
    assert [f.kind for f in report.findings] == ["SAFE_CALL_SHAPE"]
    assert report.runtime_module_origin_status == "OPEN"


@pytest.mark.parametrize(
    "source",
    [
        "from yaml import load as l,SafeLoader as S\nl(data,Loader=S)",
        "from yaml.loader import SafeLoader as S\nimport yaml as y\ny.load(stream=data,Loader=S)",
        "from yaml.cyaml import CSafeLoader as S\nfrom yaml import load_all as l\nl(data,S)",
        "from yaml import safe_load as parse\nparse(data)",
        "import yaml as y\nparse=y.safe_load_all\nparse(stream=data)",
    ],
)
def test_loader_function_module_import_aliases(source):
    report = review_bytes(source.encode())
    assert report.status == "NO_REVIEW_FINDINGS"
    assert len(report.findings) == 1
    assert report.findings[0].kind == "SAFE_CALL_SHAPE"


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.load(data)",
        "import yaml\nyaml.load_all(data)",
        "import yaml\nyaml.load(data,Loader=yaml.Loader)",
        "import yaml\nyaml.load(data,Loader=yaml.FullLoader)",
        "import yaml\nyaml.unsafe_load(data)",
        "import yaml\nyaml.unsafe_load_all(data)",
        "import yaml\nyaml.full_load(data)",
        "import yaml\nyaml.full_load_all(data)",
    ],
)
def test_selected_yaml_review_contract(source):
    report = review_bytes(source.encode())
    assert report.status == "REVIEW"
    assert report.review_required
    assert report.exploitability_status == "OPEN"


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.load(data,Loader=SafeLoader)",
        "import yaml\nSafeLoader=other\nyaml.load(data,Loader=SafeLoader)",
        "import yaml\nfrom fake import SafeLoader\nyaml.load(data,Loader=SafeLoader)",
        "import yaml\nclass SafeLoader:\n pass\nyaml.load(data,Loader=SafeLoader)",
        "import yaml\ndef SafeLoader():\n pass\nyaml.load(data,Loader=SafeLoader)",
        "import yaml\nSafeLoader=yaml.Loader\nyaml.load(data,Loader=SafeLoader)",
        "import yaml\ndef parse(data,Loader=yaml.SafeLoader):\n yaml.load(data,Loader=Loader)",
        "import yaml\nyaml.load(data,Loader='SafeLoader')",
        "import yaml\nyaml.load(data,Loader=None)",
        "import yaml\nyaml.load(data,Loader=get_loader())",
        "import yaml\nyaml.load(data,Loader=yaml.SafeLoader())",
    ],
)
def test_loader_not_guessed_by_name(source):
    report = review_bytes(source.encode())
    assert not any(f.kind == "SAFE_CALL_SHAPE" for f in report.findings)
    assert report.status in {"OPEN", "REVIEW"}


@pytest.mark.parametrize(
    "call",
    [
        "yaml.load()",
        "yaml.load(Loader=yaml.SafeLoader)",
        "yaml.load(data,yaml.SafeLoader,other)",
        "yaml.load(data,yaml.SafeLoader,Loader=yaml.SafeLoader)",
        "yaml.load(data,stream=data,Loader=yaml.SafeLoader)",
        "yaml.load(data,Loader=yaml.SafeLoader,extra=other)",
        "yaml.load(*args,Loader=yaml.SafeLoader)",
        "yaml.load(data,**kwargs)",
        "yaml.safe_load()",
        "yaml.safe_load(data,Loader=yaml.SafeLoader)",
        "yaml.safe_load(data,extra)",
        "yaml.safe_load(data,stream=data)",
        "yaml.safe_load(*args)",
        "yaml.safe_load(**kwargs)",
        "yaml.load(data,Loader=yaml.SafeLoader,Loader=yaml.SafeLoader)",
    ],
)
def test_loader_argument_contract_errors_open(call):
    report = review_bytes(("import yaml\n" + call).encode())
    assert report.status == "OPEN"
    assert not any(f.kind == "SAFE_CALL_SHAPE" for f in report.findings)
