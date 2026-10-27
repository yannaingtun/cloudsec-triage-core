"""cloudsec/serve must load the model the way evaluation loads it.

plan() is pure, so the decisions that silently change generated text can be
asserted without torch, a GPU or a real checkpoint.
"""

import json
from pathlib import Path

import pytest

from cloudsec.serve import model

ROOT = Path(__file__).resolve().parent.parent
INFER = ROOT.parent / "repo" / "infer.py"


def test_dtype_kwarg_follows_the_transformers_rename():
    assert model.dtype_kwarg("4.55.2") == "torch_dtype"
    assert model.dtype_kwarg("4.56.0") == "dtype"
    assert model.dtype_kwarg("5.5.0") == "dtype"


def test_merged_directory_loads_itself(tmp_path):
    (tmp_path / "config.json").write_text("{}")
    p = model.plan(str(tmp_path), "5.5.0")
    assert not p.is_adapter and p.kind == "merged-or-base"
    assert p.base_model is None
    assert p.tokenizer_from == str(tmp_path)


def test_adapter_takes_its_base_from_adapter_config(tmp_path):
    (tmp_path / "adapter_config.json").write_text(
        json.dumps({"base_model_name_or_path": "models/llama31-8b"}))
    p = model.plan(str(tmp_path), "5.5.0")
    assert p.is_adapter and p.kind == "adapter"
    assert p.base_model == "models/llama31-8b"
    # The adapter directory carries the tokenizer used in training, including
    # its distinct pad token, so it wins over the base model's.
    assert p.tokenizer_from == str(tmp_path)


def test_explicit_base_model_overrides_adapter_config(tmp_path):
    (tmp_path / "adapter_config.json").write_text(
        json.dumps({"base_model_name_or_path": "/app/models/llama31-8b"}))
    p = model.plan(str(tmp_path), "5.5.0", base_model="models/llama31-8b")
    assert p.base_model == "models/llama31-8b"


def test_unknown_dtype_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="dtype must be one of"):
        model.plan(str(tmp_path), "5.5.0", dtype="int8")


@pytest.mark.skipif(not INFER.exists(), reason="IaC_cicd/repo/infer.py not available")
def test_loading_decisions_match_infer_py():
    """A tripwire, not a proof.

    infer.py and this module both decide dtype, the transformers dtype keyword
    and adapter detection. If one changes and the other does not, the served
    model silently stops matching the evaluated one.
    """
    src = INFER.read_text(encoding="utf-8")
    assert f'parse_version("{model.DTYPE_RENAMED_IN}")' in src, \
        "infer.py no longer keys the dtype kwarg on 4.56"
    assert "adapter_config.json" in src, \
        "infer.py no longer detects adapters by adapter_config.json"
    for name in model.DTYPES:
        assert name in src, f"infer.py no longer offers dtype {name}"
