"""Load the fine-tuned model for serving, the way evaluation loads it.

Only a handful of decisions change the generated text: the dtype, the keyword
transformers wants it under, whether the directory is a merged model or a LoRA
adapter, and which directory the tokenizer comes from. They all live here.

IaC_cicd/repo's infer.py makes the same decisions for batch evaluation, and
tests/test_serve.py checks the two have not drifted whenever that repo is
checked out beside this one. Same arrangement as tests/test_prompt.py, which
pins PROMPT_TEMPLATE against the same file.

torch and transformers are imported inside load(), so importing this module
costs nothing until a model is actually loaded. That keeps `cloudsec` usable
on a CI runner with no GPU and no torch.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DTYPES = ("bfloat16", "float16", "float32")

# transformers 4.56 renamed from_pretrained's `torch_dtype` to `dtype`.
# from_pretrained takes **kwargs, so the wrong name is silently ignored and the
# model quietly loads in fp32. Pick by version rather than trying both.
DTYPE_RENAMED_IN = "4.56"


def dtype_kwarg(transformers_version: str) -> str:
    from packaging.version import parse

    return "dtype" if parse(transformers_version) >= parse(DTYPE_RENAMED_IN) else "torch_dtype"


@dataclass(frozen=True)
class Plan:
    """Every decision that affects what the model generates. No side effects."""

    model_path: str
    base_model: str | None
    is_adapter: bool
    tokenizer_from: str
    dtype: str
    dtype_kwarg: str
    load_in_4bit: bool

    @property
    def kind(self) -> str:
        return "adapter" if self.is_adapter else "merged-or-base"


def plan(model_path: str, transformers_version: str, base_model: str | None = None,
         dtype: str = "bfloat16", load_in_4bit: bool = False) -> Plan:
    """Resolve how this directory should be loaded.

    An adapter directory carries the tokenizer used in training, including its
    distinct pad token, so it is preferred over the base model's tokenizer.
    """
    if dtype not in DTYPES:
        raise ValueError(f"dtype must be one of {DTYPES}, got {dtype!r}")
    path = Path(model_path)
    if model_path.startswith((".", "/")) and not path.is_dir():
        # transformers treats a missing local path as a Hugging Face repo id
        # and fails with an unrelated validation error. Say what is wrong.
        raise FileNotFoundError(f"{model_path} is not a directory")
    adapter_config = path / "adapter_config.json"
    is_adapter = adapter_config.exists()

    base = base_model
    if is_adapter and base is None:
        import json
        base = json.loads(adapter_config.read_text(encoding="utf-8")).get(
            "base_model_name_or_path")

    return Plan(
        model_path=str(path),
        base_model=base,
        is_adapter=is_adapter,
        tokenizer_from=str(path),   # the adapter dir, or the merged dir
        dtype=dtype,
        dtype_kwarg=dtype_kwarg(transformers_version),
        load_in_4bit=load_in_4bit,
    )


def load(p: Plan):
    """-> (model, tokenizer). Imports torch and transformers."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch_dtype = {"bfloat16": torch.bfloat16, "float16": torch.float16,
                   "float32": torch.float32}[p.dtype]

    kwargs: dict = {"device_map": "auto"}
    if p.load_in_4bit:
        from transformers import BitsAndBytesConfig
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_compute_dtype=torch_dtype,
            bnb_4bit_use_double_quant=True, bnb_4bit_quant_type="nf4")
    else:
        kwargs[p.dtype_kwarg] = torch_dtype

    source = p.base_model if p.is_adapter else p.model_path
    model = AutoModelForCausalLM.from_pretrained(str(source), **kwargs)
    if p.is_adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, p.model_path)

    tokenizer = AutoTokenizer.from_pretrained(p.tokenizer_from)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    model.eval()
    model.config.use_cache = True
    return model, tokenizer


def fingerprint(model_path: str) -> str:
    """Cheap checkpoint identity: configs hashed, weights by name and size.

    Enough to notice a swapped config or a different shard set. Not a content
    hash of 16 GB of weights, and does not claim to be.
    """
    import hashlib

    path = Path(model_path)
    h = hashlib.sha256()
    for name in ("config.json", "tokenizer.json", "generation_config.json"):
        f = path / name
        if f.exists():
            h.update(f.read_bytes())
    for f in sorted(path.glob("*.safetensors")):
        h.update(f"{f.name}:{f.stat().st_size}".encode())
    return h.hexdigest()[:16]
