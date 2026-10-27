"""Triage service: POST a prompt, get the model's text back.

    POST /generate  {"prompt": "..."}  ->  {"text": "...", ...}
    GET  /health                       ->  checkpoint, dtype, device, fingerprint

Loads the model once at startup. infer.py pays three and a half minutes of
weight loading on every run; this pays it once. Generation is serialised behind
a lock because one resident model is the resource and interleaved generate()
calls are not what the evaluation measured. Requests past the queue limit get
503 rather than piling up behind it.

The client half of this contract is HttpModel in cloudsec/web/app.py, which
satisfies the Model Protocol in cloudsec/pipeline.py, so the dashboard, the CI
adapter and a future editor extension all reach the model the same way.

    pip install -e ".[serve]"
    python -m cloudsec.serve.app --model models/Llama-3.1-8B-CloudSec-merged
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cloudsec.builder import build_input
from cloudsec.models import Finding, IaCFile
from cloudsec.parse import parse_output
from cloudsec.prompt import build_prompt
from cloudsec.serve import model as m
from cloudsec.serve import thermal
from cloudsec.serve.thermal import gpu_temp
from cloudsec.serve import confidence as conf

MAX_QUEUE = 4
# Refuse work above this GPU temperature. 0 disables the check, which is
# the default: it exists for a machine with known cooling trouble, not as
# a policy for healthy ones. A hardware thermal trip takes the whole box
# down mid-write; a 503 only costs one request.
MAX_TEMP = int(os.environ.get("CLOUDSEC_MAX_TEMP", "0"))
# Pause mid-generation above PAUSE_TEMP until the machine falls to RESUME_TEMP.
# 0 disables it, which is the default and what a cloud deployment should use:
# this exists for a box with known cooling trouble, not as a serving policy.
PAUSE_TEMP = int(os.environ.get("CLOUDSEC_PAUSE_TEMP", "0"))
RESUME_TEMP = int(os.environ.get("CLOUDSEC_RESUME_TEMP", "60"))
PAUSE_MAX_WAIT = float(os.environ.get("CLOUDSEC_PAUSE_MAX_WAIT", "600"))

STATE: dict = {}
LOCK = threading.Lock()
_waiting = 0
_waiting_lock = threading.Lock()


class Req(BaseModel):
    prompt: str
    max_new_tokens: int | None = None


class FileIn(BaseModel):
    path: str
    content: str


class FindingIn(BaseModel):
    """Mirrors cloudsec.models.Finding; field names are the wire format."""

    tool: str
    check_id: str
    severity: str
    title: str
    start_line: int
    end_line: int


class TriageReq(BaseModel):
    file: FileIn
    findings: list[FindingIn]
    max_new_tokens: int | None = None
    include_raw: bool = False


def _warm():
    """One tiny generation so the first real request is not an outlier."""
    import torch

    tok, model = STATE["tokenizer"], STATE["model"]
    enc = tok("### Instruction:\n", return_tensors="pt")
    inputs = {k: v.to(model.device) for k, v in enc.items()
              if k in ("input_ids", "attention_mask")}
    with torch.no_grad():
        model.generate(**inputs, max_new_tokens=8, do_sample=False,
                       pad_token_id=tok.pad_token_id)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import transformers

    path = os.environ.get("CLOUDSEC_MODEL")
    if not path:
        raise RuntimeError("set CLOUDSEC_MODEL to the checkpoint directory")

    plan = m.plan(
        path, transformers.__version__,
        base_model=os.environ.get("CLOUDSEC_BASE_MODEL"),
        dtype=os.environ.get("CLOUDSEC_DTYPE", "bfloat16"),
        load_in_4bit=os.environ.get("CLOUDSEC_4BIT") == "1",
    )
    print(f"loading {plan.kind} from {plan.model_path}  "
          f"{plan.dtype_kwarg}={plan.dtype}  transformers {transformers.__version__}")
    model, tokenizer = m.load(plan)
    if tokenizer.pad_token_id == tokenizer.eos_token_id:
        print("[warn] pad and eos share an id; this checkpoint predates the EOS "
              "fix and may not terminate reliably")

    STATE.update(
        model=model, tokenizer=tokenizer, plan=plan,
        fingerprint=m.fingerprint(plan.model_path),
        max_new_tokens=int(os.environ.get("CLOUDSEC_MAX_NEW_TOKENS", "6144")),
        transformers=transformers.__version__,
        loaded_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )
    tp_ids, fp_ids = conf.label_token_ids(tokenizer)
    STATE["label_ids"] = (tp_ids, fp_ids)
    print(f"label tokens: {len(tp_ids)} TP, {len(fp_ids)} FP")
    _warm()
    print(f"ready: {plan.model_path} [{STATE['fingerprint']}] on {model.device}")
    yield
    STATE.clear()


app = FastAPI(title="cloudsec-triage", lifespan=lifespan)


@app.get("/health")
def health():
    """Provenance. Every verdict should be traceable to a checkpoint."""
    p = STATE["plan"]
    return {
        "model": p.model_path,
        "kind": p.kind,
        "base_model": p.base_model,
        "fingerprint": STATE["fingerprint"],
        "dtype": p.dtype,
        "load_in_4bit": p.load_in_4bit,
        "device": str(STATE["model"].device),
        "transformers": STATE["transformers"],
        "max_new_tokens": STATE["max_new_tokens"],
        "loaded_at": STATE["loaded_at"],
        "queued": _waiting,
    }


@contextmanager
def _slot():
    """Bounded queue in front of the single resident model."""
    global _waiting
    if MAX_TEMP:
        t = gpu_temp()
        if t is not None and t >= MAX_TEMP:
            raise HTTPException(503, f"gpu at {t}C, limit {MAX_TEMP}C")
    with _waiting_lock:
        if _waiting >= MAX_QUEUE:
            raise HTTPException(503, f"{_waiting} requests already queued")
        _waiting += 1
    try:
        yield
    finally:
        with _waiting_lock:
            _waiting -= 1


def _run(prompt: str, cap: int | None, want_conf: bool = False) -> dict:
    """One generation. The caller holds a queue slot."""
    import torch

    tok, model = STATE["tokenizer"], STATE["model"]
    cap = cap or STATE["max_new_tokens"]

    enc = tok(prompt, return_tensors="pt")
    inputs = {k: v.to(model.device) for k, v in enc.items()
              if k in ("input_ids", "attention_mask")}
    n_prompt = inputs["input_ids"].shape[1]

    proc = pauser = None
    procs = []
    if want_conf and STATE.get("label_ids"):
        proc = conf.make_processor(*STATE["label_ids"])
        procs.append(proc)
    if PAUSE_TEMP:
        pauser = thermal.make_pauser(PAUSE_TEMP, RESUME_TEMP,
                                     max_wait=PAUSE_MAX_WAIT)
        procs.append(pauser)
    extra = {"logits_processor": procs} if procs else {}

    started = time.time()
    with LOCK, torch.no_grad():
        out = model.generate(
            **inputs, max_new_tokens=cap, do_sample=False,
            eos_token_id=tok.eos_token_id, pad_token_id=tok.pad_token_id,
            **extra)

    gen = out[0][n_prompt:]
    eos = bool(tok.eos_token_id in gen.tolist())
    # Report cooling stalls apart from generation, so latency stays comparable
    # between a healthy machine and a throttled one.
    paused = round(pauser.paused_seconds, 1) if pauser else 0.0
    seconds = round(time.time() - started - paused, 1)
    print(f"  {n_prompt:>6} prompt  {len(gen):>5} new  "
          f"eos={'y' if eos else 'N'}  {seconds}s", flush=True)
    return {
        "text": tok.decode(gen, skip_special_tokens=True).strip(),
        "prompt_tokens": int(n_prompt),
        "tokens": int(len(gen)),
        "stopped_on_eos": eos,
        "seconds": seconds,
        "model": STATE["plan"].model_path,
        "fingerprint": STATE["fingerprint"],
        "label_steps": proc.steps if proc else None,
        "paused_seconds": paused,
        "pauses": pauser.pauses if pauser else 0,
        "peak_temp": pauser.peak if pauser else None,
    }


@app.post("/generate")
def generate(r: Req):
    """Raw prompt in, raw text out. The escape hatch for experiments."""
    with _slot():
        return _run(r.prompt, r.max_new_tokens)


@app.post("/triage")
def triage(r: TriageReq):
    """Findings in, verdicts out.

    build_input, build_prompt and parse_output all have to agree with the
    weights byte for byte, so they run here rather than in every client. A
    client sends what its scanners found and renders its own report, which
    keeps the report format a client concern and the training format a server
    one. One verdict comes back per finding, in input order, occurrence kept.
    """
    file = IaCFile(path=r.file.path, content=r.file.content)
    findings = [
        Finding(tool=f.tool, check_id=f.check_id, severity=f.severity,
                title=f.title, start_line=f.start_line, end_line=f.end_line)
        for f in r.findings
    ]

    prompt = build_prompt(build_input(file, findings))
    with _slot():
        out = _run(prompt, r.max_new_tokens, want_conf=True)

    context, verdicts = parse_output(out["text"], findings)

    # One label step per addressed verdict, or none at all: a mismatch means
    # the model wrote a label somewhere that is not a verdict line, and
    # guessing the alignment would attach a confidence to the wrong finding.
    steps = out.get("label_steps") or []
    addressed = [v for v in verdicts if v.label is not None]
    confs = conf.confidences(steps) if len(steps) == len(addressed) else []
    by_verdict = dict(zip((id(v) for v in addressed), confs)) if confs else {}
    body = {
        "context": asdict(context) if context else None,
        "verdicts": [{**asdict(v), "confidence": by_verdict.get(id(v))}
                     for v in verdicts],
        "confidence_aligned": bool(by_verdict),
        "label_steps": len(steps),
        "unaddressed": sum(v.label is None for v in verdicts),
        "prompt_tokens": out["prompt_tokens"],
        "tokens": out["tokens"],
        "stopped_on_eos": out["stopped_on_eos"],
        "seconds": out["seconds"],
        "paused_seconds": out.get("paused_seconds", 0.0),
        "pauses": out.get("pauses", 0),
        "peak_temp": out.get("peak_temp"),
        "model": out["model"],
        "fingerprint": out["fingerprint"],
    }
    if r.include_raw:
        body["raw"] = out["text"]
    return body


def main():
    import argparse

    import uvicorn

    p = argparse.ArgumentParser(prog="python -m cloudsec.serve.app")
    p.add_argument("--model", required=True, help="checkpoint directory")
    p.add_argument("--base-model", help="only for a LoRA adapter")
    p.add_argument("--dtype", default="bfloat16", choices=list(m.DTYPES))
    p.add_argument("--load-in-4bit", action="store_true",
                   help="changes the outputs; unnecessary with enough memory")
    p.add_argument("--max-new-tokens", type=int, default=6144)
    p.add_argument("--host", default="127.0.0.1",
                   help="localhost by default; /generate has no authentication")
    p.add_argument("--port", type=int, default=8100)
    a = p.parse_args()

    os.environ["CLOUDSEC_MODEL"] = a.model
    if a.base_model:
        os.environ["CLOUDSEC_BASE_MODEL"] = a.base_model
    os.environ["CLOUDSEC_DTYPE"] = a.dtype
    if a.load_in_4bit:
        os.environ["CLOUDSEC_4BIT"] = "1"
    os.environ["CLOUDSEC_MAX_NEW_TOKENS"] = str(a.max_new_tokens)
    uvicorn.run(app, host=a.host, port=a.port, workers=1)


if __name__ == "__main__":
    main()
