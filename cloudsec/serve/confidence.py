"""Per-verdict confidence, taken from the model's own distribution.

At the moment the model writes TP in "CKV_AWS_18: TP [High]" there is a
distribution over the vocabulary. Renormalising it over just the TP and FP
tokens gives P(TP) for that finding: a real probability, unlike a confidence
the model writes out as text, which is only more generated tokens.

Keeping every step's logits would be half a gigabyte per request, so a
LogitsProcessor records two scalars per step instead.

Alignment avoids character offsets entirely. Greedy decoding commits to the
argmax, verdicts are emitted in input order, and parse_output returns them in
input order, so the k-th step whose argmax is a label token is the k-th
verdict. If the counts disagree, something was emitted that is not a verdict
and no confidences are attached, which fails loudly rather than misaligning.
"""

from __future__ import annotations


def label_token_ids(tokenizer) -> tuple[set[int], set[int]]:
    """Token ids that decode to TP and to FP, however the tokenizer spells them.

    A label may be tokenized with or without a leading space depending on what
    precedes it, so this scans the vocabulary rather than assuming one form.
    """
    tp, fp = set(), set()
    for tok, i in tokenizer.get_vocab().items():
        if "TP" not in tok and "FP" not in tok:
            continue
        try:
            s = tokenizer.convert_tokens_to_string([tok]).strip()
        except Exception:
            continue
        if s == "TP":
            tp.add(i)
        elif s == "FP":
            fp.add(i)
    return tp, fp


def make_processor(tp_ids: set[int], fp_ids: set[int]):
    """A LogitsProcessor that collects (p_tp, p_fp) at each label step."""
    import torch
    from transformers import LogitsProcessor

    class LabelProbs(LogitsProcessor):
        def __init__(self):
            self.tp = torch.tensor(sorted(tp_ids))
            self.fp = torch.tensor(sorted(fp_ids))
            self.labels = tp_ids | fp_ids
            self.steps: list[tuple[float, float]] = []

        def __call__(self, input_ids, scores):
            row = scores[0]
            if int(row.argmax()) in self.labels:
                p = torch.softmax(row.float(), dim=-1)
                self.steps.append((float(p[self.tp.to(p.device)].sum()),
                                   float(p[self.fp.to(p.device)].sum())))
            return scores

    return LabelProbs()


def confidences(steps: list[tuple[float, float]]) -> list[float]:
    """P(TP) per verdict, renormalised over the two labels.

    Always P(TP), never P(chosen): an FP at 0.49 and a TP at 0.51 should read
    as adjacent, not as equally confident.
    """
    out = []
    for p_tp, p_fp in steps:
        total = p_tp + p_fp
        out.append(round(p_tp / total, 4) if total > 0 else None)
    return out
