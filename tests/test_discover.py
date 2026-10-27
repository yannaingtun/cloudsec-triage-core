import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from cloudsec.builder import parse_input
from cloudsec.discover import changed_paths, find_iac_files, iac_kind

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests/data/test.jsonl"

TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
K8S = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
CFN_YAML = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"
CFN_JSON = '{\n  "Resources": {\n    "B": {"Type": "AWS::S3::Bucket"}\n  }\n}\n'
CFN_COOKIE = '{\n  "AWSTemplateFormatVersion": "2010-09-09",\n  "Default": "{{cookiecutter.slug}}"\n}\n'
HELM = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Values.name }}\n"
OTHER = "name: ci\non: push\n"


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_finds_only_scannable_iac(tmp_path):
    for rel, text in [("infra/main.tf", TF), ("k8s/pod.yaml", K8S), ("cfn/stack.yml", CFN_YAML),
                      ("cfn/stack.json", CFN_JSON), ("cfn/cookie.json", CFN_COOKIE), ("charts/pod.yaml", HELM), (".github/ci.yml", OTHER),
                      (".terraform/modules/m/main.tf", TF), ("node_modules/x/pod.yaml", K8S),
                      ("big.tf", TF + "#" * 1_000_001)]:
        write(tmp_path, rel, text)
    assert [f.path for f in find_iac_files(tmp_path)] == [
        "cfn/cookie.json", "cfn/stack.json", "cfn/stack.yml", "infra/main.tf", "k8s/pod.yaml"]


def test_every_gold_file_is_detected():
    spec = importlib.util.spec_from_file_location("drift_check", ROOT / "scripts/drift_check.py")
    dc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dc)
    missed = []
    for i, line in enumerate(open(DATA, encoding="utf-8")):
        r = json.loads(line)
        file, _ = parse_input(r["input"])
        iac_type = r["output"].split("\n", 1)[0].split(":", 1)[1].strip()
        name = dc.filename_for(iac_type, file.content)
        if iac_kind(name, file.content) is None:
            missed.append((i, iac_type, name))
    assert missed == []


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                   check=True, capture_output=True)


def test_changed_paths(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, "a.tf", TF)
    write(tmp_path, "b.tf", TF)
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    write(tmp_path, "b.tf", TF + "# changed\n")
    write(tmp_path, "c.tf", TF)
    (tmp_path / "a.tf").unlink()
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "change")
    assert changed_paths(tmp_path, base) == {"b.tf", "c.tf"}


def test_changed_paths_explains_missing_base(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, "a.tf", TF)
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    with pytest.raises(RuntimeError, match="GIT_DEPTH"):
        changed_paths(tmp_path, "0" * 40)
