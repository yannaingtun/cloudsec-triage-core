import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from cloudsec import scan
from cloudsec.builder import parse_input
from cloudsec.ci import gitlab
from cloudsec.models import Finding

ROOT = Path(__file__).resolve().parent.parent
TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'


def finding(line=1):
    return Finding(tool="checkov", check_id="CKV_TEST_1", severity="HIGH",
                   title="test", start_line=line, end_line=line + 2)


@pytest.fixture
def fake_scanners(monkeypatch):
    """Scanners 'installed'; b.tf fails to scan, every other file has one finding."""
    monkeypatch.setattr(scan, "tools_dir", lambda profile: Path("."))

    def fake_scan(file, profile=None):
        if file.path.endswith("b.tf"):
            raise scan.ScannerError("boom")
        return [finding()]
    monkeypatch.setattr(scan, "scan_file", fake_scan)


def run(root, *extra, env=None):
    report = root / "report.json"
    code = gitlab.main(["--root", str(root), "--report", str(report), "--profile", "training", *extra],
                       env=env or {})
    data = json.loads(report.read_text()) if report.exists() else None
    return code, data


def test_missing_scanners_exit_2(tmp_path, monkeypatch):
    def missing(profile):
        raise scan.ScannerError("not installed")
    monkeypatch.setattr(scan, "tools_dir", missing)
    (tmp_path / "a.tf").write_text(TF)
    code, data = run(tmp_path)
    assert (code, data) == (2, None)


def test_scan_failure_is_skipped_not_fatal(tmp_path, fake_scanners, capsys):
    (tmp_path / "a.tf").write_text(TF)
    (tmp_path / "b.tf").write_text(TF)
    code, data = run(tmp_path)
    assert code == 0
    assert [e["location"]["path"] for e in data] == ["a.tf"]
    out = capsys.readouterr()
    assert "could not scan b.tf" in out.err
    assert "2 IaC files, 1 scanned, 1 failed, 1 findings" in out.out
    assert "not a merge request" in out.out


def test_all_files_failing_exit_1(tmp_path, fake_scanners):
    (tmp_path / "b.tf").write_text(TF)
    code, data = run(tmp_path)
    assert (code, data) == (1, [])


def test_no_iac_files_gives_empty_report(tmp_path, fake_scanners):
    (tmp_path / "README.md").write_text("hello\n")
    code, data = run(tmp_path)
    assert (code, data) == (0, [])


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def test_merge_request_counts_changed_iac_files(tmp_path, fake_scanners, capsys):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.tf").write_text(TF)
    (tmp_path / "c.tf").write_text(TF)
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    base = git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "c.tf").write_text(TF + "# changed\n")
    git(tmp_path, "commit", "-qam", "change")
    code, data = run(tmp_path, env={"CI_MERGE_REQUEST_DIFF_BASE_SHA": base})
    assert code == 0 and len(data) == 2  # scan scope stays all files
    assert "changed IaC files: 1" in capsys.readouterr().out


def installed():
    try:
        scan.tools_dir("training")
        return True
    except scan.ScannerError:
        return False


@pytest.mark.skipif(not installed(), reason="training scanners not installed")
def test_real_scanners_on_a_gold_file(tmp_path):
    spec = importlib.util.spec_from_file_location("drift_check", ROOT / "scripts/drift_check.py")
    dc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dc)
    r = json.loads(open(ROOT / "tests/data/test.jsonl", encoding="utf-8").readline())
    file, gold = parse_input(r["input"])
    iac_type = r["output"].split("\n", 1)[0].split(":", 1)[1].strip()
    name = dc.filename_for(iac_type, file.content)
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / name).write_text(file.content, encoding="utf-8")
    code, data = run(tmp_path)
    assert code == 0
    assert {e["location"]["path"] for e in data} == {f"infra/{name}"}
    assert {e["check_name"] for e in data if e["check_name"].startswith("checkov:")} == \
        {f"checkov:{f.check_id}" for f in gold if f.tool == "checkov"}
