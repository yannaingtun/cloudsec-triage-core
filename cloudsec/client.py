"""Client half of the /triage contract.

The server owns everything that must agree with the weights byte for byte:
the input renderer, the instruction, and the verdict grammar. The client owns
the scanners, whose versions are a property of where the scan runs, and the
report, whose format is a property of who reads it.

    from cloudsec import client
    c = client.TriageClient("http://127.0.0.1:8100")
    result = client.run_file(Path("main.tf"), c)

The FileResult returned is the same type cloudsec.pipeline produces, so
report/codequality.py and the dashboard render a remote run exactly as they
render a local one.

    python -m cloudsec.client main.tf --url http://127.0.0.1:8100
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from cloudsec.models import FileContext, Finding, IaCFile, Verdict
from cloudsec.pipeline import FileResult, pair
from cloudsec.scan import scan_file


USER_AGENT = "cloudsec-client/1.0"


def _headers() -> dict[str, str]:
    """Cloudflare Access service-token headers, when the service is behind one.

    An identity policy redirects to a login page, which an HTTP client cannot
    complete, so a program needs a service token. Read from the environment so
    a secret never lands in a config file or the repo.

    The User-Agent is not cosmetic: Cloudflare returns 403 to urllib's default
    "Python-urllib/3.12" before Access is even consulted, so a request with
    perfectly good credentials is rejected without explanation.
    """
    h = {"User-Agent": USER_AGENT}
    i = os.environ.get("CLOUDSEC_CF_CLIENT_ID")
    k = os.environ.get("CLOUDSEC_CF_CLIENT_SECRET")
    if i and k:
        h["CF-Access-Client-Id"] = i
        h["CF-Access-Client-Secret"] = k
    return h


class TriageError(RuntimeError):
    """The service refused the request or could not be reached."""


@dataclass(frozen=True)
class TriageClient:
    base_url: str = "http://127.0.0.1:8100"
    timeout: float = 600.0   # a 40-finding file is minutes, not seconds

    def _url(self, route: str) -> str:
        return self.base_url.rstrip("/") + route

    def health(self) -> dict:
        try:
            req = urllib.request.Request(self._url("/health"),
                                         headers=_headers())
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            raise TriageError(f"{self.base_url} not answering: {e}") from e

    def triage(self, file: IaCFile,
               findings: list[Finding]) -> tuple[FileContext | None,
                                                 list[Verdict], dict]:
        payload = {
            "file": {"path": file.path, "content": file.content},
            "findings": [asdict(f) for f in findings],
            "include_raw": True,
        }
        req = urllib.request.Request(
            self._url("/triage"), data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     **_headers()})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise TriageError(
                f"/triage returned {e.code}: "
                f"{e.read().decode(errors='replace')[:200]}") from e
        except urllib.error.URLError as e:
            raise TriageError(f"{self.base_url} unreachable: {e.reason}") from e

        context = FileContext(**body["context"]) if body.get("context") else None
        verdicts = [Verdict(**v) for v in body["verdicts"]]
        # The contract is one verdict per finding, in input order. If that ever
        # breaks, pair() would silently misalign verdicts with findings.
        if len(verdicts) != len(findings):
            raise TriageError(f"service returned {len(verdicts)} verdicts for "
                              f"{len(findings)} findings")
        return context, verdicts, body


def triage(file: IaCFile, findings: list[Finding],
           client: TriageClient) -> FileResult:
    """Remote counterpart of pipeline.triage."""
    if not findings:
        return FileResult(file=file, items=[])
    context, verdicts, body = client.triage(file, findings)
    return FileResult(file=file, items=pair(findings, verdicts),
                      context=context, raw_output=body.get("raw"))


def run_file(path: Path, client: TriageClient,
             profile: str | None = None) -> FileResult:
    """Scan locally with the chosen profile, triage remotely."""
    file = IaCFile(path=str(path), content=Path(path).read_text())
    return triage(file, scan_file(file, profile), client)


def main():
    import argparse

    p = argparse.ArgumentParser(prog="python -m cloudsec.client")
    p.add_argument("file", type=Path)
    p.add_argument("--url", default="http://127.0.0.1:8100")
    p.add_argument("--profile", help="scanner profile; default from scanners.toml")
    p.add_argument("--collector", default=os.environ.get("CLOUDSEC_COLLECTOR"),
                   help="file the run with a collector; also CLOUDSEC_COLLECTOR")
    a = p.parse_args()

    c = TriageClient(a.url)
    h = c.health()
    print(f"service: {h['model']} [{h['fingerprint']}] on {h['device']}\n")

    started = time.time()
    result = run_file(a.file, c, a.profile)
    if result.context:
        x = result.context
        print(f"{x.iac_type} / {x.cloud_provider} / {x.environment}")
        print(f"{x.purpose}\n")

    for t in result.items:
        v = t.verdict
        label = v.label if v and v.label else "--"
        print(f"  [{label}] {t.finding.tool:<8} {t.finding.check_id:<28} "
              f"lines {t.finding.start_line}-{t.finding.end_line}")
        if v and v.fix:
            print(f"        fix: {v.fix}")
        if v and v.reason:
            print(f"        why: {v.reason}")

    tp = sum(1 for t in result.items if t.verdict and t.verdict.label == "TP")
    fp = sum(1 for t in result.items if t.verdict and t.verdict.label == "FP")
    if a.collector:
        from cloudsec import runs
        run = runs.build_run([result], profile=a.profile, service=h,
                             seconds=round(time.time() - started, 1),
                             source="cli")
        rid = runs.post_run(a.collector, run)
        if rid:
            print(f"\nfiled as {rid}")

    print(f"\n{len(result.items)} findings: {tp} TP, {fp} FP, "
          f"{result.unaddressed} unaddressed")


if __name__ == "__main__":
    main()
