"""GPU temperature, for refusing work on a machine that is already too hot.

Software cannot cool anything. This exists so the service declines a request
instead of the hardware cutting power mid-generation, which loses the request,
the container and anything mid-write elsewhere on the box.

Returns None when the temperature cannot be read, and callers treat that as
"no opinion" rather than "too hot": a broken reader must not take the service
down.
"""

from __future__ import annotations

import shutil
import subprocess


def _via_pynvml() -> int | None:
    try:
        import pynvml
        pynvml.nvmlInit()
        h = pynvml.nvmlDeviceGetHandleByIndex(0)
        return int(pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU))
    except Exception:
        return None


def _via_smi() -> int | None:
    if not shutil.which("nvidia-smi"):
        return None
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5)
        return int(out.stdout.strip().splitlines()[0])
    except Exception:
        return None


def gpu_temp() -> int | None:
    return _via_pynvml() or _via_smi()


def zone_temps() -> dict[str, int]:
    """Every ACPI thermal zone, which on this platform includes SoC and CPU.

    The GPU is not always the hottest thing in the chassis, and the zones are
    what the firmware trips on.
    """
    from pathlib import Path as _P

    out = {}
    for z in sorted(_P("/sys/class/thermal").glob("thermal_zone*")):
        try:
            out[(z / "type").read_text().strip()] = int((z / "temp").read_text()) // 1000
        except Exception:
            continue
    return out


def gpu_stats() -> dict:
    """Utilisation and memory, for a client explaining what the GPU is doing.

    Empty dict when unreadable: a missing reading must not break /health.
    """
    try:
        import pynvml
        pynvml.nvmlInit()
        h = pynvml.nvmlDeviceGetHandleByIndex(0)
        u = pynvml.nvmlDeviceGetUtilizationRates(h)
        m = pynvml.nvmlDeviceGetMemoryInfo(h)
        return {"util": int(u.gpu),
                "mem_used_gb": round(m.used / 2 ** 30, 1),
                "mem_total_gb": round(m.total / 2 ** 30, 1)}
    except Exception:
        return {}


def hottest() -> int | None:
    """The highest reading anywhere, GPU or zone. None if nothing is readable."""
    vals = [v for v in (gpu_temp(),) if v is not None]
    vals += [v for v in zone_temps().values() if 0 < v < 200]
    return max(vals) if vals else None


def make_pauser(pause_at: int, resume_at: int, every: int = 16,
                max_wait: float = 600.0):
    """A LogitsProcessor that stalls generation while the machine is too hot.

    Checked every `every` steps rather than every step: a temperature read is
    cheap but not free, and thermal mass does not change in 80 milliseconds.

    max_wait bounds the stall, because a machine that never reaches resume_at
    should give the caller a slow answer rather than hang forever.
    """
    import time as _t

    from transformers import LogitsProcessor

    class ThermalPause(LogitsProcessor):
        def __init__(self):
            self.paused_seconds = 0.0
            self.pauses = 0
            self.peak = 0
            self._n = 0

        def __call__(self, input_ids, scores):
            self._n += 1
            if self._n % every:
                return scores
            t = hottest()
            if t is None:
                return scores
            self.peak = max(self.peak, t)
            if t < pause_at:
                return scores

            self.pauses += 1
            start = _t.time()
            print(f"[thermal] pausing generation at {t}C, "
                  f"waiting for {resume_at}C", flush=True)
            while _t.time() - start < max_wait:
                _t.sleep(2)
                t = hottest()
                if t is not None and t <= resume_at:
                    break
            waited = _t.time() - start
            self.paused_seconds += waited
            print(f"[thermal] resuming at {t}C after {waited:.0f}s", flush=True)
            return scores

    return ThermalPause()
