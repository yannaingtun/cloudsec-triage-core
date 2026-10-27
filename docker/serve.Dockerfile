# Triage service image. Separate from docker/Dockerfile, which builds the
# scanner image for CI: that one must stay torch-free, this one is nothing but.
#
#   docker build -f docker/serve.Dockerfile -t cloudsec-serve:dev .
#
# The base supplies torch built for this architecture and GPU. On DGX Spark
# that means an aarch64 image covering Blackwell; pick the newest tag NVIDIA
# publishes for it and pass it as BASE if the default is wrong.
ARG BASE=nvcr.io/nvidia/pytorch:25.09-py3
FROM ${BASE}

WORKDIR /opt/cloudsec

# The serve extra deliberately omits torch, but accelerate and peft require it,
# so pip could still pull a CPU wheel over the base image's CUDA build and the
# failure would only appear at inference. Record what the base has, install,
# then fail the build if torch lost its CUDA support.
RUN python -c "import torch; print(torch.__version__, torch.version.cuda)" > /tmp/torch-before

COPY pyproject.toml README.md ./
COPY cloudsec ./cloudsec
RUN pip install --no-cache-dir -e ".[serve]"

RUN python - <<'PY'
import sys, torch
before = open("/tmp/torch-before").read().split()
print("before:", before, "after:", torch.__version__, torch.version.cuda)
if torch.version.cuda is None:
    sys.exit("pip replaced the CUDA torch with a CPU build; pin it or use --no-deps")
PY

# Weights are mounted, not copied: 16 GB in a layer is painful to rebuild and
# the checkpoint changes on its own schedule.
VOLUME /models
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10m --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=4)" || exit 1

ENTRYPOINT ["python", "-m", "cloudsec.serve.app", "--host", "0.0.0.0", "--port", "8100"]
