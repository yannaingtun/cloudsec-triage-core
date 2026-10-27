# Client side: scanners plus the HTTP client. No torch, no GPU.
#
# The scanner profile is baked in at build time, because a profile is a
# property of the image, not of the run: a container built for the pinned
# profile must not silently fall back to latest.
#
#   docker build -f docker/client.Dockerfile --build-arg PROFILE=latest -t cloudsec-client:dev .
#   docker run --rm --network host -v "$PWD:/work:ro" cloudsec-client:dev \
#     /work/demo.tf --profile latest --url http://127.0.0.1:8100
#
# --network host is required on Linux: the service binds 127.0.0.1, which a
# bridged container cannot reach.
FROM python:3.12-slim

ARG PROFILE=latest
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl tar \
 && rm -rf /var/lib/apt/lists/*

# install_scanners.sh builds the checkov venv with uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /opt/cloudsec
COPY pyproject.toml README.md scanners.toml ./
COPY cloudsec ./cloudsec
COPY scripts ./scripts
RUN pip install -e .

RUN scripts/install_scanners.sh "$PROFILE"
RUN "tools/$PROFILE/bin/checkov" --version \
 && "tools/$PROFILE/bin/trivy" --version | head -1

ENTRYPOINT ["python", "-m", "cloudsec.client"]
