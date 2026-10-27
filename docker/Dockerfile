# CloudSec scanner image: training-profile scanners plus the cloudsec package.
#   docker build -f docker/Dockerfile -t cloudsec:dev .
# Layout matches a source checkout (/opt/cloudsec/{scanners.toml,tools/,cloudsec/}),
# so scan.py finds scanners.toml and tools/ without extra configuration.

# Stage 1: Trivy 0.58.2 from the tag. The upstream release was removed after the
# March 2026 incident; the tag remains. Same Go version and flags as the local
# build, so the binary should be byte-identical to it.
FROM golang:1.23.4 AS trivy
ARG TRIVY_TAG=v0.58.2
ARG TRIVY_COMMIT=936f06a57864d073aa77b38f77fe76c4fcb1f7c1
WORKDIR /src
RUN git clone --depth 1 --branch "${TRIVY_TAG}" https://github.com/aquasecurity/trivy.git . \
 && test "$(git rev-parse HEAD)" = "${TRIVY_COMMIT}"
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false
RUN go build -trimpath \
      -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=0.58.2" \
      -o /out/trivy ./cmd/trivy

# Stage 2: runtime
FROM python:3.12-slim
# git: changed-file detection in merge request pipelines
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/cloudsec

# Checkov 3.2.495 in its own venv, dependencies pinned to the tested set
COPY docker/checkov-training.lock /tmp/checkov.lock
RUN python -m venv tools/training/checkov-venv \
 && tools/training/checkov-venv/bin/pip install --no-cache-dir -r /tmp/checkov.lock \
 && mkdir -p tools/training/bin tools/training/cache \
 && ln -s ../checkov-venv/bin/checkov tools/training/bin/checkov

COPY --from=trivy /out/trivy tools/training/bin/trivy

# The package, installed editable so scanners.toml and tools/ resolve from here
COPY pyproject.toml scanners.toml README.md ./
COPY cloudsec ./cloudsec
RUN pip install --no-cache-dir -e .

# Fail the build if either scanner is wrong
RUN tools/training/bin/checkov --version | grep -qx 3.2.495 \
 && tools/training/bin/trivy --version | grep -q "Version: 0.58.2"
