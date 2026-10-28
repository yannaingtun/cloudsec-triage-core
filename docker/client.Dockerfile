# Client image: dashboard + scanners (Checkov, Trivy) + local run history.
# The model is not in this image; it is reached over HTTP (CLOUDSEC_TRIAGE_URL).
#   docker compose -f docker-compose.client.yml up -d --build
# PROFILE "training" = Checkov 3.2.495 + Trivy 0.58.2, the versions the
# annotations and training data were produced with. Trivy v0.58.2 was withdrawn
# from GitHub releases, so it is built here from the v0.58.2 source tag.

ARG TRIVY_VERSION=0.58.2

FROM golang:1.23-bookworm AS trivy-build
ARG TRIVY_VERSION
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
RUN git clone --depth 1 --branch "v${TRIVY_VERSION}" \
        https://github.com/aquasecurity/trivy.git /src
WORKDIR /src
RUN go build -trimpath \
      -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" \
      -o /out/trivy ./cmd/trivy \
 && /out/trivy --version

FROM python:3.12-slim
ARG PROFILE=training
ENV CLOUDSEC_PROFILE=${PROFILE} PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tar gzip git \
 && rm -rf /var/lib/apt/lists/* \
 && pip install uv
WORKDIR /app
COPY . .
RUN pip install -e . fastapi uvicorn python-multipart
COPY --from=trivy-build /out/trivy /opt/trivy-src/trivy
RUN if [ "$PROFILE" = "training" ]; then \
        TRIVY_BIN=/opt/trivy-src/trivy bash scripts/install_scanners.sh "$PROFILE"; \
    else \
        bash scripts/install_scanners.sh "$PROFILE"; \
    fi \
 && rm -rf /opt/trivy-src
VOLUME ["/data"]
EXPOSE 8080
CMD ["sh", "-c", "python -m cloudsec.web.app --host 0.0.0.0 --port 8080 --profile \"$CLOUDSEC_PROFILE\" --triage-url \"$CLOUDSEC_TRIAGE_URL\" --db /data/runs.db"]
