#!/usr/bin/env bash
# Install one scanner profile into tools/<profile>/.
#   scripts/install_scanners.sh latest
#   scripts/install_scanners.sh training
set -euo pipefail

PROFILE="${1:?usage: install_scanners.sh <profile>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/tools/$PROFILE"
# Prefer the repo venv; fall back to the system python when there is none,
# as in a container. tomllib needs 3.11+.
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3 || true)"
  if [ -z "$PY" ] || ! "$PY" -c 'import tomllib' 2>/dev/null; then
    echo "install_scanners.sh: no repo .venv and no python3 with tomllib (needs 3.11+)" >&2
    exit 1
  fi
fi

read -r CHECKOV TRIVY < <("$PY" - "$ROOT/scanners.toml" "$PROFILE" <<'PYEOF'
import sys, tomllib
p = tomllib.load(open(sys.argv[1], "rb"))["profiles"][sys.argv[2]]
assert "FILL_IN" not in p.values(), f"versions for profile {sys.argv[2]} not set"
print(p["checkov"], p["trivy"])
PYEOF
)

echo "Installing profile '$PROFILE': checkov $CHECKOV, trivy $TRIVY -> $DEST"
rm -rf "$DEST"
mkdir -p "$DEST/bin"
# A failed install must not leave a half-built profile that looks usable.
cleanup() {
  rc=$?
  if [ -n "${TMP:-}" ]; then rm -rf "$TMP"; fi
  if [ "$rc" -ne 0 ]; then
    echo "removing partial profile $DEST" >&2
    rm -rf "$DEST"
  fi
  exit "$rc"
}
trap cleanup EXIT

# Checkov in its own virtual environment
uv venv --quiet --python 3.12 "$DEST/checkov-venv"
uv pip install --quiet --python "$DEST/checkov-venv/bin/python" "checkov==$CHECKOV"
ln -sf "../checkov-venv/bin/checkov" "$DEST/bin/checkov"

# Trivy: a prebuilt binary if TRIVY_BIN is set (e.g. built from the v0.58.2
# source tag, since that release was withdrawn), otherwise the release tarball.
if [ -n "${TRIVY_BIN:-}" ]; then
  install -m 755 "$TRIVY_BIN" "$DEST/bin/trivy"
  "$DEST/bin/checkov" --version
  "$DEST/bin/trivy" --version | head -1
  exit 0
fi

# Trivy from the release tarball, checksum verified
TMP="$(mktemp -d)"
# Trivy publishes one tarball per architecture; the names differ from uname's.
case "$(uname -m)" in
  x86_64)        TRIVY_ARCH="Linux-64bit" ;;
  aarch64|arm64) TRIVY_ARCH="Linux-ARM64" ;;
  *) echo "install_scanners.sh: no trivy build for $(uname -m)" >&2; exit 1 ;;
esac

BASE="https://github.com/aquasecurity/trivy/releases/download/v$TRIVY"
(cd "$TMP"
 curl -fsSLO "$BASE/trivy_${TRIVY}_${TRIVY_ARCH}.tar.gz" || {
   echo "trivy v$TRIVY has no $TRIVY_ARCH release asset." >&2
   echo "v0.58.2 was withdrawn upstream and was never rebuilt for ARM64;" >&2
   echo "use the 'latest' profile here, or build trivy from source with Go." >&2
   exit 1
 }
 curl -fsSLO "$BASE/trivy_${TRIVY}_checksums.txt"
 sha256sum -c --ignore-missing "trivy_${TRIVY}_checksums.txt"
 tar xzf "trivy_${TRIVY}_${TRIVY_ARCH}.tar.gz" trivy)
install -m 755 "$TMP/trivy" "$DEST/bin/trivy"

"$DEST/bin/checkov" --version
"$DEST/bin/trivy" --version | head -1
