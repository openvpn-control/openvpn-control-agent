#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${1:?version required}"
GOARCH="${2:?goarch required (amd64|arm64)}"
BINARY="${3:?binary path required}"
OUT_DIR="${4:-dist/packages}"

if [ ! -f "$BINARY" ]; then
  echo "binary not found: $BINARY" >&2
  exit 1
fi

case "$GOARCH" in
  amd64|arm64) NFPM_ARCH="$GOARCH" ;;
  *)
    echo "unsupported arch: $GOARCH" >&2
    exit 1
    ;;
esac

PKG_VERSION="${VERSION#v}"
PKG_VERSION="${PKG_VERSION//\//-}"

mkdir -p "$OUT_DIR"

export NFPM_VERSION="$PKG_VERSION"
export NFPM_ARCH
export NFPM_BINARY="$BINARY"

envsubst < packaging/nfpm.yaml.template > packaging/nfpm.generated.yaml
trap 'rm -f packaging/nfpm.generated.yaml' EXIT

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm not found in PATH" >&2
  exit 1
fi

# nfpm accepts a single --packager flag; run twice for deb and rpm.
for packager in deb rpm; do
  nfpm pkg \
    --config packaging/nfpm.generated.yaml \
    --packager "${packager}" \
    --target "$OUT_DIR"
done

echo "Packages written to $OUT_DIR:"
ls -la "$OUT_DIR"
