#!/bin/bash
set -euo pipefail

# Install the standalone kei-proxy binary from the shared S3 release bucket.
#
#   curl -fsSL "$AWS_S3_RELEASES_URL_BASE/kei-proxy/install.sh" | bash
#   curl -fsSL "$AWS_S3_RELEASES_URL_BASE/kei-proxy/install.sh" | bash -s -- -v 1.2.3
#
# AWS_S3_RELEASES_URL_BASE must point at the public S3/CloudFront endpoint.

VERSION="latest"
INSTALL_DIR="/usr/local/bin"
TMP_DIR=""

while getopts ":v:d:t:h" opt; do
  case "$opt" in
    v) VERSION="$OPTARG" ;;
    d) INSTALL_DIR="$OPTARG" ;;
    t) TMP_DIR="$OPTARG" ;;
    h)
      echo "Usage: $(basename "$0") [-v VERSION] [-d DIR] [-t TMPDIR]"
      exit 0
      ;;
    \?)
      echo "Error: invalid option -$OPTARG" >&2
      exit 2
      ;;
  esac
done

if [ -z "${AWS_S3_RELEASES_URL_BASE:-}" ]; then
  echo "Error: AWS_S3_RELEASES_URL_BASE is not set." >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin) OS="macOS" ;;
  Linux) OS="Linux" ;;
  *) echo "Error: unsupported OS $(uname -s); kei-proxy supports macOS and Linux." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Error: unsupported architecture $(uname -m); kei-proxy supports amd64 and arm64." >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL --connect-timeout 10 --retry 3 \
    "$AWS_S3_RELEASES_URL_BASE/kei-proxy/latest.txt")"
fi
VERSION="${VERSION#v}"

PROJECT="kei-proxy"
ARCHIVE_NAME="${PROJECT}_${VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUM_NAME="${PROJECT}_${VERSION}_checksums.txt"
BASE_URL="$AWS_S3_RELEASES_URL_BASE/$PROJECT/$VERSION"

if [ -z "$TMP_DIR" ]; then
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
else
  mkdir -p "$TMP_DIR"
fi

curl -fsSL --connect-timeout 15 --retry 3 "$BASE_URL/$ARCHIVE_NAME" -o "$TMP_DIR/$ARCHIVE_NAME"
curl -fsSL --connect-timeout 15 --retry 3 "$BASE_URL/$CHECKSUM_NAME" -o "$TMP_DIR/$CHECKSUM_NAME"

EXPECTED="$(awk -v name="$ARCHIVE_NAME" '$2 == name {print $1}' "$TMP_DIR/$CHECKSUM_NAME")"
ACTUAL="$(shasum -a 256 "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')"
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum verification failed for $ARCHIVE_NAME" >&2
  exit 1
fi

tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
if [ ! -f "$TMP_DIR/kei-proxy" ]; then
  echo "Error: kei-proxy binary not found in archive." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP_DIR/kei-proxy" "$INSTALL_DIR/kei-proxy"
echo "Installed kei-proxy $VERSION to $INSTALL_DIR/kei-proxy" >&2
