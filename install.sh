#!/usr/bin/env sh
#
# supertoolkit installer.
#
# It verifies SHA256SUMS before moving anything into place. An installer that
# pipes curl into sh without checking what it got is precisely the habit this
# product exists to argue against, so this one refuses rather than warns.
#
#   curl -fsSL https://supertoolkit.dev/install.sh | sh
#
# Environment:
#   STK_VERSION    a tag to install, default the latest release
#   STK_BIN_DIR    where to put the binary, default /usr/local/bin or ~/.local/bin
#   STK_BASE_URL   where to fetch from, for a mirror or an air-gapped copy.
#                  SHA256SUMS is still required and still verified: a mirror is
#                  a convenience, not a reason to trust what it serves.
set -eu

REPO="${STK_REPO:-SuperJackfruitLabs/supertoolkit}"
VERSION="${STK_VERSION:-latest}"

say()  { printf '%s\n' "$*"; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required and was not found"; }
need curl
need tar

# A checksum tool is not optional here: without one there is no way to know
# what was downloaded, and installing it anyway would defeat the point.
if command -v sha256sum >/dev/null 2>&1; then
  SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA="shasum -a 256"
else
  die "no sha256sum or shasum found. This installer verifies what it downloads
and will not proceed without the means to do so. Install coreutils, or build
from source: go build -o stk ./cmd/stk"
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  *) die "unsupported OS '$os'. Build from source: go build -o stk ./cmd/stk" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "unsupported architecture '$arch'. Build from source." ;;
esac

if [ -n "${STK_BASE_URL:-}" ]; then
  base="${STK_BASE_URL%/}"
  say "fetching from $base"
elif [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

archive="stk_${os}_${arch}.tar.gz"
say "downloading $archive"
curl -fsSL -o "$archive" "$base/$archive" || die "could not download $base/$archive"
curl -fsSL -o SHA256SUMS "$base/SHA256SUMS" || die "could not download SHA256SUMS — refusing to install something unverified"

say "verifying"
# Check only our archive's line, so an unrelated asset in SHA256SUMS does not
# fail the whole verification.
grep " $archive\$" SHA256SUMS > SHA256SUMS.one \
  || die "SHA256SUMS does not mention $archive — refusing to install"
$SHA -c SHA256SUMS.one >/dev/null 2>&1 \
  || die "checksum mismatch for $archive.

The file does not match what the release says it should be. Do not install it.
This is what a tampered or truncated download looks like."
say "  sha256 ok"

tar xzf "$archive" || die "could not extract $archive"
[ -f stk ] || die "the archive did not contain stk"
chmod +x stk

if [ -n "${STK_BIN_DIR:-}" ]; then
  dir="$STK_BIN_DIR"
elif [ -w /usr/local/bin ] 2>/dev/null; then
  dir="/usr/local/bin"
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir" || die "could not create $dir"
mv stk "$dir/stk" || die "could not install into $dir (set STK_BIN_DIR, or use sudo)"

say ""
say "installed $dir/stk"
"$dir/stk" version || true
say ""
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "note: $dir is not in your PATH" ;;
esac
say "next:"
say "  stk init"
say "  stk add github && stk connect github"
say "  stk doctor --probe      # confirm your clients actually go through the broker"
