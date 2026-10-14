#!/usr/bin/env bash
#
# Build release archives and SHA256SUMS.
#
# The builds are reproducible, binary and archive both.
#
# The binary: -trimpath removes local paths, the version is the only thing
# stamped in, and CGO is off so there is nothing to link against the build
# machine. Two runs produce byte-identical binaries, verified below.
#
# The archive needed work. tar records each entry's mtime, uid, gid and user
# names, and gzip writes a timestamp of its own, so two runs a second apart
# produced different checksums even though the binaries inside were identical.
# That matters: a published checksum is only worth something if someone else
# can rebuild the artefact and get the same number, and an archive that embeds
# the clock makes that impossible. So the entry is normalised to a fixed mtime
# and uid/gid 0, and gzip is told not to timestamp.
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: scripts/release.sh <version>   e.g. scripts/release.sh 0.0.1" >&2
  exit 2
fi
case "$VERSION" in
  0.*|1.*) ;;
  v*) echo "pass the version without a leading v: 0.0.1, not $VERSION" >&2; exit 2 ;;
  *) echo "unexpected version '$VERSION'" >&2; exit 2 ;;
esac

# A fixed timestamp for every archive entry. The date is arbitrary and only has
# to be constant; what must never appear is the build clock.
readonly EPOCH="202601010000.00"

# tar flags differ between GNU tar (Linux, and CI) and bsdtar (macOS), and
# neither accepts the other's spelling for "pretend the owner is root". Detect
# once rather than guessing.
tar_ownership() {
  if tar --version 2>/dev/null | grep -qi "gnu tar"; then
    printf '%s' "--owner=0 --group=0 --numeric-owner --sort=name"
  else
    printf '%s' "--uid 0 --gid 0 --numeric-owner"
  fi
}

# archive <dir> <name> <file...> — a deterministic tar.gz.
archive() {
  local dir="$1" name="$2"; shift 2
  local f
  for f in "$@"; do touch -t "${EPOCH%.*}" "$dir/$f"; done
  # shellcheck disable=SC2046  # the flags are intentionally word-split
  tar $(tar_ownership) -cf - -C "$dir" "$@" | gzip -n -9 > "$dir/$name"
}

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist"
rm -rf "$out"; mkdir -p "$out"
cd "$root"

echo "building supertoolkit $VERSION"
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  printf '  %-14s' "$target"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$out/stk" ./cmd/stk
  archive "$out" "stk_${os}_${arch}.tar.gz" stk
  rm "$out/stk"
  echo "ok"
done

# Verify the stamp took. `-X` against a const is silently ignored, and a
# released binary that reports the development version is a lie nobody notices
# until someone files a bug against the wrong code.
native_os="$(go env GOOS)"; native_arch="$(go env GOARCH)"
if [ -f "$out/stk_${native_os}_${native_arch}.tar.gz" ]; then
  check="$(mktemp -d)"
  tar -C "$check" -xzf "$out/stk_${native_os}_${native_arch}.tar.gz"
  got="$("$check/stk" version)"
  rm -rf "$check"
  if [ "$got" != "stk $VERSION" ]; then
    echo "the built binary reports '$got', not 'stk $VERSION'." >&2
    echo "main.version must be a var for -ldflags -X to apply; as a const it is" >&2
    echo "silently ignored and every archive here would misreport its version." >&2
    exit 1
  fi
  echo "  version stamp verified: $got"
fi

if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
else
  SHA_CMD="shasum -a 256"
fi
cd "$out"
$SHA_CMD stk_*.tar.gz > SHA256SUMS

echo
cat SHA256SUMS

# Reproducibility is a claim this script makes, so it checks it: build one
# archive a second time and compare. A checksum nobody else can reproduce
# attests to a moment rather than to a source tree.
echo
echo "checking reproducibility"
again="$(mktemp -d)"
cd "$root"
CGO_ENABLED=0 GOOS="$native_os" GOARCH="$native_arch" \
  go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$again/stk" ./cmd/stk
archive "$again" "repeat.tar.gz" stk
a="$($SHA_CMD "$out/stk_${native_os}_${native_arch}.tar.gz" | cut -d' ' -f1)"
b="$($SHA_CMD "$again/repeat.tar.gz" | cut -d' ' -f1)"
rm -rf "$again"
if [ "$a" = "$b" ]; then
  echo "  the same source produces the same archive: $a"
else
  echo "  NOT reproducible: $a vs $b" >&2
  echo "  someone else cannot verify these checksums. Find what embeds the clock." >&2
  exit 1
fi

echo
echo "dist/ is ready. install.sh verifies SHA256SUMS, so both must be published"
echo "together — an archive without its checksum cannot be installed."
