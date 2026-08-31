#!/bin/sh
# Cross-compiles cmd/nse-status (the browser-mode server) for every
# supported platform into build/. Pure Go, CGO_ENABLED=0 throughout, so
# this runs on any machine with the Go toolchain installed — used both
# locally and by .github/workflows/release.yml.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="${1:-dev}"
out="$root/build"
mkdir -p "$out"

build_status() {
	os="$1"; arch="$2"; goarm="${3:-}"
	suffix="$arch"
	[ -n "$goarm" ] && suffix="${arch}v${goarm}"
	name="nse-status_${version}_${os}_${suffix}"
	[ "$os" = "windows" ] && name="${name}.exe"
	echo "  $name"
	env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" ${goarm:+GOARM=$goarm} \
		go build -trimpath -ldflags "-s -w" -o "$out/$name" ./cmd/nse-status
}

# Desktop/server OSes.
build_status darwin  amd64
build_status darwin  arm64
build_status linux   amd64
build_status linux   arm64
build_status windows amd64
build_status windows arm64
build_status freebsd amd64

# Raspberry Pi: GOARM=6 covers Pi Zero/Zero W/1 (ARMv6); GOARM=7 covers
# Pi 2 and any 32-bit install of Pi 3/4/400 (ARMv7). 64-bit Raspberry Pi
# OS on Pi 3/4/5/400/Zero 2 W uses the linux/arm64 build above.
build_status linux arm 6
build_status linux arm 7

echo "Done. Portable binaries in $out"
