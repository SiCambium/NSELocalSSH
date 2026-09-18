#!/bin/sh
# One-shot local "build everything this machine can build" for a release.
# On macOS this produces the full set: the portable nse-status binary for
# every supported platform, plus the native macOS desktop app. The native
# Windows (WebView2) and Linux (GTK/WebKit2GTK) desktop apps need their
# own OS's toolchain and are built natively in CI instead — see
# .github/workflows/release.yml.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="${1:-dev}"
rm -rf "$root/build"

echo "=== nse-status (portable server, all platforms) ==="
sh scripts/build-portable.sh "$version"

echo "=== nse-app (native desktop, macOS universal) ==="
sh scripts/build-macos-app.sh "$version"

echo
echo "Done. Artifacts in $root/build:"
ls -la "$root/build"
